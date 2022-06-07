/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * hsak is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.* Description: LibStorage IO interface for external users.
 * Author: xiehuiming@huawei.com
 * Create: 2018-09-01
 */

#include <sys/file.h>
#include "bdev_rw_internal.h"
#include "bdev_rw_rpc_internal.h"
#ifdef SPDK_CONFIG_ERR_INJC
#include "bdev_rw_err_injc.h"
#endif
#include "spdk/string.h"
#include "spdk_internal/nvme_internal.h"
#include "spdk_internal/thread.h"

#define MEMORY_MAGIC 0x89DEADFE

/* share lock file between uio and ublock */
#define UIO_UBLOCK_SHARE_LOCK           "share_lock.shm.\
e9b10e0e1010dadeefcb70a19bbe61d0352ec43fd02979ee0c925be1"
#define LOCK_INIT    0x00000000

static SLIST_HEAD(, ctrlr_capability_info) g_ctrlr_cap_list = SLIST_HEAD_INITIALIZER(g_ctrlr_cap_list);
static pthread_mutex_t g_ctrlr_cap_mutex = PTHREAD_MUTEX_INITIALIZER;

bool g_bSpdkInitcomplete = false;
bool g_bSameBdevMultiQ = false;
uint8_t g_ucE2EDif = (uint8_t)IO_E2E_PROTECTION;

struct spdk_conf *g_libstorage_config = NULL;
struct spdk_thread  *g_masterThread = NULL;
struct spdk_mempool *g_libstorage_io_t_mempool = NULL;
void *g_alloc_io_t[LIBSTORAGE_IO_T_POOL_SIZE] = {NULL};

/* mutex for admin operation in libstorage, do not ues it for IO. */
pthread_mutex_t *g_libstorage_admin_op_mutex = NULL;
/* atomic lock for uio and ublock */
uint32_t *g_uio_ublock_lock = NULL;

static int uio_ublock_lock_init(void)
{
    int shm_fd = shm_open(UIO_UBLOCK_SHARE_LOCK, O_CREAT | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR);
    if (shm_fd < 0) {
        if (errno != EEXIST) {
            SPDK_ERRLOG("create share memory failed: %d\n", errno);
            return -1;
        }
        shm_fd = shm_open(UIO_UBLOCK_SHARE_LOCK, O_RDWR, S_IRUSR | S_IWUSR);
        if (shm_fd < 0) {
            SPDK_ERRLOG("share memory is already exist, open failed: %d\n", errno);
            return -1;
        }
    }
    if (ftruncate(shm_fd, sizeof(uint32_t)) == -1) {
        SPDK_ERRLOG("ftruncate share memory failed %d\n", errno);
        close(shm_fd);
        shm_unlink(UIO_UBLOCK_SHARE_LOCK);
        return -1;
    }

    g_uio_ublock_lock = (uint32_t *)mmap(NULL, sizeof(uint32_t), PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (g_uio_ublock_lock == MAP_FAILED) {
        SPDK_ERRLOG("mmap failed: %d\n", errno);
        close(shm_fd);
        return -1;
    }

    close(shm_fd);
    return 0;
}

static int32_t libstorage_nvme_ctrlr_get_info(struct nvme_ctrlr_info** ppCtrlr)
{
    int32_t num_ctrlr;
    num_ctrlr = nvme_ctrlr_get_info(NULL, ppCtrlr);
    if (num_ctrlr < 0) {
        /* try again */
        num_ctrlr = nvme_ctrlr_get_info(NULL, ppCtrlr);
    }
    return num_ctrlr;
}

int libstorage_robust_mutex_init_recursive_shared(pthread_mutex_t *mtx)
{
    int rc = 0;
    pthread_mutexattr_t mutexattr;

    if (mtx == NULL) {
        SPDK_ERRLOG("[libstorage] global process mutex inited should not be NULL\n");
        return -1;
    }

    if (pthread_mutexattr_init(&mutexattr)) {
        return -1;
    }
    if (pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE) ||
        pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST) ||
        pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED) ||
        pthread_mutex_init(mtx, &mutexattr)) {
        rc = -1;
    }

    pthread_mutexattr_destroy(&mutexattr);
    return rc;
}

static pthread_mutex_t *libstorage_process_mutex_init(void)
{
    int rc;
    pthread_mutex_t *mtx = NULL;

    mtx = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    if (mtx == NULL) {
        SPDK_ERRLOG("[libstorage]libstorage_process_mutex_init failed.\n");
        return NULL;
    }

    rc = libstorage_robust_mutex_init_recursive_shared(mtx);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage]robust_mutex_init_recursive_shared failed.\n");
        free(mtx);
        return NULL;
    }

    return mtx;
}

int libstorage_process_mutex_lock(pthread_mutex_t *mutex)
{
    int ret;

    if (spdk_unlikely(mutex == NULL)) {
        return -1;
    }

    ret = pthread_mutex_lock(mutex);
    /* if the owner of robust mutex terminates while holding the mutex, */
    /* only the next process that acquires the mutex lock can get the retrun value with EOWNERDEAD */
    if (ret == EOWNERDEAD) {
        /* in this case, it means that more than one process is terminated. */
        /* use pthread_mutex_consistent() to make that mutex available. */
        ret = pthread_mutex_consistent(mutex);
        if (ret != 0) {
            SPDK_ERRLOG("[libstorage] the libstorage process mutex is not normal any more.\n");
            return ret;
        }
    }

    return 0;
}

int libstorage_process_mutex_unlock(pthread_mutex_t *mutex)
{
    if (spdk_unlikely(mutex == NULL)) {
        return -1;
    }

    return pthread_mutex_unlock(mutex);
}

static void libstorage_process_mutex_destroy(pthread_mutex_t *mtx)
{
    if (mtx == NULL) {
        SPDK_WARNLOG("[libstorage] invalid parameter.\n");
        return;
    }

    free(mtx);
}

static void libstorage_update_ctrlr_cap_info(const char *ctrlName, const struct spdk_nvme_format *format)
{
    struct ctrlr_capability_info *pCtrlrCap = NULL;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    if (ctrlName == NULL || format == NULL) {
        return;
    }

    ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlName);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("%s is not exist.\n", ctrlName);
        return;
    }

    bdev_nvme_update_block_by_nvme_ctrlr(ctrlr);

    (void)pthread_mutex_lock(&g_ctrlr_cap_mutex);
    SLIST_FOREACH(pCtrlrCap, &g_ctrlr_cap_list, slist) {
        if (strcmp(pCtrlrCap->ctrlrName, ctrlName) == 0) {
            pCtrlrCap->cur_format = format->lbaf;
            pCtrlrCap->cur_extended = format->ms;
            pCtrlrCap->cur_pi = format->pi;
            pCtrlrCap->cur_pil = format->pil;
        }
    }
    (void)pthread_mutex_unlock(&g_ctrlr_cap_mutex);
}

void libstorage_remove_ctrlr_cap_info(const char *ctrlName)
{
    struct ctrlr_capability_info *pCtrlrCap = NULL;

    if (ctrlName == NULL) {
        SPDK_ERRLOG("[libstorage] ctrlName should not be NULL\n");
        return;
    }

    (void)pthread_mutex_lock(&g_ctrlr_cap_mutex);

    SLIST_FOREACH(pCtrlrCap, &g_ctrlr_cap_list, slist) {
        if (strcmp(pCtrlrCap->ctrlrName, ctrlName) != 0) {
            continue;
        }
        SLIST_REMOVE(&g_ctrlr_cap_list, pCtrlrCap, ctrlr_capability_info, slist);
        break;
    }

    if (pCtrlrCap != NULL) {
        free(pCtrlrCap);
    } else {
        SPDK_NOTICELOG("[libstorage] fail to find cap info of %s to remove\n", ctrlName);
    }

    (void)pthread_mutex_unlock(&g_ctrlr_cap_mutex);
    return;
}

static void libstorage_ctrl_ns_info_to_capinfo(const struct nvme_ctrlr_info *ctrlrInfo,
                                               const struct spdk_nvme_ns_data *nsdata,
                                               struct ctrlr_capability_info *pCtrlrCap)
{
    int rc;
    pCtrlrCap->max_num_ns = ctrlrInfo->max_num_ns;
    pCtrlrCap->ns_manage = ctrlrInfo->support_ns;
    pCtrlrCap->directives = ctrlrInfo->directives;
    pCtrlrCap->dsm = ctrlrInfo->dsm;
    pCtrlrCap->nlbaf = nsdata->nlbaf;
    pCtrlrCap->cur_format = nsdata->flbas.format;
    pCtrlrCap->cur_extended = nsdata->flbas.extended;
    pCtrlrCap->cur_pi = nsdata->dps.pit;
    pCtrlrCap->cur_pil = nsdata->dps.md_start;
    pCtrlrCap->cur_can_share = nsdata->nmic.can_share;
    pCtrlrCap->mc_extented = nsdata->mc.extended;
    pCtrlrCap->mc_pointer = nsdata->mc.pointer;
    pCtrlrCap->pi_type1 = nsdata->dpc.pit1;
    pCtrlrCap->pi_type2 = nsdata->dpc.pit2;
    pCtrlrCap->pi_type3 = nsdata->dpc.pit3;
    pCtrlrCap->md_start = nsdata->dpc.md_start;
    pCtrlrCap->md_end = nsdata->dpc.md_end;
    rc = memcpy_s(pCtrlrCap->lbaf, sizeof(pCtrlrCap->lbaf), nsdata->lbaf, sizeof(nsdata->lbaf));
    if (rc != 0) {
        SPDK_WARNLOG("memcpy failed.\n");
    }
}

static int libstorage_get_ns_common_data(const char *ctrlName, struct spdk_nvme_ns_data *nsdata)
{
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    int ret;

    ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlName);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("%s is not exist.\n", ctrlName);
        return -1;
    }

    ret = nvme_ns_get_common_data(ctrlr, nsdata);
    if (ret != 0) {
        SPDK_WARNLOG("get common data failed.\n");
        return -1;
    }

    return 0;
}

static struct ctrlr_capability_info *libstorage_add_ctrlr_cap_info(const char *ctrlName,
                                                                   const struct nvme_ctrlr_info *ctrlrInfo)
{
    struct ctrlr_capability_info *pCtrlrCap = NULL;
    struct spdk_nvme_ns_data nsdata;
    int8_t esn[21] = {0};       /* 21 is to hold 20-bytes esn and '\0' */
    int8_t firmware[9] = {0};   /* 9 is to hold 8-bytes fr and '\0' */
    int rc;

    rc = memset_s(&nsdata, sizeof(struct spdk_nvme_ns_data), 0, sizeof(struct spdk_nvme_ns_data));
    if (rc != 0) {
        SPDK_WARNLOG("memset nsdata failed.\n");
    }

    rc = libstorage_get_ns_common_data(ctrlName, &nsdata);
    if (rc < 0) {
        return NULL;
    }

    pCtrlrCap = malloc(sizeof(struct ctrlr_capability_info));
    if (pCtrlrCap == NULL) {
        SPDK_ERRLOG("failed to alloc memory\n");
        return NULL;
    }
    rc = strcpy_s(pCtrlrCap->ctrlrName, MAX_CTRL_NAME_LEN, ctrlName);

    libstorage_ctrl_ns_info_to_capinfo(ctrlrInfo, &nsdata, pCtrlrCap);

    rc += memcpy_s(esn, sizeof(esn), ctrlrInfo->sn, 20);          /* length of sn is 20 */
    esn[20] = 0;                                                  /* add 0 at position of 20 at last */
    rc += memcpy_s(firmware, sizeof(firmware), ctrlrInfo->fr, 8); /* length of fr is 8 */
    firmware[8] = 0;                                              /* add 0 at position of 8 at last */
    if (rc != 0) {
        SPDK_WARNLOG("memcpy or strcpy failed.\n");
    }

    syslog(LOG_INFO, "Controller[%s(FR: %s | SN: %s)] infomation:\n",
           ctrlrInfo->ctrlName, firmware, esn);
    syslog(LOG_INFO, "version[0x%x], pci_addr[%s], totalcap[%lu], unusecap[%lu], max_num_ns[%u], "
           "support_ns[%u], directives[%u], dsm[%u]\n",
           ctrlrInfo->version, ctrlrInfo->pciAddr, ctrlrInfo->tnvmcap,
           ctrlrInfo->unvmcap, ctrlrInfo->max_num_ns, ctrlrInfo->support_ns,
           ctrlrInfo->directives, ctrlrInfo->dsm);
    syslog(LOG_INFO, "cur_format[%u{%u:%u}], cur_extended[%u], cur_pi[%u], cur_pil[%u]\n",
           pCtrlrCap->cur_format, 1 << nsdata.lbaf[pCtrlrCap->cur_format].lbads,
           nsdata.lbaf[pCtrlrCap->cur_format].ms, pCtrlrCap->cur_extended,
           pCtrlrCap->cur_pi, pCtrlrCap->cur_pil);

    (void)pthread_mutex_lock(&g_ctrlr_cap_mutex);
    SLIST_INSERT_HEAD(&g_ctrlr_cap_list, pCtrlrCap, slist);
    (void)pthread_mutex_unlock(&g_ctrlr_cap_mutex);

    return pCtrlrCap;
}

static bool libstorage_ctrlr_lba_md_size_matched(const struct ctrlr_capability_info *pCtrlrCap,
                                                 uint32_t mdSize, uint32_t lbaSize)
{
    if ((mdSize == 0xFFFFFFFF && lbaSize == 0xFFFFFFFF) || (pCtrlrCap->lbaf[pCtrlrCap->cur_format].ms == mdSize &&
        pCtrlrCap->lbaf[pCtrlrCap->cur_format].lbads == lbaSize)) {
        return true;
    }
    return false;
}

static struct ctrlr_capability_info *libstorage_find_ctrlr_in_list(const char *ctrlName)
{
    struct ctrlr_capability_info *pCtrlrCap = NULL;

    (void)pthread_mutex_lock(&g_ctrlr_cap_mutex);
    SLIST_FOREACH(pCtrlrCap, &g_ctrlr_cap_list, slist) {
        if (strcmp(pCtrlrCap->ctrlrName, ctrlName) == 0) {
            (void)pthread_mutex_unlock(&g_ctrlr_cap_mutex);
            return pCtrlrCap;
        }
    }

    (void)pthread_mutex_unlock(&g_ctrlr_cap_mutex);
    return NULL;
}

static int8_t libstorage_get_ctrlr_cap_info(const char *ctrlName, struct ctrlr_capability_info *ctrlr_cap_info,
                                            uint32_t mdSize, uint32_t lbaSize)
{
    struct ctrlr_capability_info *pCtrlrCap = NULL;
    size_t size = sizeof(struct ctrlr_capability_info);
    int rc = 0;
    int8_t format;

    pCtrlrCap = libstorage_find_ctrlr_in_list(ctrlName);
    if (pCtrlrCap == NULL) {
        struct nvme_ctrlr_info *ctrlrInfo = NULL;
        if (nvme_ctrlr_get_info(ctrlName, &ctrlrInfo) <= 0) {
            SPDK_ERRLOG("failed to get %s's controller info\n", ctrlName);
            return -EPERM;
        }
        pCtrlrCap = libstorage_add_ctrlr_cap_info(ctrlName, ctrlrInfo);
        if (pCtrlrCap == NULL) {
            SPDK_ERRLOG("%s is not exist.\n", ctrlName);
            free(ctrlrInfo);
            return -EPERM;
        }

        free(ctrlrInfo);
    }

    if (libstorage_ctrlr_lba_md_size_matched(pCtrlrCap, mdSize, lbaSize)) {
        rc = memcpy_s(ctrlr_cap_info, size, pCtrlrCap, size);
        if (rc != 0) {
            SPDK_WARNLOG("memcpy failed.\n");
        }

        format = pCtrlrCap->cur_format;
        return format;
    }

    return -EPERM;
}

static uint32_t libstorage_nvme_format_get_nsid(const char *ctrlName,
                                                struct spdk_nvme_ctrlr **pctrlr)
{
    uint32_t ns_id = 1;

    *pctrlr = spdk_nvme_ctrlr_get_by_name(ctrlName);
    if (*pctrlr == NULL) {
        SPDK_ERRLOG("%s is not exist.\n", ctrlName);
        return 0;
    }

    if (!spdk_nvme_ctrlr_is_format_supported(*pctrlr)) {
        SPDK_ERRLOG("%s is not support Format NVM command.\n", ctrlName);
        return 0;
    }

    if (spdk_nvme_ctrlr_is_format_all_ns(*pctrlr)) {
        ns_id = 0xFFFFFFFF;
    }

    return ns_id;
}

static int8_t libstorage_nvme_format_nvm(const char *ctrlName, struct spdk_nvme_format *fmt)
{
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    uint32_t ns_id;

    if (ctrlName == NULL || fmt == NULL) {
        return -EINVAL;
    }

    ns_id = libstorage_nvme_format_get_nsid(ctrlName, &ctrlr);
    if (ns_id == 0) {
        return -EINVAL;
    }

    if (spdk_nvme_ctrlr_format(ctrlr, ns_id, fmt)) {
        SPDK_ERRLOG("Failed to format %s.\n", ctrlName);
        return -EPERM;
    }
    SPDK_WARNLOG("Format controller[%s], lbaf[%u], md_extended[%u],"
                 " pi_type[%u], pi_loc[%u], ses[%u]\n",
                 ctrlName,
                 fmt->lbaf, fmt->ms, fmt->pi, fmt->pil, fmt->ses);
    libstorage_update_ctrlr_cap_info(ctrlName, fmt);

    return fmt->lbaf;
}

static int8_t libstorage_param_check_for_nvme_format(const char *ctrlName, uint8_t lbaf,
                                                     enum libstorage_ns_pi_type piType,
                                                     bool pil_start, bool ms_extented)
{
    struct ctrlr_capability_info ctrlr_cap_info;

    if (libstorage_get_ctrlr_cap_info(ctrlName, &ctrlr_cap_info, 0xFFFFFFFF, 0xFFFFFFFF) < 0) {
        SPDK_ERRLOG("Parameter error, ctrlName[%s]\n", ctrlName);
        return -EINVAL;
    }
    if (lbaf > ctrlr_cap_info.nlbaf) {
        SPDK_ERRLOG("Parameter lbaf[%d] out of range[0~%u].\n", lbaf, ctrlr_cap_info.nlbaf);
        return -EINVAL;
    }
    if (piType > LIBSTORAGE_FMT_NVM_PROTECTION_DISABLE) {
        if (pil_start && !ctrlr_cap_info.md_start) {
            SPDK_ERRLOG("%s does not support protection information as the first eight bytes of metadata\n", ctrlName);
            return -EINVAL;
        }
        if (!pil_start && !ctrlr_cap_info.md_end) {
            SPDK_ERRLOG("%s does not support protection information as the last eight bytes of metadata\n", ctrlName);
            return -EINVAL;
        }
    }
    if (!ms_extented && !ctrlr_cap_info.mc_pointer) {
        SPDK_ERRLOG("%s does not support transferring metadata with separate metadata pointer\n", ctrlName);
        return -EINVAL;
    }

    return 0;
}

int8_t libstorage_low_level_format_nvm(const char *ctrlName, uint8_t lbaf,
                                       enum libstorage_ns_pi_type piType,
                                       bool pil_start, bool ms_extented, uint8_t ses)
{
    int8_t rc;
    struct spdk_nvme_format fmt;

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    if (ctrlName == NULL) {
        SPDK_ERRLOG("Parameter error, ctrlName is NULL\n");
        return -EINVAL;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    rc = libstorage_param_check_for_nvme_format(ctrlName, lbaf, piType, pil_start, ms_extented);
    if (rc < 0) {
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return rc;
    }

    fmt.lbaf = lbaf;
    fmt.pi = (uint8_t)piType;
    fmt.ses = ses;
    if (piType > LIBSTORAGE_FMT_NVM_PROTECTION_DISABLE && pil_start) {
        fmt.pil = (uint8_t)SPDK_NVME_FMT_NVM_PROTECTION_AT_HEAD;
    } else {
        fmt.pil = (uint8_t)SPDK_NVME_FMT_NVM_PROTECTION_AT_TAIL;
    }

    if (ms_extented) {
        fmt.ms = (uint8_t)SPDK_NVME_FMT_NVM_METADATA_TRANSFER_AS_LBA;
    } else {
        fmt.ms = (uint8_t)SPDK_NVME_FMT_NVM_METADATA_TRANSFER_AS_BUFFER;
    }
    rc = libstorage_nvme_format_nvm(ctrlName, &fmt);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return rc;
}

static struct spdk_nvme_ns *libstorage_get_ns_by_bdevname(const char *bdevName)
{
    struct spdk_bdev *bdev = NULL;

    if (bdevName == NULL) {
        SPDK_ERRLOG("Invalid argument\n");
        return NULL;
    }

    if (strncasecmp(bdevName, "nvme", strlen("nvme")) == 0) {
        bdev = spdk_bdev_get_by_name(bdevName);
    }

    if (bdev == NULL) {
        SPDK_ERRLOG("Cannot find %s\n", bdevName);
        return NULL;
    }

    return bdev_nvme_get_ns(bdev->ctxt);
}

uint32_t libstorage_get_nvme_ctrlr_info(struct libstorage_nvme_ctrlr_info **ppCtrlrInfo)
{
    int32_t num_ctrlr;
    int32_t i = 0;
    struct libstorage_nvme_ctrlr_info *pCtrlrInfo = NULL;
    struct nvme_ctrlr_info *pCtrlr = NULL;
    struct ctrlr_capability_info *pCtrlr_cap_info = NULL;
    struct spdk_pci_addr pci_addr;
    int rc;

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return 0;
    }

    if (ppCtrlrInfo == NULL) {
        return 0;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    num_ctrlr = libstorage_nvme_ctrlr_get_info(&pCtrlr);
    if (num_ctrlr <= 0) {
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return 0;
    }
    pCtrlrInfo = calloc(num_ctrlr, sizeof(struct libstorage_nvme_ctrlr_info));
    if (pCtrlrInfo == NULL) {
        SPDK_ERRLOG("Failed to alloc memory for getting spdk controller infomation.\n");
        goto exit;
    }
    pCtrlr_cap_info = malloc(sizeof(struct ctrlr_capability_info));
    if (pCtrlr_cap_info == NULL) {
        SPDK_ERRLOG("Failed to alloc memory for getting spdk controller capability infomation.\n");
        goto exit;
    }
    for (i = 0; i < num_ctrlr; i++) {
        rc = strcpy_s(pCtrlrInfo[i].name, MAX_CTRL_NAME_LEN, pCtrlr[i].ctrlName);
        rc += strcpy_s(pCtrlrInfo[i].address, sizeof(pCtrlrInfo[i].address), pCtrlr[i].pciAddr);
        rc += memcpy_s(pCtrlrInfo[i].sn, sizeof(pCtrlrInfo[0].sn), pCtrlr[i].sn, 20); /* length of sn is 20 */
        rc += memcpy_s(pCtrlrInfo[i].fr, sizeof(pCtrlrInfo[0].fr), pCtrlr[i].fr, 8); /* length of fr is 8 */
        if (rc != 0) {
            SPDK_WARNLOG("error occurs to copy ctrlr info.\n");
        }
        (void)spdk_pci_addr_parse(&pci_addr, pCtrlrInfo[i].address);

        pCtrlrInfo[i].pci_addr.domain = pci_addr.domain;
        pCtrlrInfo[i].pci_addr.bus = pci_addr.bus;
        pCtrlrInfo[i].pci_addr.dev = pci_addr.dev;
        pCtrlrInfo[i].pci_addr.func = pci_addr.func;
        pCtrlrInfo[i].totalcap = pCtrlr[i].tnvmcap;
        pCtrlrInfo[i].unusecap = pCtrlr[i].unvmcap;
        pCtrlrInfo[i].ctrlid = pCtrlr[i].ctrlid;
        pCtrlrInfo[i].version = pCtrlr[i].version;
        pCtrlrInfo[i].max_num_ns = pCtrlr[i].max_num_ns;
        pCtrlrInfo[i].num_io_queues = pCtrlr[i].num_io_queues;
        pCtrlrInfo[i].io_queue_size = pCtrlr[i].io_queue_size;
        if (libstorage_get_ctrlr_cap_info(pCtrlr[i].ctrlName, pCtrlr_cap_info, 0xFFFFFFFF, 0xFFFFFFFF) >= 0) {
            rc = memcpy_s(pCtrlrInfo[i].cap_info.lbaf, sizeof(pCtrlrInfo[i].cap_info.lbaf),
                          pCtrlr_cap_info->lbaf, sizeof(pCtrlr_cap_info->lbaf));
            if (rc != 0) {
                SPDK_WARNLOG("memcpy failed.\n");
            }
            pCtrlrInfo[i].cap_info.nlbaf = pCtrlr_cap_info->nlbaf;
            pCtrlrInfo[i].cap_info.cur_format = pCtrlr_cap_info->cur_format;
            pCtrlrInfo[i].cap_info.cur_extended = pCtrlr_cap_info->cur_extended;
            pCtrlrInfo[i].cap_info.cur_pi = pCtrlr_cap_info->cur_pi;
            pCtrlrInfo[i].cap_info.cur_pil = pCtrlr_cap_info->cur_pil;
            pCtrlrInfo[i].cap_info.cur_can_share = pCtrlr_cap_info->cur_can_share;
            pCtrlrInfo[i].cap_info.mc_extented = pCtrlr_cap_info->mc_extented;
            pCtrlrInfo[i].cap_info.mc_pointer = pCtrlr_cap_info->mc_pointer;
            pCtrlrInfo[i].cap_info.pi_type1 = pCtrlr_cap_info->pi_type1;
            pCtrlrInfo[i].cap_info.pi_type2 = pCtrlr_cap_info->pi_type2;
            pCtrlrInfo[i].cap_info.pi_type3 = pCtrlr_cap_info->pi_type3;
            pCtrlrInfo[i].cap_info.md_start = pCtrlr_cap_info->md_start;
            pCtrlrInfo[i].cap_info.md_end = pCtrlr_cap_info->md_end;
            pCtrlrInfo[i].cap_info.ns_manage = pCtrlr_cap_info->ns_manage;
            pCtrlrInfo[i].cap_info.directives = pCtrlr_cap_info->directives;
            pCtrlrInfo[i].cap_info.dsm = pCtrlr_cap_info->dsm;
        }
    }
    *ppCtrlrInfo = pCtrlrInfo;
    free(pCtrlr);
    free(pCtrlr_cap_info);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return (uint32_t)num_ctrlr;
exit:
    free(pCtrlr);
    free(pCtrlrInfo);
    free(pCtrlr_cap_info);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return 0;
}

int32_t libstorage_get_mgr_info_by_esn(const char *esn, struct libstorage_mgr_info *mgr_info)
{
    if (esn == NULL || mgr_info == NULL) {
        SPDK_ERRLOG("esn or mgr_info is NULL\n");
        return -1;
    }

    int32_t num_ctrlr;
    int32_t i;
    struct nvme_ctrlr_info *pCtrlr = NULL;
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    struct spdk_nvme_ns_data nsdata = {0x0};

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    num_ctrlr = libstorage_nvme_ctrlr_get_info(&pCtrlr);
    if (num_ctrlr <= 0) {
        SPDK_ERRLOG("[libstorage] fail to get nvme ctrlr list\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }
    for (i = 0; i < num_ctrlr; i++) {
        char buffer[21] = {0x0}; /* 21 is the max length of string to hold */
        int rc;

        rc = memcpy_s(buffer, sizeof(buffer), pCtrlr[i].sn, sizeof(pCtrlr[i].sn));
        if (rc != 0) {
            SPDK_WARNLOG("[libstorage] memcpy failed\n");
        }
        buffer[20] = '\0';      /* add '\0' to the position of 20 at last */

        if (strcmp(esn, buffer) == 0) {
            rc = memcpy_s(mgr_info->pci, sizeof(mgr_info->pci),
                          pCtrlr[i].pciAddr, sizeof(pCtrlr[i].pciAddr));
            rc += memcpy_s(mgr_info->ctrlName, sizeof(mgr_info->ctrlName),
                           pCtrlr[i].ctrlName, sizeof(pCtrlr[i].ctrlName));
            rc += memcpy_s(mgr_info->serial_number, sizeof(mgr_info->serial_number),
                           pCtrlr[i].sn, sizeof(pCtrlr[i].sn));
            rc += memcpy_s(mgr_info->model_number, sizeof(mgr_info->model_number),
                           pCtrlr[i].mn, sizeof(pCtrlr[i].mn));
            rc += memcpy_s(mgr_info->firmware_revision, sizeof(mgr_info->firmware_revision),
                           pCtrlr[i].fr, sizeof(pCtrlr[i].fr));
            if (rc != 0) {
                SPDK_WARNLOG("[libstorage] memcpy failed\n");
            }
            ctrlr = spdk_nvme_ctrlr_get_by_name(pCtrlr[i].ctrlName);
            if (nvme_ns_get_common_data(ctrlr, &nsdata) != 0) {
                SPDK_ERRLOG("[libstorage] fail to find matched ns data\n");
                libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
                free(pCtrlr);
                return -1;
            }
            mgr_info->sector_size = 1 << nsdata.lbaf[nsdata.flbas.format].lbads;
            mgr_info->cap_size = pCtrlr[i].tnvmcap;
            mgr_info->device_id = pCtrlr[i].device_id;
            mgr_info->subsystem_device_id = pCtrlr[i].subdevice_id;
            mgr_info->vendor_id = pCtrlr[i].vid;
            mgr_info->subsystem_vendor_id = pCtrlr[i].ssvid;
            mgr_info->controller_id = pCtrlr[i].ctrlid;

            free(pCtrlr);
            libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
            return 0;
        }
    }

    SPDK_ERRLOG("[libstorage] fail to find matched esn in nvme ctrlr list\n");
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    free(pCtrlr);
    return -2; /* -2 means that find no devices matched to the esn */
}

int32_t libstorage_get_mgr_smart_by_esn(const char *esn, uint32_t nsid, struct libstorage_smart_info *mgr_smart_info)
{
    if (esn == NULL || mgr_smart_info == NULL) {
        SPDK_ERRLOG("esn or smart_info is NULL\n");
        return -1;
    }

    int rc;
    int32_t num_ctrlr;
    int32_t i;
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    struct nvme_ctrlr_info *pCtrlr = NULL;
    struct spdk_nvme_health_information_page *smart_info = (struct spdk_nvme_health_information_page *)mgr_smart_info;

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    num_ctrlr = libstorage_nvme_ctrlr_get_info(&pCtrlr);
    if (num_ctrlr <= 0) {
        SPDK_ERRLOG("[libstorage] fail to get nvme ctrlr list\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }
    for (i = 0; i < num_ctrlr; i++) {
        char buffer[21] = {0x0}; /* 21 is the max length of string to hold */
        rc = memcpy_s(buffer, sizeof(buffer), pCtrlr[i].sn, sizeof(pCtrlr[i].sn));
        if (rc != 0) {
            SPDK_WARNLOG("[libstorage] memcpy failed\n");
        }
        buffer[20] = '\0';      /* add '\0' to the position of 20 at last */

        if (strcmp(esn, buffer) == 0) {
            ctrlr = spdk_nvme_ctrlr_get_by_name(pCtrlr[i].ctrlName);
            if (ctrlr == NULL) {
                SPDK_ERRLOG("[libstorage] fail to get spdk nvme ctrlr\n");
                free(pCtrlr);
                libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
                return -1;
            }

            rc = spdk_nvme_ctrlr_get_smart_info(ctrlr, nsid, smart_info);
            if (rc != 0) {
                SPDK_ERRLOG("[libstorage] fail to get smart info\n");
                free(pCtrlr);
                libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
                return -1;
            }

            free(pCtrlr);
            libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
            return 0;
        }
    }

    SPDK_ERRLOG("[libstorage] fail to find matched esn in nvme ctrlr list\n");
    free(pCtrlr);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return -2; /* -2 means that find no devices matched to the esn */
}

uint32_t libstorage_get_bdev_ns_info(const char *bdevName, struct libstorage_namespace_info **ppNsInfo)
{
    struct spdk_nvme_ns *ns = NULL;
    struct libstorage_namespace_info *nsinfo = NULL;
    int rc;

    if (bdevName == NULL || ppNsInfo == NULL) {
        return 0;
    }

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return 0;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    ns = libstorage_get_ns_by_bdevname(bdevName);
    if (ns == NULL) {
        SPDK_ERRLOG("Cannot find %s\n", bdevName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return 0;
    }

    nsinfo = calloc(1, sizeof(struct libstorage_namespace_info));
    if (nsinfo == NULL) {
        SPDK_ERRLOG("Failed to alloc memory for nsinfo\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return 0;
    }
    nsinfo->size = spdk_nvme_ns_get_size(ns);
    nsinfo->sectors = spdk_nvme_ns_get_num_sectors(ns);
    nsinfo->sector_size = spdk_nvme_ns_get_sector_size(ns);
    nsinfo->md_size = spdk_nvme_ns_get_md_size(ns);
    nsinfo->pi_type = (uint8_t)spdk_nvme_ns_get_pi_type(ns);
    nsinfo->max_io_xfer_size = spdk_nvme_ns_get_max_io_xfer_size(ns);
    nsinfo->id = spdk_nvme_ns_get_id(ns);
    nsinfo->is_active = (uint8_t)spdk_nvme_ns_is_active(ns) & 0x1;
    nsinfo->ext_lba = (uint8_t)spdk_nvme_ns_supports_extended_lba(ns) & 0x1;
    nsinfo->dsm = (uint8_t)spdk_nvme_ns_is_dataset_mng_supported(ns) & 0x1;
    rc = strcpy_s(nsinfo->name, MAX_BDEV_NAME_LEN, bdevName);
    if (rc != 0) {
        SPDK_WARNLOG("strcpy failed.\n");
    }
    *ppNsInfo = nsinfo;
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    SPDK_NOTICELOG("[%u]namespace[%s]: sectors[%lu], sector_size[%u], md_size[%u], "
                   "pi_type[%u], max_io_xfer_size[%u], dsm[%u]\n",
                   nsinfo->id, nsinfo->name, nsinfo->sectors, nsinfo->sector_size,
                   nsinfo->md_size, nsinfo->pi_type, nsinfo->max_io_xfer_size, nsinfo->dsm);
    return 1;
}

uint32_t libstorage_get_ctrl_ns_info(const char *ctrlName, struct libstorage_namespace_info **ppNsInfo)
{
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    struct spdk_nvme_ns *ns = NULL;
    uint32_t ns_id;
    uint32_t num_ns;
    uint32_t count = 0;
    struct libstorage_namespace_info *nsinfo = NULL;
    int rc = 0;

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return 0;
    }

    if (ctrlName == NULL || ppNsInfo == NULL) {
        return 0;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    if (strncasecmp(ctrlName, "nvme", strlen("nvme")) == 0) {
        ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlName);
    }

    if (ctrlr == NULL) {
        SPDK_ERRLOG("Cannot find %s.\n", ctrlName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return 0;
    }
    num_ns = spdk_nvme_ctrlr_get_num_ns(ctrlr);
    if (!num_ns) {
        SPDK_ERRLOG("No namespace on %s.\n", ctrlName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return 0;
    }
    nsinfo = calloc(num_ns, sizeof(struct libstorage_namespace_info));
    if (nsinfo == NULL) {
        SPDK_ERRLOG("Failed to alloc memory for nsinfo\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return 0;
    }

    *ppNsInfo = nsinfo;
    for (ns_id = 1; ns_id <= num_ns; ns_id++) {
        ns = spdk_nvme_ctrlr_get_ns(ctrlr, ns_id);
        if (ns == NULL) {
            SPDK_NOTICELOG("Skipping invalid NS %u\n", ns_id);
            continue;
        }
        if (!spdk_nvme_ns_is_active(ns)) {
            SPDK_NOTICELOG("Skipping inactive NS %u\n", ns_id);
            continue;
        }

        nsinfo->size = spdk_nvme_ns_get_size(ns);
        nsinfo->sectors = spdk_nvme_ns_get_num_sectors(ns);
        nsinfo->sector_size = spdk_nvme_ns_get_sector_size(ns);
        nsinfo->md_size = spdk_nvme_ns_get_md_size(ns);
        nsinfo->pi_type = (uint8_t)spdk_nvme_ns_get_pi_type(ns);
        nsinfo->max_io_xfer_size = spdk_nvme_ns_get_max_io_xfer_size(ns);
        nsinfo->id = spdk_nvme_ns_get_id(ns);
        nsinfo->is_active = (uint8_t)spdk_nvme_ns_is_active(ns) & 0x1;
        nsinfo->ext_lba = (uint8_t)spdk_nvme_ns_supports_extended_lba(ns) & 0x1;
        nsinfo->dsm = (uint8_t)spdk_nvme_ns_is_dataset_mng_supported(ns) & 0x1;
        rc = snprintf_s(nsinfo->name, MAX_BDEV_NAME_LEN, MAX_BDEV_NAME_LEN - 1, "%sn%d", ctrlName, nsinfo->id);
        if (rc < 0) {
            SPDK_WARNLOG("[libstorage] snprintf failed\n");
        }
        SPDK_NOTICELOG("[%u]namespace[%s]: sectors[%lu], sector[%u], md[%u], "
                       "pi[%u], max_io_size[%u], dsm[%u]\n",
                       nsinfo->id, nsinfo->name, nsinfo->sectors, nsinfo->sector_size,
                       nsinfo->md_size, nsinfo->pi_type, nsinfo->max_io_xfer_size, nsinfo->dsm);
        count++;
        nsinfo++;
    }

    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return count;
}

#define MAX_NS 1024
int32_t libstorage_nvme_create_ctrlr(const char *pci_addr, const char *ctrlr_name)
{
    struct spdk_nvme_transport_id trid = {0};
    size_t count = MAX_NS;
    char **names = NULL;
    struct spdk_nvme_ctrlr *nvme_ctrlr = NULL;
    int32_t rc;

    if (pci_addr == NULL || ctrlr_name == NULL) {
        SPDK_ERRLOG("pci_addr or ctrlr_name is NULL\n");
        return -1;
    }

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    spdk_set_thread(g_masterThread);
    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    nvme_ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlr_name);
    if (nvme_ctrlr != NULL) {
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        SPDK_ERRLOG("controller %s exists\n", ctrlr_name);
        return -1;
    }

    trid.trtype = SPDK_NVME_TRANSPORT_PCIE;
    rc = strcpy_s(trid.traddr, sizeof(trid.traddr), pci_addr);
    if (rc != 0) {
        SPDK_ERRLOG("strcpy failed.\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    names = malloc(sizeof(char *) * count);
    if (names == NULL) {
        SPDK_ERRLOG("fail to malloc names\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }
    rc = spdk_bdev_nvme_create_self(&trid, ctrlr_name, (const char **)names, &count, NULL);

    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);

    if (rc != 0) {
        SPDK_ERRLOG("Failed to add controller %s.\n", ctrlr_name);
        free(names);
        return -1;
    }

    if (g_bRpcServer && libstorage_register_one_info_to_ublock(pci_addr, ctrlr_name) != 0) {
        SPDK_ERRLOG("Failed to register %s to ublock, delete it.\n", ctrlr_name);
        libstorage_nvme_delete_ctrlr(ctrlr_name);
        free(names);
        return -1;
    }

    nvme_ctrlr_clear_iostat_by_name(ctrlr_name);

    syslog(LOG_INFO, "Complete nvme %s create ctrlr %s!\n", pci_addr, ctrlr_name);
    free(names);

    return 0;
}

int32_t libstorage_nvme_delete_ctrlr(const char *ctrlr_name)
{
    struct nvme_ctrlr_info *ctrlr_info = NULL;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    if (ctrlr_name == NULL) {
        return -1;
    }

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    spdk_set_thread(g_masterThread);
    SPDK_WARNLOG("%s will be deleted.\n", ctrlr_name);
    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    if (nvme_ctrlr_get_info(ctrlr_name, &ctrlr_info) <= 0) {
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        SPDK_ERRLOG("failed to get controller info of %s\n", ctrlr_name);
        return -1;
    }

    ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlr_name);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] fail to get ctrlr by name\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        free(ctrlr_info);
        return -1;
    }

    /* set flag of shutdown */
    spdk_nvme_ctrlr_set_shutdown(ctrlr, true);

    /* free resource and operate according to nvme spec */
    spdk_bdev_nvme_remove_cb(ctrlr->cb_ctx, ctrlr);

    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);

    libstorage_remove_ctrlr_cap_info(ctrlr_name);
    libstorage_remove_rpc_register_info(ctrlr_name);

    nvme_ctrlr_clear_iostat_by_name(ctrlr_name);

    free(ctrlr_info);
    syslog(LOG_INFO, "Complete nvme delete ctrlr %s!\n", ctrlr_name);
    return 0;
}

static int32_t libstorage_attach_ns_to_ctrlr(const char *ctrlName, uint32_t nsid)
{
    int32_t ret;
    struct nvme_bdev_ctrlr *nvme = NULL;
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    struct spdk_nvme_ctrlr_list ctrlr_list;
    const struct spdk_nvme_ctrlr_data *tmpCdata = NULL;

    if (ctrlName == NULL || nsid < 1) {
        SPDK_ERRLOG("parameter error, ctrlName[%p], nsid[%u]\n", ctrlName, nsid);
        return -EINVAL;
    }

    nvme = nvme_ctrlr_get_by_name(ctrlName);
    if (nvme != NULL) {
        ctrlr = spdk_nvme_ctrlr_get_by_ctrlr(nvme);
    }

    if (ctrlr == NULL) {
        SPDK_ERRLOG("Cannot find %s.\n", ctrlName);
        return -EINVAL;
    }

    if (!spdk_nvme_ctrlr_is_ns_manage_supported(ctrlr)) {
        SPDK_ERRLOG("Controller %s does not support ns management.\n", ctrlName);
        return -EPERM;
    }

    tmpCdata = spdk_nvme_ctrlr_get_data(ctrlr);
    if (tmpCdata == NULL) {
        return -EINVAL;
    }
    ret = memset_s(&ctrlr_list, sizeof(struct spdk_nvme_ctrlr_list), 0, sizeof(struct spdk_nvme_ctrlr_list));
    if (ret == 0) {
        ctrlr_list.ctrlr_count = 1;
        ctrlr_list.ctrlr_list[0] = tmpCdata->cntlid;

        ret = spdk_nvme_ctrlr_attach_ns(ctrlr, nsid, &ctrlr_list);
    }
    if (ret != 0) {
        SPDK_ERRLOG("Failed to attach ns[%u] to %s.\n", nsid, ctrlName);
        return ret;
    }

    ret = bdev_nvme_update_ns(nvme, nsid);
    if (ret != 0) {
        SPDK_ERRLOG("Failed to create bdev by namespace[%u]!\n", nsid);
        return ret;
    }

    return ret;
}

static struct spdk_nvme_ctrlr *libstorage_get_nvme_ctrlr_and_check_is_ns_supported(const char *ctrlName)
{
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlName);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("Cannot find %s.\n", ctrlName);
        return NULL;
    }

    if (!spdk_nvme_ctrlr_is_ns_manage_supported(ctrlr)) {
        SPDK_ERRLOG("Controller %s does not support ns management.\n", ctrlName);
        return NULL;
    }

    return ctrlr;
}

static int libstorage_construct_ns_data(const char *ctrlName, struct spdk_nvme_ctrlr *ctrlr,
                                        uint64_t size, struct spdk_nvme_ns_data *ndata)
{
    int8_t format;
    struct ctrlr_capability_info capInfo;
    const struct spdk_nvme_ctrlr_data *cdata = NULL;
    uint64_t unvmcap = 0;
    uint32_t lbads = 0; /* value is reported in terms of a power of two */
    int rc;

    format = libstorage_get_ctrlr_cap_info(ctrlName, &capInfo, 0xFFFFFFFF, 0xFFFFFFFF);
    if (format < 0) {
        SPDK_ERRLOG("Failed to get the information of %s.\n", ctrlName);
        return format;
    }

    cdata = spdk_nvme_ctrlr_get_data(ctrlr);
    if (cdata != NULL) {
        lbads = capInfo.lbaf[format].lbads;
        unvmcap = cdata->unvmcap[0] >> lbads;
    }
    if (size > unvmcap) {
        SPDK_ERRLOG("require %lu sectors, but only %lu sectors available. \n", size, unvmcap);
        return -EINVAL;
    }

    rc = memset_s(ndata, sizeof(struct spdk_nvme_ns_data), 0, sizeof(struct spdk_nvme_ns_data));
    if (rc != 0) {
        SPDK_ERRLOG("memset failed.\n");
        return -EINVAL;
    }
    ndata->nsze = size;
    ndata->ncap = size;
    ndata->flbas.format = format;
    ndata->flbas.extended = capInfo.cur_extended;
    ndata->nmic.can_share = capInfo.cur_can_share;
    ndata->dps.pit = capInfo.cur_pi;
    ndata->dps.md_start = capInfo.cur_pil;

    return 0;
}

static inline int libstorage_check_for_create_namespace(const char *ctrlName, uint64_t size, char **outputName)
{
    if (ctrlName == NULL || outputName == NULL || size == 0) {
        SPDK_ERRLOG("parameter error, ctrlName[%p]  outputName[%p] size[%lu]\n", ctrlName, outputName, size);
        return -EINVAL;
    }

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    return 0;
}

int32_t libstorage_create_namespace(const char *ctrlName, uint64_t size, char **outputName)
{
    uint32_t nsid;
    struct spdk_nvme_ns_data ndata;
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    int32_t rc;

    rc = libstorage_check_for_create_namespace(ctrlName, size, outputName);
    if (rc < 0) {
        return rc;
    }

    spdk_set_thread(g_masterThread);
    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    ctrlr = libstorage_get_nvme_ctrlr_and_check_is_ns_supported(ctrlName);
    if (ctrlr == NULL) {
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -EPERM;
    }

    rc = libstorage_construct_ns_data(ctrlName, ctrlr, size, &ndata);
    if (rc < 0) {
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return rc;
    }

    nsid = spdk_nvme_ctrlr_create_ns(ctrlr, &ndata);
    if (nsid == NS_ID_INVALID) {
        SPDK_ERRLOG("Failed to create namespace on %s.\n", ctrlName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -EINVAL;
    }

    SPDK_WARNLOG("Create namespace[%u] on %s successfully.\n", nsid, ctrlName);
    if (libstorage_attach_ns_to_ctrlr(ctrlName, nsid) != 0) {
        rc = spdk_nvme_ctrlr_delete_ns(ctrlr, nsid);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        SPDK_ERRLOG("Failed to attach namespace to %s, delete it. rc[%d].\n", ctrlName, rc);
        return rc;
    }

    spdk_nvme_ctrlr_update_unvmcap(ctrlr);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    *outputName = spdk_sprintf_alloc("%sn%d", ctrlName, nsid);
    return nsid;
}

/* Verify that there is an IO operation on the NS and require that IO be stopped before deleting */
static int32_t libstorage_verify_io_in_ns(const char *pctrlName,
                                          struct nvme_bdev_ctrlr *nvme,
                                          struct spdk_nvme_ctrlr *ctrlr,
                                          uint32_t nsid)
{
    int32_t ret;
    if (!spdk_bdev_can_remove(nvme, nsid)) {
        SPDK_ERRLOG("namespace[%sn%u] is opened for IO.\n", pctrlName, nsid);
        return -EPERM;
    }
    ret = spdk_nvme_ctrlr_delete_ns(ctrlr, nsid);
    if (ret != 0) {
        SPDK_ERRLOG("Failed to delete namespace[%u] from %s.\n", nsid, pctrlName);
        spdk_bdev_set_ns_normal(nvme, nsid);
        return ret;
    } else {
        SPDK_WARNLOG("Deleted namespace[%u] from %s successfully.\n", nsid, pctrlName);
        spdk_nvme_ctrlr_update_unvmcap(ctrlr);
    }

    ret = bdev_nvme_update_ns(nvme, nsid);
    if (ret != 0) {
        SPDK_ERRLOG("Failed to delete bdev by namespace[%u]!\n", nsid);
    }
    return ret;
}

int32_t libstorage_delete_namespace(const char *pctrlName, uint32_t nsid)
{
    int32_t ret = 0;
    struct nvme_bdev_ctrlr *nvme = NULL;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    if (pctrlName == NULL || nsid < 1) {
        SPDK_ERRLOG("parameter error, ctrlName[%p], nsid[%u]\n", pctrlName, nsid);
        return -EINVAL;
    }

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    spdk_set_thread(g_masterThread);
    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    nvme = nvme_ctrlr_get_by_name(pctrlName);
    if (nvme != NULL) {
        ctrlr = spdk_nvme_ctrlr_get_by_ctrlr(nvme);
    }

    if (ctrlr == NULL) {
        SPDK_ERRLOG("Cannot find this nvme controller[%s]\n", pctrlName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -EINVAL;
    }

    if (!spdk_nvme_ctrlr_is_ns_manage_supported(ctrlr)) {
        SPDK_ERRLOG("Controller %s does not support ns management.\n", pctrlName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -EPERM;
    }

    if (!spdk_nvme_ctrlr_is_active_ns(ctrlr, nsid)) {
        if (spdk_nvme_ns_is_allocated(ctrlr, nsid)) {
            ret = spdk_nvme_ctrlr_delete_ns(ctrlr, nsid);
            if (ret != 0) {
                SPDK_ERRLOG("Failed to delete allocated namespace[%u] from %s.\n", nsid, pctrlName);
            } else {
                SPDK_WARNLOG("Deleted inactive namespace[%u] from %s successfully.\n", nsid, pctrlName);
            }
        } else {
            SPDK_WARNLOG("ns[%u] is not exist in %s.\n", nsid, pctrlName);
            ret = -ENODEV;
        }
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return ret;
    }

    ret = libstorage_verify_io_in_ns(pctrlName, nvme, ctrlr, nsid);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return ret;
}

static int32_t libstorage_get_ns_num_to_delete(const char *ctrlName)
{
    int32_t num_ns;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    ctrlr = spdk_nvme_ctrlr_get_by_name(ctrlName);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("Cannot find this nvme controller[%s]\n", ctrlName);
        return -EINVAL;
    }

    if (!spdk_nvme_ctrlr_is_ns_manage_supported(ctrlr)) {
        SPDK_ERRLOG("Controller %s does not support ns management.\n", ctrlName);
        return -EPERM;
    }

    /* spdk_nvme_ctrlr_get_num_ns return value will not bigger than 1024 */
    num_ns = spdk_nvme_ctrlr_get_num_ns(ctrlr);
    return num_ns;
}

int32_t libstorage_delete_all_namespace(const char *ctrlName)
{
    int32_t ret;
    int32_t num_ns;
    int32_t ns_id;

    if (ctrlName == NULL) {
        return -EINVAL;
    }

    if (!g_bSpdkInitcomplete) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -EPERM;
    }

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    num_ns = libstorage_get_ns_num_to_delete(ctrlName);
    if (num_ns <= 0) {
        SPDK_NOTICELOG("Fail to get ns number, or no namespace on this controller[%s]\n", ctrlName);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return num_ns;
    }

    for (ns_id = 1; ns_id <= num_ns; ns_id++) {
        ret = libstorage_delete_namespace(ctrlName, ns_id);
        if (ret == -ENODEV) {
            continue;
        } else if (ret != 0) {
            SPDK_ERRLOG("Failed to delete namespace[%u] on %s\n", ns_id, ctrlName);
            libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
            return ret;
        }
    }

    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return 0;
}

static bool libstorage_is_nvme_device(const char *pathname)
{
    /* NVMe isn't registered to the Block Device Layer, so it can only be identified by name */
    if (strncasecmp(pathname, "nvme", strlen("nvme")) == 0) {
        return true;
    }
    return false;
}

static __always_inline bool libstorage_is_valid_fd(int fd)
{
    static int validRange = (int)NVME_DISK << DISK_TYPE_SHIFT2_FOR_FD | (int)NVME_DISK << DISK_TYPE_SHIFT1_FOR_FD;
    return fd > validRange;
}

int32_t libstorage_open(const char *devfullname)
{
    int32_t fd = 0;

    if (devfullname == NULL) {
        return -1;
    }

    if (spdk_unlikely(!g_bSpdkInitcomplete)) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -1;
    }

    if (!libstorage_is_nvme_device(devfullname)) {
        SPDK_ERRLOG("%s is not NVMe device\n", devfullname);
        return -1;
    }

    fd = libstorage_open_poll(devfullname);

    syslog(LOG_INFO, "%s is opened by thread[%lu]. fd[%d]!\n", devfullname, pthread_self(), fd);
    return fd;
}

int32_t libstorage_close(int32_t fd)
{
    int32_t err = 0;

    if (spdk_likely(!g_bSpdkInitcomplete)) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return -1;
    }
    if (!libstorage_is_valid_fd(fd)) {
        SPDK_ERRLOG("%d is not valid fd\n", fd);
        return -1;
    }

    err = libstorage_close_poll(fd);

    syslog(LOG_INFO, "fd[%d] is closed by thread[%lu]. err[%d]!\n", fd, pthread_self(), err);
    return err;
}

static bool async_io_completion_dif_read_fail(const LIBSTORAGE_IO_T *io, const struct spdk_bdev_io *bdev_io)
{
    if (io->opcode == (uint16_t)OP_READ && (io->pi_action & 0x03) == (uint8_t)IO_E2E_PROTECTION &&
               (io->pi_action & (uint8_t)FLAG_CALCRC) && !libstorage_dif_verify_crc(bdev_io->bdev, io)) {
        SPDK_ERRLOG("Failed to read %s, crc16 is wrong\n", bdev_io->bdev->name);
        return true;
    } else if (io->opcode == (uint16_t)OP_READV && (io->pi_action & 0x03) == (uint8_t)IO_E2E_PROTECTION &&
               (io->pi_action & (uint8_t)FLAG_CALCRC) && !libstorage_dif_verify_crc_v(bdev_io->bdev, io)) {
        SPDK_ERRLOG("Failed to readv %s, crc16 is wrong\n", bdev_io->bdev->name);
        return true;
    }

    return false;
}

void async_io_completion_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    LIBSTORAGE_IO_T *io = NULL;
    int32_t bserrno = 0;
    int32_t scterrno = 0;
    LIBSTORAGE_CALLBACK_FUNC cb;
    static char *op_name[OP_NOP] = { "NA", "read", "write", "readv", "writev", "deallocate", "nop" };

    if (cb_arg == NULL || bdev_io == NULL) {
        SPDK_ERRLOG("Invalid parameter\n");
        return;
    }

    io = (LIBSTORAGE_IO_T *)((uintptr_t)cb_arg - offsetof(struct libstorage_io, location));

    if (spdk_unlikely(!success)) {
        if (bdev_io->internal.status == (int8_t)SPDK_BDEV_IO_STATUS_NVME_ERROR) {
            bserrno = bdev_io->internal.error.nvme.sc;
            scterrno = bdev_io->internal.error.nvme.sct;
        } else {
            bserrno = -EIO;
        }

        SPDK_ERRLOG("Failed to %s %s block on offset[%lu]. sc[%d], sct[%d]\n", op_name[io->opcode],
                    bdev_io->bdev->name, io->offset, bserrno, scterrno);
    } else if (async_io_completion_dif_read_fail(io, bdev_io)) {
        bserrno = -EIO;
    }
#ifdef SPDK_CONFIG_ERR_INJC
    libstorage_err_injc_io_process(bdev_io->bdev->name, io, &bserrno, &scterrno);
#endif
    cb = io->cb;
    spdk_mb();
    io->cb = NULL;
    spdk_mb();
    if (cb) {
        io->location = (uint8_t)LOCAL_LIBSTORAGE_CALLBACK;
        cb(bserrno, scterrno, io->cb_arg);
        libstorage_io_t_free_buf(io);
    } else {
        SPDK_ERRLOG("Oops. Invalid io[%p], fd[%d] op[%u] offset[%lu]\n", io, io->fd, io->opcode, io->offset);
        if (io->magic != MEMORY_MAGIC) {
            SPDK_ERRLOG("IO[0x%p]'s magic[0x%X] is invalid.\n", io, io->magic);
        }
    }

    spdk_bdev_free_io(bdev_io);
}

static int32_t libstorage_submit_io(LIBSTORAGE_IO_T *submitio)
{
    int32_t err = 0;

    err = libstorage_submit_io_poll(submitio);

    return err;
}

int32_t libstorage_deallocate_block(int32_t fd, struct libstorage_dsm_range_desc *range, uint16_t range_count,
                                    LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg)
{
    int rc;
    LIBSTORAGE_IO_T *io = NULL;

    if (fd < 0) {
        return -EBADF;
    }
    if (range == NULL || range_count == 0 || range_count > LIBSTORAGE_MAX_DSM_RANGE_DESC_COUNT) {
        return -EINVAL;
    }
    if (cb == NULL) {
        return -EINVAL;
    }

    io = (LIBSTORAGE_IO_T *)libstorage_io_t_alloc_buf();
    if (io == NULL) {
        return -ENOMEM;
    }

    io->buf = NULL;
    io->fd = fd;
    io->location = (uint8_t)LOCAL_RECEIVE_APP;
    io->md_buf = (void *)range;
    io->md_len = range_count;
    io->nbytes = 0;
    io->offset = range[0].lba;
    io->opcode = (uint16_t)OP_DEALLOCATE;
    io->fua = (uint8_t)IO_FUA_NO;
    io->pi_action = (uint8_t)IO_NO_PROTECTION;
    io->cb = cb;
    io->cb_arg = cb_arg;
    io->magic = MEMORY_MAGIC;
    io->err = 0;

    rc = libstorage_submit_io(io);
    if (rc != 0) {
        libstorage_io_t_free_buf(io);
    }

    return rc;
}

static __always_inline int32_t libstorage_rw_valid_param(int32_t fd, void *buf, int bufSize, size_t nbytes, void *cb)
{
    if (fd < 0) {
        return -EBADF;
    }

    if (buf == NULL || bufSize <= 0 || nbytes == 0 || cb == NULL) {
        return -EINVAL;
    }

    return 0;
}

int32_t libstorage_async_write(int32_t fd, void *buf, size_t nbytes, uint64_t offset, void *md_buf, size_t md_len,
                               enum libstorage_crc_and_prchk dif_flag,
                               LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg)
{
    int32_t rc;
    LIBSTORAGE_IO_T *iow = NULL;

    rc = libstorage_rw_valid_param(fd, buf, (int)nbytes, nbytes, cb);
    if (rc != 0) {
        return rc;
    }

    iow = (LIBSTORAGE_IO_T *)libstorage_io_t_alloc_buf();
    if (iow == NULL) {
        return -ENOMEM;
    }

    iow->buf = buf;
    iow->fd = fd;
    iow->location = (uint8_t)LOCAL_RECEIVE_APP;
    iow->md_buf = md_buf;
    iow->md_len = md_len;
    iow->nbytes = nbytes;
    iow->offset = offset;
    iow->opcode = (uint16_t)OP_WRITE;
    iow->fua = (uint8_t)IO_FUA_NO;
    /* bit 3: libstorage or app cal crc */
    iow->pi_action = (uint8_t)dif_flag << 2; /* bit 2: whether enable protection information check; */
    iow->cb = cb;
    iow->cb_arg = cb_arg;
    iow->magic = MEMORY_MAGIC;
    iow->err = 0;

    rc = libstorage_submit_io(iow);
    if (rc != 0) {
        libstorage_io_t_free_buf(iow);
    }

    return rc;
}

int32_t libstorage_async_writev(int32_t fd, struct iovec *piov, int iovcnt, size_t nbytes, uint64_t offset,
                                void *md_buf, size_t md_len, enum libstorage_crc_and_prchk dif_flag,
                                LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg)
{
    int rc;
    LIBSTORAGE_IO_T *iowv = NULL;

    rc = libstorage_rw_valid_param(fd, piov, iovcnt, nbytes, cb);
    if (rc != 0) {
        return rc;
    }

    if (md_buf != NULL || md_len != 0) {
        SPDK_ERRLOG("libstorage sgl not support separate meta data mode!\n");
        return -EINVAL;
    }

    iowv = (LIBSTORAGE_IO_T *)libstorage_io_t_alloc_buf();
    if (iowv == NULL) {
        return -ENOMEM;
    }

    iowv->iovs = piov;
    iowv->iovcnt = iovcnt;
    iowv->fd = fd;
    iowv->location = (uint8_t)LOCAL_RECEIVE_APP;
    iowv->md_buf = md_buf;
    iowv->md_len = md_len;
    iowv->nbytes = nbytes;
    iowv->offset = offset;
    iowv->opcode = (uint16_t)OP_WRITEV;
    iowv->fua = (uint8_t)IO_FUA_NO;
    /* bit 3: libstorage or app cal crc */
    iowv->pi_action = (uint8_t)dif_flag << 2;   /* bit 2: whether enable protection information check; */
    iowv->cb = cb;
    iowv->cb_arg = cb_arg;
    iowv->magic = MEMORY_MAGIC;
    iowv->err = 0;

    rc = libstorage_submit_io(iowv);
    if (rc != 0) {
        libstorage_io_t_free_buf(iowv);
    }

    return rc;
}

int32_t libstorage_async_read(int32_t fd, void *buf, size_t nbytes, uint64_t offset, void *md_buf, size_t md_len,
                              enum libstorage_crc_and_prchk dif_flag, LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg)
{
    int rc;
    LIBSTORAGE_IO_T *ior = NULL;

    rc = libstorage_rw_valid_param(fd, buf, (int)nbytes, nbytes, cb);
    if (rc != 0) {
        return rc;
    }

    ior = (LIBSTORAGE_IO_T *)libstorage_io_t_alloc_buf();
    if (ior == NULL) {
        return -ENOMEM;
    }

    ior->buf = buf;
    ior->fd = fd;
    ior->location = (uint8_t)LOCAL_RECEIVE_APP;
    ior->md_buf = md_buf;
    ior->md_len = md_len;
    ior->nbytes = nbytes;
    ior->offset = offset;
    ior->opcode = (uint16_t)OP_READ;
    ior->fua = (uint8_t)IO_FUA_NO;
    /* bit 3: libstorage or app cal crc */
    ior->pi_action = (uint8_t)dif_flag << 2;   /* bit 2: whether enable protection information check; */
    ior->cb = cb;
    ior->cb_arg = cb_arg;
    ior->magic = MEMORY_MAGIC;
    ior->err = 0;

    rc = libstorage_submit_io(ior);
    if (rc != 0) {
        libstorage_io_t_free_buf(ior);
    }

    return rc;
}

int32_t libstorage_async_readv(int32_t fd, struct iovec *iov, int iovcnt, size_t nbytes, uint64_t offset, void *md_buf,
                               size_t md_len,
                               enum libstorage_crc_and_prchk dif_flag, LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg)
{
    int rc;
    LIBSTORAGE_IO_T *iorv = NULL;

    rc = libstorage_rw_valid_param(fd, iov, iovcnt, nbytes, cb);
    if (rc != 0) {
        return rc;
    }

    if (md_buf != NULL || md_len != 0) {
        SPDK_ERRLOG("libstorage sgl not support separate meta data mode!\n");
        return -EINVAL;
    }

    iorv = (LIBSTORAGE_IO_T *)libstorage_io_t_alloc_buf();
    if (iorv == NULL) {
        return -ENOMEM;
    }

    iorv->iovs = iov;
    iorv->iovcnt = iovcnt;
    iorv->fd = fd;
    iorv->location = (uint8_t)LOCAL_RECEIVE_APP;
    iorv->md_buf = md_buf;
    iorv->md_len = md_len;
    iorv->nbytes = nbytes;
    iorv->offset = offset;
    iorv->opcode = (uint16_t)OP_READV;
    iorv->fua = (uint8_t)IO_FUA_NO;
    /* bit 3: libstorage or app cal crc */
    iorv->pi_action = (uint8_t)dif_flag << 2;   /* bit 2: whether enable protection information check; */
    iorv->cb = cb;
    iorv->cb_arg = cb_arg;
    iorv->magic = MEMORY_MAGIC;
    iorv->err = 0;

    rc = libstorage_submit_io(iorv);
    if (rc != 0) {
        libstorage_io_t_free_buf(iorv);
    }

    return rc;
}

static void io_completion_cb(int32_t cb_status, int32_t sct_code, void *cb_arg)
{
    struct rw_completion_status *status = (struct rw_completion_status *)cb_arg;

    if (status == NULL) {
        return;
    }

    status->result = cb_status | (sct_code << 16); /* pre 16 bits to hold sct code */
    spdk_wmb();
    status->done = true;
}

int32_t libstorage_sync_read(int fd, void *buf, size_t nbytes, off_t offset)
{
    int err;
    struct rw_completion_status status;

    if (offset < 0) {
        SPDK_ERRLOG("libstorage sync read does not support negative offset!\n");
        return -EINVAL;
    }

    status.done = false;
    err = libstorage_async_read(fd, buf, nbytes, offset, NULL, 0, LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                io_completion_cb, &status);
    if (err != 0) {
        return err;
    }

    while (!status.done) {}

    return status.result;
}

int32_t libstorage_sync_write(int fd, const void *buf, size_t nbytes, off_t offset)
{
    int err;
    struct rw_completion_status status;

    if (offset < 0) {
        SPDK_ERRLOG("libstorage sync write does not support negative offset!\n");
        return -EINVAL;
    }

    status.done = false;
    err = libstorage_async_write(fd, (void *)buf, nbytes, offset, NULL, 0, LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                 io_completion_cb, &status);
    if (err != 0) {
        return err;
    }

    while (!status.done) {}

    return status.result;
}

static void libstorage_init_ctrlr_cap_info(void)
{
    int32_t num_ctrlr;
    int32_t i = 0;
    struct nvme_ctrlr_info *ctrlrInfo = NULL;
    struct ctrlr_capability_info *pCtrlrCap = NULL;

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);
    num_ctrlr = libstorage_nvme_ctrlr_get_info(&ctrlrInfo);
    if (num_ctrlr <= 0) {
        SPDK_ERRLOG("No any NVMe disk is configured in this system.\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return;
    }

    for (i = 0; i < num_ctrlr; i++) {
        pCtrlrCap = libstorage_add_ctrlr_cap_info(ctrlrInfo[i].ctrlName, &ctrlrInfo[i]);
        if (pCtrlrCap == NULL) {
            libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
            SPDK_ERRLOG("Add controller capinfo in init failed, exit.\n");
            exit(EXIT_FAILURE);
        }
    }

    free(ctrlrInfo);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
}

struct spdk_thread* libstorage_create_spdk_thread(void)
{
    struct spdk_thread *thread = NULL;
    struct spdk_cpuset tmp_cpumask = {};
    char thread_name[SPDK_THREAD_NAME_LENGTH];
    int ret;

    ret = snprintf_s(thread_name, SPDK_THREAD_NAME_LENGTH, SPDK_THREAD_NAME_LENGTH - 1,
                     "thread_%u", pthread_self());
    if (ret < 0) {
        SPDK_WARNLOG("thread_name snprintf failed\n");
        return NULL;
    }

    spdk_cpuset_zero(&tmp_cpumask);
    spdk_cpuset_set_cpu(&tmp_cpumask, spdk_env_get_current_core(), true);
    thread = spdk_thread_create(thread_name, &tmp_cpumask);

    if (thread == NULL) {
        SPDK_ERRLOG("Failed to allocate thread for master core.\n");
        return NULL;
    }

    return thread;
}

static void uio_ublock_lock(void)
{
    if (g_uio_ublock_lock != NULL) {
        while (!__sync_bool_compare_and_swap(g_uio_ublock_lock, LOCK_INIT, getpid())) {
            usleep(1);
        }
    }
}

static void uio_ublock_unlock(void)
{
    if (g_uio_ublock_lock != NULL) {
        __sync_bool_compare_and_swap(g_uio_ublock_lock, getpid(), LOCK_INIT);
    }
}

int32_t libstorage_nvme_reload_ctrlr(const char *cfgfile)
{
    struct libstorage_nvme_config *nvmes_config = NULL;
    int32_t num_nvme_config;
    int32_t i = 0;
    int32_t ret = 0;

    if (cfgfile == NULL) {
        SPDK_ERRLOG("Config file is NULL\n");
        return -EINVAL;
    }

    nvmes_config = (struct libstorage_nvme_config *)malloc(sizeof(struct libstorage_nvme_config) *
                                                           LIBSTORAGE_CONFIG_MAX_CONTROLLERS);
    if (nvmes_config == NULL) {
        SPDK_ERRLOG("fail to malloc memory of nvmes_config\n");
        return -ENOMEM;
    }

    spdk_set_thread(g_masterThread);
    (void)libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);
    num_nvme_config = libstorage_init_nvme_conf(nvmes_config, LIBSTORAGE_LOAD_MAX_CONTROLLERS);
    if (num_nvme_config < 0) {
        SPDK_ERRLOG("Init nvme config failed\n");
        (void)libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        free(nvmes_config);
        return num_nvme_config;
    }

    num_nvme_config = libstorage_get_nvme_from_conf(cfgfile, nvmes_config, num_nvme_config);
    if (num_nvme_config < 0) {
        SPDK_ERRLOG("Failed to get nvme config\n");
        (void)libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        free(nvmes_config);
        return num_nvme_config;
    }

    uio_ublock_lock();
    for (i = 0; i < num_nvme_config; i++) {
        if (nvmes_config[i].state == RELOAD_DELETE) {
            (void)libstorage_nvme_delete_ctrlr(nvmes_config[i].ctrlName);
        }
        else if (nvmes_config[i].state == RELOAD_CREATE) {
            if (libstorage_nvme_create_ctrlr(nvmes_config[i].pciAddr, nvmes_config[i].ctrlName) != 0) {
                SPDK_ERRLOG("Failed to create controller for %s with name %s\n",
                            nvmes_config[i].pciAddr, nvmes_config[i].ctrlName);
                ret = -EAGAIN;
            }
        }
    }
    uio_ublock_unlock();

    (void)libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    free(nvmes_config);
    return ret;
}

static int32_t libstorage_construct_resource(void)
{
    int32_t ret;

    /* initialize the mutex 'g_libstorage_admin_op_mutex' */
    g_libstorage_admin_op_mutex = libstorage_process_mutex_init();
    if (g_libstorage_admin_op_mutex == NULL) {
        SPDK_ERRLOG("Cannot init mutex for admin-operation.\n");
        return -1;
    }
    libstorage_init_ctrlr_cap_info();

    /* create libstorage_io_t mempool should be after spdk_env_init() */
    ret = libstorage_io_t_mempool_initialize();
    if (ret != 0) {
        SPDK_ERRLOG("Cannot init mempool, ret: %d!\n", ret);
        return ret;
    }

    /* create share memory for performance statistics */
    ret = libstorage_stat_init();
    if (ret != 0) {
        SPDK_ERRLOG("Cannot create share memory for performance statistics!\n");
    }

    /* initialize the mutex 'g_io_stat_map_mutex' */
    g_io_stat_map_mutex = libstorage_process_mutex_init();
    if (g_io_stat_map_mutex == NULL) {
        SPDK_ERRLOG("Cannot init g_io_stat_map_mutex.\n");
        return -1;
    }

    ret = uio_ublock_lock_init();
    if (ret != 0) {
        SPDK_ERRLOG("Cannot create share memory for lock!\n");
        return -1;
    }

    return 0;
}

static void libstorage_spdk_init_fn(int rc, void *arg)
{
    if (rc < 0) {
        libstorage_exit_module();
    }
    return;
}

static void libstorage_spdk_fini_fn(void *arg)
{
    return;
}

static int32_t libstorage_init_spdk_module(void)
{
    int32_t ret;

    spdk_reactors_use(true);
    ret = libstorage_init_with_reactor();

    if (ret != 0) {
        SPDK_ERRLOG("Failed to initialize system environment.\n");
        return ret;
    }

    // try to lockup the file when doing nvme probe operation
    uio_ublock_lock();

    spdk_subsystem_init(libstorage_spdk_init_fn, NULL);

    // probe operation done, release the flock
    uio_ublock_unlock();
    return 0;
}

int32_t libstorage_init_module(const char *cfgfile)
{
    int32_t ret;
    static libstorage_atomic32_t run_once = LIBSTORAGE_ATOMIC32_INIT(0);
    if (!libstorage_atomic32_test_and_set(&run_once, 1)) {
        SPDK_ERRLOG("Initialize repeatedly!\n");
        return -1;
    }

    spdk_log_set_print_level(SPDK_LOG_WARN);

    ret = libstorage_parse_conf_item(cfgfile);
    if (ret != 0) {
        SPDK_ERRLOG("Read config file failed\n");
        goto FAILURE_EXIT;
    }

    ret = libstorage_init_spdk_module();
    if (ret != 0) {
        SPDK_ERRLOG("Failed to init spdk module, ret: %d.\n", ret);
        goto FAILURE_EXIT;
    }
    if (libstorage_construct_resource() != 0) {
        SPDK_ERRLOG("Failed to construct resource.\n");
        goto FAILURE_EXIT;
    }

    /* start rpc server */
    libstorage_start_rpc_server();
    g_bSpdkInitcomplete = true;
    syslog(LOG_INFO, "Complete LibStorage Module initialization!\n");
    return 0;

FAILURE_EXIT:
    spdk_conf_free(g_libstorage_config);
    g_libstorage_config = NULL;
    libstorage_io_t_mempool_free();
    if (g_masterThread != NULL) {
        spdk_thread_exit(spdk_get_thread());
        spdk_set_thread_exited(spdk_get_thread());
        spdk_thread_destroy(spdk_get_thread());
    }
    exit(EXIT_FAILURE);
}

static bool g_libstorageExit = false;
int32_t libstorage_exit_module(void)
{
    syslog(LOG_INFO, "LibStorage Module exit!\n");
    if (g_bSpdkInitcomplete) {
        g_bSpdkInitcomplete = false;
        g_libstorageExit = true;
    }
    return 0;
}

static void libstorage_destruct_resource(void)
{
    struct ctrlr_capability_info *pCtrlrCap = NULL;

    /* destroy the mutex 'g_libstorage_admin_op_mutex' */
    libstorage_process_mutex_destroy(g_libstorage_admin_op_mutex);
    g_libstorage_admin_op_mutex = NULL;

    /* destroy the mutex 'g_io_stat_map_mutex' */
    libstorage_process_mutex_destroy(g_io_stat_map_mutex);
    g_io_stat_map_mutex = NULL;

    (void)pthread_mutex_lock(&g_ctrlr_cap_mutex);
    while (!SLIST_EMPTY(&g_ctrlr_cap_list)) {
        pCtrlrCap = (struct ctrlr_capability_info *)SLIST_FIRST(&g_ctrlr_cap_list);
        SLIST_REMOVE_HEAD(&g_ctrlr_cap_list, slist);
        free(pCtrlrCap);
    }
    (void)pthread_mutex_unlock(&g_ctrlr_cap_mutex);

    /* free libstorage_io_t mempool after free other mempools in spdk_subsysterm_fini() */
    libstorage_io_t_mempool_free();
    spdk_conf_free(g_libstorage_config);

    (void)libstorage_stat_exit();
    g_io_stat_map = NULL;

    if (g_uio_ublock_lock != NULL) {
        uio_ublock_unlock();
        (void)munmap(g_uio_ublock_lock, sizeof(uint32_t));
    }
    g_uio_ublock_lock = NULL;

    if (g_masterThread != NULL) {
        spdk_thread_exit(spdk_get_thread());
        spdk_set_thread_exited(spdk_get_thread());
        spdk_thread_destroy(spdk_get_thread());
    }
    spdk_reactors_fini();
}

__attribute__((destructor)) static void libstorage_auto_exit(void)
{
    int32_t rc;

    syslog(LOG_INFO, "LibStorage_auto_exit begin!\n");
    if (!g_bSpdkInitcomplete && !g_libstorageExit) {
        syslog(LOG_INFO, "Libstorage initialization exception, LibStorage_auto_exit end!\n");
        return;
    }
    g_bSpdkInitcomplete = false;

    if (spdk_get_thread() != g_masterThread) {
        syslog(LOG_INFO, "Only in the main thread destructor, LibStorage_auto_exit end!\n");
        return;
    }

    LibstoragePollExitCheckResource();
    rc = libstorage_exit_with_reactor();
    /* stop rpc server */
    libstorage_stop_rpc_server();
    spdk_subsystem_fini(libstorage_spdk_fini_fn, NULL);

    libstorage_destruct_resource();
    syslog(LOG_INFO, "LibStorage_auto_exit end[%d]!\n", rc);
    spdk_log_close();
}
