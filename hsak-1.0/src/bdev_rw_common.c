/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * hsak is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: HSAK IO interface for external users.
 * Author: xiehuiming@huawei.com
 * Create: 2019-04-30
 */
#include <sys/file.h>
#include "bdev_rw_internal.h"
#include "bdev_rw_rpc_internal.h"
#include "spdk/crc16.h"

/* The total reserve memory for libstorage about 800M */
#define RESERVE_TOTAL_MEMORY (800 * 1024 * 1024)
/* The min reserve memory for libstorage in each memory segment */
#define RESERVE_MIN_MEMORY (100 * 1024 * 1024)

#define MB      (1024 * 1024)

static void *g_io_t_mem_manage[LIBSTORAGE_IO_T_POOL_SIZE] = {NULL};
static libstorage_atomic32_t g_alloc_io_t_num;
static libstorage_atomic32_t g_alloc_io_t_idx;
static libstorage_atomic32_t g_free_io_t_idx;
static TAILQ_HEAD(, libstorage_dpdk_init_notify) g_dpdkInitNotify = TAILQ_HEAD_INITIALIZER(g_dpdkInitNotify);
/* the index of dpdk memseg array */
int g_memseg_index = 0;
static int g_reserve_total_memory = 0;

void libstorage_add_notify_func(struct libstorage_dpdk_init_notify *notification)
{
    TAILQ_INSERT_TAIL(&g_dpdkInitNotify, notification, tailq);
}

static void libstorage_get_dpdk_meminfo(const struct rte_memseg_list *memsegs, int len,
                                        struct libstorage_dpdk_init_notify_arg *arg)
{
    uint16_t argIdx = 0;
    bool first = true;
    uint16_t seg_idx;
    uint64_t reserve_len = 0;
    const struct rte_memseg_list *seg = NULL;

    arg->memsegCount = 0;
    for (seg_idx = 0; seg_idx < g_memseg_index; seg_idx++) {
        seg = &memsegs[seg_idx];

        if (seg->base_va != NULL && seg->memseg_arr.count != 0) {
            if (spdk_unlikely(first)) {
                arg->baseAddr = seg->addr_64;
                arg->memsegCount++;
                arg->memseg[argIdx].virtAddr = seg->addr_64;
                arg->memseg[argIdx].memLen = seg->memseg_arr.count * seg->page_sz;
                first = false;
                continue;
            }

            if ((arg->memseg[argIdx].virtAddr + arg->memseg[argIdx].memLen) != seg->addr_64) {
                arg->memseg[++argIdx].virtAddr = seg->addr_64;
                arg->memseg[argIdx].memLen = seg->memseg_arr.count * seg->page_sz;
                arg->memsegCount++;
            } else {
                arg->memseg[argIdx].memLen += seg->memseg_arr.count * seg->page_sz;
            }
        }
    }
    if (arg->memsegCount) {
        reserve_len = g_reserve_total_memory / arg->memsegCount;
    }

    if (reserve_len < RESERVE_MIN_MEMORY) {
        reserve_len = RESERVE_MIN_MEMORY;
    }

    for (argIdx = 0; argIdx < arg->memsegCount; argIdx++) {
        if (arg->memseg[argIdx].memLen < reserve_len) {
            arg->memseg[argIdx].allocLen = 0;
        } else {
            arg->memseg[argIdx].allocLen = arg->memseg[argIdx].memLen - reserve_len;
        }
        syslog(LOG_INFO, "[%u]memseg: 0x%lx, length of memseg: %lubytes, allocLen: %lubytes.\n",
               argIdx, arg->memseg[argIdx].virtAddr, arg->memseg[argIdx].memLen, arg->memseg[argIdx].allocLen);
    }
}

static int memory_iter_cb(const struct rte_memseg_list *msl, const struct rte_memseg *ms, size_t len, void *arg)
{
    struct rte_memseg_list *temp = arg;
    temp[g_memseg_index] = *msl;
    g_memseg_index++;
    if (g_memseg_index == RTE_MAX_MEMSEG_LISTS) {
        SPDK_ERRLOG("[libstorage]memsegs is large than 128!\n");
        return -1;
    }
    return 0;
}

void libstorage_notify_dpdk_init(void)
{
    struct libstorage_dpdk_init_notify *notify = NULL;
    struct libstorage_dpdk_init_notify_arg *arg = NULL;
    struct rte_memseg_list memsegs[RTE_MAX_MEMSEG_LISTS];
    int ret;

    if (TAILQ_EMPTY(&g_dpdkInitNotify)) {
        SPDK_NOTICELOG("[libstorage]Needn't notify\n");
        return;
    }

    ret = rte_memseg_contig_walk(memory_iter_cb, memsegs);
    if (ret != 0) {
        SPDK_ERRLOG("[libstorage]get memsegs failed!\n");
        return;
    }

    arg = malloc(sizeof(struct libstorage_dpdk_init_notify_arg) +
                 sizeof(struct libstorage_dpdk_contig_mem) * RTE_MAX_MEMSEG_LISTS);
    if (arg == NULL) {
        SPDK_ERRLOG("[libstorage]No Memory\n");
        return;
    }
    /* arg->memseg should direct to arg->memseg[0]. For the pointer of arg direct to the space
     * includes the struct of arg itself and RTE_MAX_MEMSEG_LISTS memseg elements, and (arg + 1)
     * is equal to the arg address add the sizeof(struct libstorage_dpdk_init_notify_arg), so
     * (arg + 1) is direct to arg->memseg[0].
     */
    arg->memseg = (void *)(arg + 1);
    libstorage_get_dpdk_meminfo(memsegs, g_memseg_index, arg);

    TAILQ_FOREACH(notify, &g_dpdkInitNotify, tailq) {
        notify->notifyFunc(arg);
    }

    free(arg);
}

void *libstorage_mem_reserve(size_t size, size_t align)
{
    void *buf = rte_malloc(NULL, size, align);
    return buf;
}

void libstorage_mem_free(void *ptr)
{
    rte_free(ptr);
}

void *libstorage_alloc_io_buf(size_t nbytes)
{
    struct spdk_mempool *pool = NULL;
    char *buf = NULL;

    if (spdk_unlikely(!g_bSpdkInitcomplete)) {
        SPDK_ERRLOG("SPDK module didn't initialize completely\n");
        return NULL;
    }

    pool = spdk_bdev_io_get_pool(nbytes);
    if (pool == NULL) {
        return NULL;
    }
    buf = (char *)spdk_mempool_get(pool);
    return buf;
}

int32_t libstorage_free_io_buf(void *buf, size_t nbytes)
{
    struct spdk_mempool *pool = NULL;

    if (spdk_unlikely(buf == NULL)) {
        SPDK_ERRLOG("free io buf is NULL.\n");
        return -1;
    }

    pool = spdk_bdev_io_get_pool(nbytes);
    if (pool == NULL) {
        return -1;
    }
    spdk_mempool_put(pool, buf);
    return 0;
}

int32_t libstorage_io_t_mempool_initialize(void)
{
    uint32_t i = 0;
    LIBSTORAGE_IO_T *io = NULL;
    g_libstorage_io_t_mempool = spdk_mempool_create("libstorage_io_t_pool",
                                                    LIBSTORAGE_IO_T_POOL_SIZE,
                                                    sizeof(LIBSTORAGE_IO_T),
                                                    0,
                                                    SPDK_ENV_SOCKET_ID_ANY);
    if (g_libstorage_io_t_mempool == NULL) {
        SPDK_ERRLOG("Create memory pool failed!\n");
        return -ENOMEM;
    }
    for (i = 0; i < LIBSTORAGE_IO_T_POOL_SIZE; i++) {
        io = spdk_mempool_get(g_libstorage_io_t_mempool);
        if (io == NULL) {
            spdk_mempool_free(g_libstorage_io_t_mempool);
            g_libstorage_io_t_mempool = NULL;
            SPDK_ERRLOG("Create memory failed!\n");
            return -ENOMEM;
        }

        io->count = i;
        g_alloc_io_t[i] = NULL;
        g_io_t_mem_manage[i] = io;
    }

    return 0;
}

void libstorage_io_t_mempool_free(void)
{
    if (g_libstorage_io_t_mempool == NULL) {
        SPDK_ERRLOG("Memory pool have not initialized, no need to free.\n");
        return;
    }

    spdk_mempool_free(g_libstorage_io_t_mempool);
    g_libstorage_io_t_mempool = NULL;
}

static __always_inline void *libstorage_get_io_t(void)
{
    uintptr_t buf;
    int allocIdx;
    int count = 0;
    static libstorage_atomic32_t allocInit = LIBSTORAGE_ATOMIC32_INIT(1);

RETRY:
    allocIdx = libstorage_atomic32_return_inc(&g_alloc_io_t_idx);
    if (allocIdx >= (int)LIBSTORAGE_IO_T_POOL_SIZE) {
        /* Only one thread is allowed to initialize the index to 0 at the same time */
        if (libstorage_atomic32_test_and_set(&allocInit, 1)) {
            libstorage_atomic32_set(&g_alloc_io_t_idx, 0);
        } else if (++count > 100) {
            sched_yield();
            count = 0;
        }
        goto RETRY;
    }

    /* After travelling to end of array, the array index is allowed to be reinitialized to 0 */
    if (spdk_unlikely((allocIdx + 1) == (int)LIBSTORAGE_IO_T_POOL_SIZE)) {
        libstorage_atomic32_cmp_and_swap(&allocInit, 1, 0);
    }

    buf = __sync_lock_test_and_set((uintptr_t*)&g_io_t_mem_manage[allocIdx], 0);
    if (buf == 0) {
        SPDK_NOTICELOG("Conflict with index obtained by other threads, try again.\n");
        goto RETRY;
    }
    return (void*)buf;
}

static inline void libstorage_record_io_t_alloc(const LIBSTORAGE_IO_T *buf)
{
    if (buf->count >= (uint32_t)LIBSTORAGE_IO_T_POOL_SIZE) {
        SPDK_ERRLOG("Invalid io[%p] count[%u].\n", buf, buf->count);
        return;
    }

    if (__sync_bool_compare_and_swap((uintptr_t*)&g_alloc_io_t[buf->count], 0, (uintptr_t)buf)) {
        return;
    }
    if (__sync_bool_compare_and_swap((uintptr_t*)&g_alloc_io_t[buf->count], (uintptr_t)buf, 0)) {
        return;
    }
}

void *libstorage_io_t_alloc_buf(void)
{
    LIBSTORAGE_IO_T *buf = NULL;

    if (spdk_unlikely(!g_bSpdkInitcomplete)) {
        SPDK_ERRLOG("Memory pool have not initialized, cannot allocate buf.\n");
        return NULL;
    }

    /* Don't accept IOs that exceed the maximum number supported by the system */
    if (libstorage_atomic32_inc_return(&g_alloc_io_t_num) > (int)LIBSTORAGE_IO_T_POOL_SIZE) {
        SPDK_NOTICELOG("Too more io, please retry.\n");
        libstorage_atomic32_dec(&g_alloc_io_t_num);
        return NULL;
    }

    buf = libstorage_get_io_t();
    if (buf == NULL) {
        return NULL;
    }

    libstorage_record_io_t_alloc(buf);
    return buf;
}

static __always_inline void libstorage_free_io_t(const LIBSTORAGE_IO_T *buf)
{
    int freeIdx;
    int count = 0;
    static libstorage_atomic32_t freeInit = LIBSTORAGE_ATOMIC32_INIT(1);

RETRY:
    freeIdx = libstorage_atomic32_return_inc(&g_free_io_t_idx);
    if (freeIdx >= (int)LIBSTORAGE_IO_T_POOL_SIZE) {
        /* Only one thread is allowed to initialize the index to 0 at the same time */
        if (libstorage_atomic32_test_and_set(&freeInit, 1)) {
            libstorage_atomic32_set(&g_free_io_t_idx, 0);
        } else if (++count > 100) {
            sched_yield();
            count = 0;
        }
        goto RETRY;
    }

    /* After travelling to end of array, the array index is allowed to be reinitialized to 0 */
    if (spdk_unlikely((freeIdx + 1) == (int)LIBSTORAGE_IO_T_POOL_SIZE)) {
        libstorage_atomic32_cmp_and_swap(&freeInit, 1, 0);
    }

    if (!__sync_bool_compare_and_swap((uintptr_t*)&g_io_t_mem_manage[freeIdx], 0, (uintptr_t)buf)) {
        SPDK_NOTICELOG("The allocation buf[%p] is not fetched, index: %d free buf[%p].\n",
                       g_io_t_mem_manage[freeIdx], freeIdx, buf);
        goto RETRY; /* Hold the freed memory to the next location */
    }
}

void libstorage_io_t_free_buf(LIBSTORAGE_IO_T *buf)
{
    if (spdk_unlikely(!g_bSpdkInitcomplete)) {
        SPDK_ERRLOG("Memory pool have not initialized, cannnot free buf.\n");
        return;
    }

    if (spdk_unlikely(buf == NULL)) {
        SPDK_ERRLOG("Buf is NULL, no need to free.\n");
        return;
    }

    libstorage_record_io_t_alloc(buf);
    libstorage_free_io_t(buf);
    libstorage_atomic32_dec(&g_alloc_io_t_num);
}

static bool libstorage_separate_verify_crc(struct spdk_nvme_ns *ns, const LIBSTORAGE_IO_T *io)
{
    uint32_t i;
    uint32_t lba_count;
    uint32_t md_size;
    uint32_t md_offset = 0;
    uint16_t crc16;
    uint32_t ss;
    struct pi_struct *pi = NULL;

    /* ss is sector size, it will not be zero */
    ss = spdk_nvme_ns_get_sector_size(ns);
    lba_count = io->nbytes / ss;
    md_size = spdk_nvme_ns_get_md_size(ns);

    if (!spdk_nvme_ns_pi_md_start(ns)) {
        md_offset = md_size - PI_SIZE;
    }

    for (i = 0; i < lba_count; i++) {
        crc16 = spdk_crc16_t10dif(0, io->buf + ss * i, ss); /* for separate lba, crc not cover any metadata */
        pi = (struct pi_struct *)(io->md_buf + md_size * i + md_offset);

        if (from_be16(&pi->guard_tag) != crc16) {
            return false;
        }
    }

    return true;
}

static bool libstorage_extended_verify_crc(struct spdk_nvme_ns *ns, const LIBSTORAGE_IO_T *io)
{
    uint32_t i;
    uint32_t lba_count;
    uint32_t md_size;
    uint32_t crc_size;
    uint32_t md_offset = 0;
    uint16_t crc16;
    uint32_t ss;
    uint32_t extLba;
    struct pi_struct *pi = NULL;

    /* ss is sector size, it will not be zero */
    ss = spdk_nvme_ns_get_sector_size(ns);
    lba_count = io->nbytes / ss;
    md_size = spdk_nvme_ns_get_md_size(ns);

    if (!spdk_nvme_ns_pi_md_start(ns)) {
        md_offset = md_size - PI_SIZE;
    }

    /* pi within first, CRC does not cover any metadata bytes;
     * pi within last, CRC cover all metadada excluding last eight bytes
     */
    crc_size = ss + md_offset;
    extLba = ss + md_size;
    for (i = 0; i < lba_count; i++) {
        crc16 = spdk_crc16_t10dif(0, io->buf + extLba * i, crc_size);
        pi = (struct pi_struct *)(io->buf + extLba * i + ss + md_offset);

        if (from_be16(&pi->guard_tag) != crc16) {
            return false;
        }
    }

    return true;
}

bool libstorage_dif_verify_crc(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *io)
{
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;

    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    ns = bdev_nvme_get_ns(nvme_bdev);
    if (spdk_nvme_ns_get_pi_type(ns) <= SPDK_NVME_FMT_NVM_PROTECTION_DISABLE) {
        return true;
    }

    if (spdk_nvme_ns_supports_extended_lba(ns)) {
        return libstorage_extended_verify_crc(ns, io);
    }

    return libstorage_separate_verify_crc(ns, io);
}

static bool libstorage_extended_verify_crc_v(struct spdk_nvme_ns *ns, const LIBSTORAGE_IO_T *iotv)
{
    uint32_t i;
    uint32_t lba_count;
    uint32_t md_size;
    uint32_t crc_size;
    uint32_t md_offset = 0;
    struct iovec *iov = NULL;
    int iovpos;
    uint16_t crc16;
    struct pi_struct *pi = NULL;
    uint32_t ss;
    uint32_t extLba;

    /* ss is sector size, it will not be zero */
    ss = spdk_nvme_ns_get_sector_size(ns);
    md_size = spdk_nvme_ns_get_md_size(ns);
    if (!spdk_nvme_ns_pi_md_start(ns)) {
        md_offset = md_size - PI_SIZE;
    }

    /* pi within first, CRC does not cover any metadata bytes;
     * pi within last, CRC cover all metadada excluding last eight bytes
     */
    crc_size = ss + md_offset;
    extLba = ss + md_size;
    for (iovpos = 0; iovpos < iotv->iovcnt; iovpos++) {
        iov = &iotv->iovs[iovpos];
        lba_count = iov->iov_len / extLba;
        for (i = 0; i < lba_count; i++) {
            crc16 = spdk_crc16_t10dif(0, (uint8_t *)(iov->iov_base) + extLba * i, crc_size);
            pi = (struct pi_struct *)((uint8_t *)(iov->iov_base) + extLba * i + ss + md_offset);

            if (from_be16(&pi->guard_tag) != crc16) {
                return false;
            }
        }
    }

    return true;
}

bool libstorage_dif_verify_crc_v(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *iotv)
{
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;

    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    ns = bdev_nvme_get_ns(nvme_bdev);
    if (spdk_nvme_ns_get_pi_type(ns) <= SPDK_NVME_FMT_NVM_PROTECTION_DISABLE) {
        return true;
    }

    if (!spdk_nvme_ns_supports_extended_lba(ns)) {
        SPDK_ERRLOG("SGL transfer not support separate meta data mode!\n");
        return false;
    }

    return libstorage_extended_verify_crc_v(ns, iotv);
}

static int32_t libstorage_extended_generate_crc(struct spdk_nvme_ns *ns, const LIBSTORAGE_IO_T *pio)
{
    uint64_t lba;
    uint32_t i;
    uint32_t lba_count;
    uint32_t md_size;
    uint32_t crc_size;
    uint32_t md_offset = 0;
    uint16_t crc16;
    uint32_t ss;
    uint32_t extLba;
    struct pi_struct *pi = NULL;

    /* ss is sector size, it will not be zero */
    ss = spdk_nvme_ns_get_sector_size(ns);
    lba = pio->offset / ss;
    lba_count = pio->nbytes / ss;
    md_size = spdk_nvme_ns_get_md_size(ns);

    if (!spdk_nvme_ns_pi_md_start(ns)) {
        md_offset = md_size - PI_SIZE;
    }

    /* pi within first, CRC does not cover any metadata bytes;
     * pi within last, CRC cover all metadada excluding last eight bytes
     */
    crc_size = ss + md_offset;
    extLba = ss + md_size;
    for (i = 0; i < lba_count; i++) {
        crc16 = spdk_crc16_t10dif(0, pio->buf + extLba * i, crc_size);
        pi = (struct pi_struct *)(pio->buf + extLba * i + ss + md_offset);

        to_be16(&pi->guard_tag, crc16);
        to_be32(&pi->ref_tag, (uint32_t)(lba + i));
        pi->app_tag = 0;
    }

    return 0;
}

static int32_t libstorage_separate_generate_crc(struct spdk_nvme_ns *ns, const LIBSTORAGE_IO_T *pio)
{
    uint64_t lba;
    uint32_t i;
    uint32_t lba_count;
    uint32_t md_size;
    uint32_t md_offset = 0;
    uint16_t crc16;
    uint32_t ss;
    struct pi_struct *pi = NULL;

    /* ss is sector size, it will not be zero */
    ss = spdk_nvme_ns_get_sector_size(ns);
    lba = pio->offset / ss;
    lba_count = pio->nbytes / ss;
    md_size = spdk_nvme_ns_get_md_size(ns);

    if (!spdk_nvme_ns_pi_md_start(ns)) {
        md_offset = md_size - PI_SIZE;
    }

    if ((pio->md_buf == NULL) || (pio->md_len != md_size * lba_count)) {
        return -EINVAL;
    }

    for (i = 0; i < lba_count; i++) {
        crc16 = spdk_crc16_t10dif(0, pio->buf + ss * i, ss); /* for separate lba, crc not cover any metadata */
        pi = (struct pi_struct *)(pio->md_buf + md_size * i + md_offset);

        to_be16(&pi->guard_tag, crc16);
        to_be32(&pi->ref_tag, (uint32_t)(lba + i));
        pi->app_tag = 0;
    }

    return 0;
}

int32_t libstorage_dif_generate(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *pio)
{
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;

    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    ns = bdev_nvme_get_ns(nvme_bdev);
    if (spdk_nvme_ns_supports_extended_lba(ns)) {
        return libstorage_extended_generate_crc(ns, pio);
    }

    return libstorage_separate_generate_crc(ns, pio);
}

static int32_t libstorage_extended_generate_crc_v(struct spdk_nvme_ns *ns, const LIBSTORAGE_IO_T *piov)
{
    uint64_t lba;
    uint32_t i;
    uint32_t lba_count;
    uint32_t md_size;
    uint32_t crc_size;
    uint32_t md_offset = 0;
    struct iovec *iov = NULL;
    int iovpos;
    uint16_t crc16;
    uint32_t ss;
    struct pi_struct *pi = NULL;

    /* ss is sector size, it will not be zero */
    ss = spdk_nvme_ns_get_sector_size(ns);
    lba = piov->offset / ss;
    md_size = spdk_nvme_ns_get_md_size(ns);

    if (!spdk_nvme_ns_pi_md_start(ns)) {
        md_offset = md_size - PI_SIZE;
    }

    /* pi within first, CRC does not cover any metadata bytes;
     * pi within last, CRC cover all metadada excluding last eight bytes
     */
    crc_size = ss + md_offset;

    for (iovpos = 0; iovpos < piov->iovcnt; iovpos++) {
        iov = &piov->iovs[iovpos];
        if (iov->iov_len % (ss + md_size)) {
            SPDK_ERRLOG("Unaligned SGL iov_len in iovs[%d]!\n", iovpos);
            return -EINVAL;
        }

        lba_count = iov->iov_len / (ss + md_size);
        for (i = 0; i < lba_count; i++) {
            crc16 = spdk_crc16_t10dif(0, (uint8_t *)(iov->iov_base) + (ss + md_size) * i, crc_size);
            pi = (struct pi_struct *)((uint8_t *)(iov->iov_base) + (ss + md_size) * i + ss + md_offset);

            to_be16(&pi->guard_tag, crc16);
            to_be32(&pi->ref_tag, (uint32_t)(lba + i));
            pi->app_tag = 0;
        }
    }

    return 0;
}

int32_t libstorage_dif_generate_v(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *piov)
{
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;

    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    ns = bdev_nvme_get_ns(nvme_bdev);
    if (!spdk_nvme_ns_supports_extended_lba(ns)) {
        SPDK_ERRLOG("SGL transfer not support separate meta data mode!\n");
        return -EINVAL;
    }

    return libstorage_extended_generate_crc_v(ns, piov);
}

int32_t libstorage_open_shm_set_size(const char *shm_name, off_t length, bool *is_create)
{
    int shm_fd;

    /* open share memory */
    shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600); // 0600 is RW authority only for root.
    if (shm_fd < 0) {
        if (errno != EEXIST) {
            SPDK_ERRLOG("Create share memory failed[errno=%s].\n", strerror(errno));
            return -1;
        }

        shm_fd = shm_open(shm_name, O_RDWR, 0600); // 0600 is RW authority only for root.
        if (shm_fd < 0) {
            SPDK_ERRLOG("Share memory is already exist, open failed[errno=%s].\n", strerror(errno));
            return -1;
        }

        if (ftruncate(shm_fd, length) == -1) {
            SPDK_ERRLOG("Ftruncate share memory failed[errno=%s].\n", strerror(errno));
            *is_create = false;
            close(shm_fd);
            (void)shm_unlink(shm_name);
            return -1;
        }

        *is_create = false;
        return shm_fd;
    }

    /* specify the size of share memory */
    if (ftruncate(shm_fd, length) == -1) {
        SPDK_ERRLOG("Ftruncate share memory failed[errno=%s].\n", strerror(errno));
        close(shm_fd);
        (void)shm_unlink(shm_name);
        return -1;
    }

    *is_create = true;
    return shm_fd;
}

struct spdk_nvme_ns *libstorage_get_ns_by_devname(const char *devname)
{
    struct spdk_bdev *bdev = NULL;

    bdev = spdk_bdev_get_by_name(devname);
    if (bdev == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] cannot get bdev %s\n", devname);
        return NULL;
    }

    return bdev_nvme_get_ns(bdev->ctxt);
}

static __always_inline int LibstorageRwCheckPara(const LIBSTORAGE_DEVICE_FD_T *devfd, const LIBSTORAGE_IO_T *io)
{
    struct spdk_bdev *bdev = NULL;
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;

    bdev = spdk_bdev_desc_get_bdev(devfd->bdev_desc);
    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    if (spdk_unlikely(io->nbytes % bdev->blocklen != 0 || io->offset % bdev->blocklen != 0)) {
        SPDK_ERRLOG("Unaligned IO request length[%u] or offset[%lu]!\n", io->nbytes, io->offset);
        return -EINVAL;
    }

    ns = bdev_nvme_get_ns(nvme_bdev);
    if (io->md_buf != NULL && spdk_nvme_ns_supports_extended_lba(ns)) {
        SPDK_ERRLOG("Not support separate meta data mode!\n");
        return -EINVAL;
    }

    if (spdk_nvme_ns_ctrl_is_failed(ns)) {
        return -ENODEV;
    }

    return 0;
}

int LibstorageDeallocateNvme(const LIBSTORAGE_DEVICE_FD_T *devfd, LIBSTORAGE_IO_T *io, spdk_bdev_io_completion_cb cb)
{
    struct spdk_bdev *bdev = NULL;
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;

    bdev = spdk_bdev_desc_get_bdev(devfd->bdev_desc);
    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    ns = bdev_nvme_get_ns(nvme_bdev);
    if (!spdk_nvme_ns_is_dataset_mng_supported(ns)) {
        SPDK_ERRLOG("%s does not support deallocate command on namespace base.\n", bdev->name);
        return -EPERM;
    }

    return spdk_bdev_unmap_multiblocks(devfd->bdev_desc, devfd->channel, io->md_buf,
                                       io->md_len, cb, &io->location);
}

static __always_inline int LibstorageGenerateDif(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *io)
{
    if (((io->pi_action & 0x03) == (uint8_t)IO_E2E_PROTECTION) && (io->pi_action & (uint8_t)FLAG_CALCRC)) {
        if (io->opcode == (uint16_t)OP_WRITE) {
            return libstorage_dif_generate(bdev, io);
        }

        return libstorage_dif_generate_v(bdev, io);
    }

    return 0;
}

int LibstorageLaunchIoToNvme(const LIBSTORAGE_DEVICE_FD_T *devfd, LIBSTORAGE_IO_T *io, spdk_bdev_io_completion_cb cb)
{
    int32_t err;
    struct spdk_bdev_desc *bdev_desc = devfd->bdev_desc;
    struct spdk_bdev *bdev = spdk_bdev_desc_get_bdev(bdev_desc);
    struct nvme_bdev *nvme_bdev = NULL;
    struct spdk_nvme_ns *ns = NULL;
    uint64_t offset_blocks = io->offset / bdev->blocklen;
    uint64_t num_blocks = io->nbytes / bdev->blocklen;

    err = LibstorageRwCheckPara(devfd, io);
    if (err != 0) {
        return err;
    }

    bdev = spdk_bdev_desc_get_bdev(bdev_desc);
    nvme_bdev = (struct nvme_bdev *)bdev->ctxt;
    ns = bdev_nvme_get_ns(nvme_bdev);
    if (spdk_nvme_ns_get_pi_type(ns) != SPDK_NVME_FMT_NVM_PROTECTION_DISABLE) {
        io->pi_action |= g_ucE2EDif;
    }

    if (io->opcode == (uint16_t)OP_READ) {
        err = spdk_bdev_read_blocks_with_md(bdev_desc, devfd->channel, io->buf, io->md_buf,
                                            offset_blocks, num_blocks, cb, io);
    } else if (io->opcode == (uint16_t)OP_READV) {
        err = spdk_bdev_readv_blocks_with_md(bdev_desc, devfd->channel, io->iovs, io->iovcnt, NULL,
                                             offset_blocks, num_blocks, cb, io);
    } else if (io->opcode == (uint16_t)OP_WRITE) {
        /* filter io->pi_action to get pi action and cal crc flag */
        err = LibstorageGenerateDif(bdev, io);
        if (spdk_unlikely(err)) {
            SPDK_ERRLOG("%s failed to generate dif. err: %d\n", bdev->name, err);
            return err;
        }

        err = spdk_bdev_write_blocks_with_md(bdev_desc, devfd->channel, io->buf, io->md_buf,
                                             offset_blocks, num_blocks, cb, io);
    } else if (io->opcode == (uint16_t)OP_WRITEV) {
        /* filter io->pi_action to get pi action and cal crc flag */
        err = LibstorageGenerateDif(bdev, io);
        if (spdk_unlikely(err)) {
            SPDK_ERRLOG("%s failed to generate dif in async process. err: %d\n", bdev->name, err);
            return err;
        }

        err = spdk_bdev_writev_blocks_with_md(bdev_desc, devfd->channel, io->iovs, io->iovcnt,
                                              NULL, offset_blocks, num_blocks, cb, io);
    }

    return err;
}

int build_socket_cmd(char *cmd_str, size_t size, const char *socket_mem,
                     const char *socket_limit)
{
    int rc;

    if (socket_mem == NULL) {
        SPDK_NOTICELOG("SocketMem was empty!\n");
        return 0;
    }

    if (socket_limit != NULL) {
        rc = sprintf_s(cmd_str, size, "--socket-mem=%s --socket-limit=%s",
                       socket_mem, socket_limit);
    } else {
        rc = sprintf_s(cmd_str, size, "--socket-mem=%s",
                       socket_mem);
    }

    if (rc < 0) {
        SPDK_ERRLOG("Failed to parse socket parameter!\n");
    }
    return rc;
}

int32_t libstorage_get_print_level_from_conf(struct spdk_conf_section *sp)
{
    int32_t print_level;

    print_level = spdk_conf_section_get_intval(sp, "LogLevel");
    if (print_level < (int32_t)SPDK_LOG_ERROR || print_level > (int32_t)SPDK_LOG_DEBUG) {
        print_level = (int32_t)SPDK_LOG_WARN;
    }

    return print_level;
}

void libstorage_get_dif_from_conf(struct spdk_conf_section *sp)
{
    g_ucE2EDif = spdk_conf_section_get_intval(sp, "E2eDif");
    if (g_ucE2EDif != (uint8_t)IO_E2E_PROTECTION && g_ucE2EDif != (uint8_t)IO_HALF_WAY_PROTECTION) {
        g_ucE2EDif = (uint8_t)IO_E2E_PROTECTION;
    }
    openlog("LibStorage", LOG_ODELAY | LOG_PID, LOG_LOCAL7);
    syslog(LOG_INFO, "E2eDif is set to %u\n", g_ucE2EDif);
    closelog();
}

int32_t libstorage_init_global_conf(const char *cfgfile)
{
    struct spdk_conf *config = NULL;
    int32_t ret;

    config = spdk_conf_allocate();
    if (config == NULL) {
        SPDK_ERRLOG("allocate config failed\n");
        return -1;
    }

    ret = spdk_conf_read(config, cfgfile);
    if (ret != 0) {
        SPDK_ERRLOG("Could not read config file %s, ret: %d.\n", cfgfile, ret);
        spdk_conf_free(config);
        return ret;
    }
    if (spdk_conf_first_section(config) == NULL) {
        SPDK_ERRLOG("Invalid config file %s\n", cfgfile);
        spdk_conf_free(config);
        return -1;
    }

    g_libstorage_config = config;
    spdk_conf_set_as_default(g_libstorage_config);

    return 0;
}

int32_t libstorage_parse_conf_item(const char *cfgfile)
{
    struct spdk_conf_section *sp = NULL;
    int32_t print_level;
    int32_t ret;

    if (cfgfile == NULL) {
        SPDK_ERRLOG("config file is NULL\n");
        return -1;
    }

    ret = libstorage_init_global_conf(cfgfile);
    if (ret != 0) {
        SPDK_ERRLOG("Read config file failed, ret: %d\n", ret);
        return ret;
    }

    sp = spdk_conf_find_section(g_libstorage_config, "Global");
    if (sp == NULL) {
        SPDK_ERRLOG("Cannot find \"Global\" section in %s\n", cfgfile);
        return -1;
    }

    print_level = libstorage_get_print_level_from_conf(sp);
    spdk_log_set_print_level((enum spdk_log_level)print_level);
    spdk_log_set_level((enum spdk_log_level)print_level);
    spdk_log_open(NULL);

    libstorage_get_dif_from_conf(sp);

    /* get config from conf file, decide whether to start rpc server or not */
    g_bRpcServer = spdk_conf_section_get_boolval(sp, "RpcServer", false);
    g_useCUSE = spdk_conf_section_get_boolval(sp, "NvmeCUSE", true);
    g_reserve_total_memory = spdk_conf_section_get_intval(sp, "ReserveHugePage");
    g_reserve_total_memory = g_reserve_total_memory * MB;
    if (g_reserve_total_memory > RESERVE_TOTAL_MEMORY || g_reserve_total_memory < 0) {
        g_reserve_total_memory = RESERVE_TOTAL_MEMORY;
    }
    if (g_reserve_total_memory < RESERVE_MIN_MEMORY) {
        g_reserve_total_memory = RESERVE_MIN_MEMORY;
    }
    return 0;
}

int32_t libstorage_get_nvme_from_conf(const char *cfgfile,
                                      struct libstorage_nvme_config *p_nvmes_config, int32_t config_nvme_num)
{
    struct spdk_conf *config = NULL;
    struct spdk_conf_section *sp = NULL;
    struct libstorage_nvme_config nvme_config;
    int32_t i = 0;
    int32_t ret;

    if (p_nvmes_config == NULL || cfgfile == NULL) {
        return -EINVAL;
    }

    config = spdk_conf_allocate();
    if (config == NULL) {
        printf("failed to alloc memory for config file\n");
        return -ENOMEM;
    }

    ret = spdk_conf_read(config, cfgfile);
    if (ret != 0) {
        SPDK_ERRLOG("Could not read config file %s\n", cfgfile);
        goto exit_and_free_config;
    }

    sp = spdk_conf_find_section(config, "Nvme");
    if (sp == NULL) {
        SPDK_ERRLOG("Could not find Nvme section\n");
        ret = -EINVAL;
        goto exit_and_free_config;
    }

    /* get nvme config info */
    for (i = 0; i < LIBSTORAGE_LOAD_MAX_CONTROLLERS; i++) {
        ret = libstorage_get_one_nvme_from_conf(sp, i, &nvme_config);
        if (ret < 0) {
            SPDK_ERRLOG("Get nvme config failed\n");
            goto exit_and_free_config;
        }

        if (ret == LIBSTORAGE_LOAD_FINISH) {
            break;
        }

        ret = libstorage_update_nvme_conf(p_nvmes_config, config_nvme_num, &nvme_config);
        if (ret == LIBSTORAGE_LOAD_NEW) {
            ret = libstorage_insert_nvme_conf(p_nvmes_config, &config_nvme_num, &nvme_config);
            if (ret != 0) {
                SPDK_ERRLOG("Insert config with %s-%s failed\n", nvme_config.ctrlName, nvme_config.pciAddr);
                goto exit_and_free_config;
            }
        }
    }

    ret = config_nvme_num;

exit_and_free_config:
    spdk_conf_free(config);
    return ret;
}

int32_t libstorage_get_one_nvme_from_conf(struct spdk_conf_section *sp,
                                          int32_t index, struct libstorage_nvme_config *nvme_config)
{
    const char *val = NULL;
    int32_t ret;
    struct spdk_nvme_transport_id trid = {0};

    val = spdk_conf_section_get_nmval(sp, "TransportID", index, 0);
    if (val == NULL) {
        return LIBSTORAGE_LOAD_FINISH;
    }

    ret = spdk_nvme_transport_id_parse(&trid, val);
    if (ret < 0) {
        SPDK_ERRLOG("Unable to parse TransportID: %s\n", val);
        return ret;
    }

    if (trid.trtype != SPDK_NVME_TRANSPORT_PCIE) {
        SPDK_ERRLOG("Only support PCIE type\n");
        return -EINVAL;
    }

    if (strlen(trid.traddr) > sizeof(nvme_config->pciAddr) - 1) {
        SPDK_ERRLOG("Pci address is too long\n");
        return -EINVAL;
    }

    ret = strcpy_s(nvme_config->pciAddr, sizeof(nvme_config->pciAddr), trid.traddr);
    if (ret != 0) {
        SPDK_ERRLOG("Copy pci address from config file failed\n");
        return -EINVAL;
    }

    val = spdk_conf_section_get_nmval(sp, "TransportID", index, 1);
    if (val == NULL) {
        SPDK_ERRLOG("No name provided for TransportID\n");
        return -EINVAL;
    }
    if (strlen(val) > sizeof(nvme_config->ctrlName) - 1) {
        SPDK_ERRLOG("Name %s is too long\n", val);
        return -EINVAL;
    }

    ret = strcpy_s(nvme_config->ctrlName, sizeof(nvme_config->ctrlName), val);
    if (ret != 0) {
        SPDK_ERRLOG("Copy controller name from config file failed\n");
        return -EINVAL;
    }

    return LIBSTORAGE_LOAD_SUCCESS;
}

int32_t libstorage_update_nvme_conf(struct libstorage_nvme_config *p_nvmes_config, int32_t config_nvme_num,
                                    const struct libstorage_nvme_config *nvme_config)
{
    int32_t i;

    for (i = 0; i < config_nvme_num; i++) {
        if (strcmp(p_nvmes_config[i].pciAddr, nvme_config->pciAddr) != 0) {
            continue;
        }

        if (strcmp(p_nvmes_config[i].ctrlName, nvme_config->ctrlName) != 0) {
            /* no return errno */
            SPDK_ERRLOG("Name for %s changes, original name is %s, new name is %s\n",
                        p_nvmes_config[i].pciAddr, nvme_config->ctrlName, p_nvmes_config[i].ctrlName);
        }

        p_nvmes_config[i].state = RELOAD_REMAIN;
        return 0;
    }

    return LIBSTORAGE_LOAD_NEW;
}

int32_t libstorage_insert_nvme_conf(struct libstorage_nvme_config *p_nvmes_config, int32_t *config_nvme_tail,
                                    const struct libstorage_nvme_config *nvme_config)
{
    int32_t ret;

    if (*config_nvme_tail >= LIBSTORAGE_CONFIG_MAX_CONTROLLERS) {
        return -EINVAL;
    }

    ret = strcpy_s(p_nvmes_config[*config_nvme_tail].ctrlName,
                   sizeof(p_nvmes_config[*config_nvme_tail].ctrlName), nvme_config->ctrlName);
    if (ret != 0) {
        SPDK_ERRLOG("Copy controller name from insert nvme config failed\n");
        return ret;
    }

    ret = strcpy_s(p_nvmes_config[*config_nvme_tail].pciAddr,
                   sizeof(p_nvmes_config[*config_nvme_tail].pciAddr), nvme_config->pciAddr);
    if (ret != 0) {
        SPDK_ERRLOG("Copy controller pci from insert nvme config failed\n");
        return ret;
    }

    p_nvmes_config[*config_nvme_tail].state = RELOAD_CREATE;
    (*config_nvme_tail)++;
    return ret;
}

int32_t libstorage_init_nvme_conf(struct libstorage_nvme_config *p_nvmes_config, size_t nvmes_config_size)
{
    int32_t num_ctrlr;
    int32_t i = 0;
    int32_t ret = 0;
    struct nvme_ctrlr_info *ctrlr_info = NULL;

    if (p_nvmes_config == NULL) {
        return -EINVAL;
    }

    num_ctrlr = nvme_ctrlr_get_info(NULL, &ctrlr_info);
    if (num_ctrlr < 0) {
        SPDK_ERRLOG("Failed to get controller info\n");
        return num_ctrlr;
    } else if (num_ctrlr > (int32_t)nvmes_config_size) {
        SPDK_ERRLOG("Loaded controller number %d is greater than %lu\n", num_ctrlr, nvmes_config_size);
        ret = -EINVAL;
        goto exit_and_free_ctrlrs;
    }

    for (i = 0; i < num_ctrlr; i++) {
        p_nvmes_config[i].state = RELOAD_DELETE;
        ret = strcpy_s(p_nvmes_config[i].ctrlName, sizeof(p_nvmes_config[i].ctrlName), ctrlr_info[i].ctrlName);
        if (ret != 0) {
            SPDK_ERRLOG("Copy loaded controller name failed\n");
            goto exit_and_free_ctrlrs;
        }
        ret = strcpy_s(p_nvmes_config[i].pciAddr, sizeof(p_nvmes_config[i].pciAddr), ctrlr_info[i].pciAddr);
        if (ret != 0) {
            SPDK_ERRLOG("Copy loaded controller pci address failed\n");
            goto exit_and_free_ctrlrs;
        }
    }
    ret = num_ctrlr;

exit_and_free_ctrlrs:
    if (ctrlr_info != NULL) {
        free(ctrlr_info);
    }
    return ret;
}

