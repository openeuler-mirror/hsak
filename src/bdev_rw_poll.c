/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: LibStorage read and write API in polling mode.
 * Author: xiehuiming@huawei.com
 * Create: 2018-09-01
 */

#include "spdk/thread.h"
#include "spdk_internal/thread.h"
#include "bdev_rw_internal.h"
#ifdef SPDK_CONFIG_ERR_INJC
#include "bdev_rw_err_injc.h"
#endif

/* The maximum number of block devices per server */
#define MAX_BDEVS_PER_SERVER 512
/* The minimum memory size of huge page */
#define MINIMUM_MEMORY_SIZE_WITH_REACTOR_M 300

struct dev_thread_info_S {
    char bdevName[MAX_BDEV_NAME_LEN];
    uint8_t lcore_devnum[RTE_MAX_LCORE];
};

static LibstorageDevFdListHead g_devfd_list = SLIST_HEAD_INITIALIZER(g_devfd_list);
static pthread_mutex_t g_devfd_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_thread_info_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Protected by g_thread_info_mutex */
static struct dev_thread_info_S g_dev_thread_info[MAX_BDEVS_PER_SERVER];
/* Count of devices in dev_thread_info. Protected by g_thread_info_mutex */
static int32_t g_devInfoSize = 0;

static uint8_t *LibstorageGetThreadBdevNum(const char *bdevName)
{
    uint8_t *pDevNum = NULL;
    uint8_t i;

    for (i = 0; i < g_devInfoSize; i++) {
        if (strcmp(g_dev_thread_info[i].bdevName, bdevName) == 0) {
            pDevNum = g_dev_thread_info[i].lcore_devnum;
            break;
        }
    }

    return pDevNum;
}

static uint8_t *LibstorageGetAddThreadBdevNum(const char *bdevName)
{
    uint8_t *pDevNum = NULL;
    size_t nameLen;

    nameLen = strlen(bdevName);
    if (nameLen >= MAX_BDEV_NAME_LEN) {
        SPDK_ERRLOG("Invalid device name: %s.\n", bdevName);
        return NULL;
    }

    pDevNum = LibstorageGetThreadBdevNum(bdevName);
    if (pDevNum == NULL) {
        if (g_devInfoSize >= MAX_BDEVS_PER_SERVER) {
            SPDK_ERRLOG("Number of devices exceeded expectations\n");
            return NULL;
        }

        if (strcpy_s(g_dev_thread_info[g_devInfoSize].bdevName, MAX_BDEV_NAME_LEN, bdevName) != 0) {
            SPDK_ERRLOG("strcpy failed\n");
            return NULL;
        }
        pDevNum = g_dev_thread_info[g_devInfoSize].lcore_devnum;
        g_devInfoSize++;
    }

    return pDevNum;
}

static int32_t LibstorageGetNodevCore(const uint8_t *pDevNum, uint8_t *minLcore, uint32_t *firstCore)
{
    int32_t minLcoreSize = 0;
    uint32_t lcore = RTE_MAX_LCORE;
    uint32_t curCore = RTE_MAX_LCORE;

    SPDK_ENV_FOREACH_CORE(lcore) {
        if (lcore_thread_info[lcore].state == (int32_t)SPDK_THREAD_STATE_RUNNING) {
            /* Find the first running thread.
             * If the appropriate thread is not found, it is placed on the first running thread.
             */
            if (curCore == RTE_MAX_LCORE) {
                curCore = lcore;
            }

            /* Find the list of cores that no any this controller runs on. */
            if (pDevNum[lcore] == 0) {
                minLcore[minLcoreSize] = lcore;
                minLcoreSize++;
            }
        }
    }

    if (spdk_unlikely(curCore == RTE_MAX_LCORE)) {
        return -1;
    }

    *firstCore = curCore;
    return minLcoreSize;
}

static struct spdk_thread *LibstorageGetBdevThread(const char *bdevName)
{
    uint8_t *pDevNum = NULL;
    struct spdk_thread *thread = NULL;
    uint32_t lcore = RTE_MAX_LCORE;
    uint32_t curCore = RTE_MAX_LCORE;
    uint8_t minLcore[RTE_MAX_LCORE] = {0};
    int32_t minLcoreSize;
    uint8_t i;

    (void)pthread_mutex_lock(&g_thread_info_mutex);
    pDevNum = LibstorageGetAddThreadBdevNum(bdevName);
    if (pDevNum == NULL) {
        (void)pthread_mutex_unlock(&g_thread_info_mutex);
        return NULL;
    }

    minLcoreSize = LibstorageGetNodevCore(pDevNum, minLcore, &curCore);
    if (minLcoreSize < 0) {
        (void)pthread_mutex_unlock(&g_thread_info_mutex);
        return NULL;
    }

    /* If the same block device is already on all threads,
     * put it on a thread with the least number of block devices.
     */
    if (minLcoreSize == 0) {
        SPDK_ENV_FOREACH_CORE(lcore) {
            if (lcore_thread_info[lcore].state == (int32_t)SPDK_THREAD_STATE_RUNNING &&
                lcore_thread_info[lcore].bdevnum < lcore_thread_info[curCore].bdevnum) {
                curCore = lcore;
            }
        }
        goto EXIT;
    }

    /* Find a thread with the minimum number of block devics from the list of cores
     * that the minimum number of this block devices runs on.
     */
    curCore = minLcore[0];
    for (i = 1; i < minLcoreSize; i++) {
        lcore = minLcore[i];
        if (lcore_thread_info[lcore].bdevnum < lcore_thread_info[curCore].bdevnum) {
            curCore = lcore;
        }
    }

EXIT:
    thread = lcore_thread_info[curCore].thread;
    lcore_thread_info[curCore].bdevnum += 1;
    pDevNum[curCore]++;
    (void)pthread_mutex_unlock(&g_thread_info_mutex);

    return thread;
}

static void LibstoragePutBdevThread(const struct spdk_thread *thread, const char *bdevName)
{
    uint32_t lcore = 0;
    uint8_t *pDevNum = NULL;

    (void)pthread_mutex_lock(&g_thread_info_mutex);
    pDevNum = LibstorageGetThreadBdevNum(bdevName);

    SPDK_ENV_FOREACH_CORE(lcore) {
        if (lcore_thread_info[lcore].thread == thread) {
            if (lcore_thread_info[lcore].bdevnum != 0) {
                lcore_thread_info[lcore].bdevnum -= 1;
            }

            if (pDevNum != NULL && pDevNum[lcore] > 0) {
                pDevNum[lcore]--;
            }

            break;
        }
    }
    (void)pthread_mutex_unlock(&g_thread_info_mutex);
}

static void LibstorageCloseDiskEventCb(void *cb_arg)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = (LIBSTORAGE_DEVICE_FD_T *)cb_arg;
    struct spdk_bdev_desc *bdev_desc = NULL;
    bool *done = NULL;

    if (devfd != NULL) {
        /* Release devfd resources After IO thread confirms */
        bdev_desc = devfd->bdev_desc;
        done = (bool *)devfd->data;

        /* NVMe resources are released when the module exits */
        spdk_bdev_close(bdev_desc);

        if (done != NULL) {
            *done = true;
        }
    }
}

static void LibstorageCloseDisk(LIBSTORAGE_DEVICE_FD_T *devfd)
{
    struct spdk_thread *thread = NULL;
    volatile bool done = false;

    thread = devfd->thread;

    if (thread != NULL) {
        devfd->data = (void *)&done;

        /* Notify IO thread to close disk */
        spdk_thread_send_msg(thread, LibstorageCloseDiskEventCb, devfd);

        while (!done) {
            /* do nothing; */
        }

        devfd->data = NULL;
        return;
    }
}

static void LibstoragePollReleaseDevResource(LIBSTORAGE_DEVICE_FD_T *devfd)
{
    uint32_t channel_ref;
    while (spdk_bdev_have_io_in_channel(devfd->channel)) { /* do nothing, Wait for all IO on the channel to end */ }

    spdk_set_thread(devfd->thread);
    channel_ref = spdk_get_channel_ref(devfd->channel);
    spdk_put_io_channel(devfd->channel);
    LibstoragePutBdevThread(devfd->thread, devfd->devname);

    if (channel_ref == 1) {
        /* When io channel ref is 1, we need wait for all resource to release done. */
        while (spdk_bdev_get_channel_state(devfd->channel) != 1) {}
    }

    LibstorageCloseDisk(devfd);
    devfd->fd = -1;
    devfd->bdev_desc = NULL;
    devfd->thread = NULL;
    devfd->channel = NULL;
    devfd->disktype = (int32_t)INVALID_DISK;
    devfd->data = NULL;
    devfd->ctrlr = NULL;
#ifdef SPDK_CONFIG_ERR_INJC
    /* this function will need devfd->devname, so call it before free it. */
    (void)libstorage_err_injc_destory(devfd->devname);
#endif
    spdk_mb();
    devfd->ref = (int32_t)DISK_REUSE;
}

static void LibstoragePollDiskRemove(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *remove_ctx)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    LIBSTORAGE_DEVICE_FD_T *tmpDevfd = NULL;
    int32_t fd = (intptr_t)remove_ctx;

    /* Need to lock avoid conflicts with open/close operation */
    (void)pthread_mutex_lock(&g_devfd_mutex);

    devfd = LibstorageFindDevfd(&g_devfd_list, fd);
    if (devfd == NULL) {
        pthread_mutex_unlock(&g_devfd_mutex);
        return;
    }

    if (devfd->ref != (int32_t)DISK_DELETE) {
        /* Maybe concurrent with LibstorageGetFdThread, but does not affect */
        devfd->ref = (int32_t)DISK_DELETE;

        /* All devices under the same controller are marked for deletion */
        SLIST_FOREACH(tmpDevfd, &g_devfd_list, slist) {
            if (tmpDevfd->ctrlr == devfd->ctrlr) {
                tmpDevfd->ref = (int32_t)DISK_DELETE;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_devfd_mutex);
    LibstoragePollReleaseDevResource(devfd);
}

/* Notice: Called after all IO threads have exited */
void LibstoragePollExitCheckResource(void)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    struct spdk_bdev_desc *bdev_desc = NULL;
    struct spdk_bdev *bdev = NULL;

    (void)pthread_mutex_lock(&g_devfd_mutex);
    while (!SLIST_EMPTY(&g_devfd_list)) {
        devfd = (LIBSTORAGE_DEVICE_FD_T *)SLIST_FIRST(&g_devfd_list);
        SLIST_REMOVE_HEAD(&g_devfd_list, slist);

        if (devfd->ref == (int32_t)DISK_REUSE) {
            free(devfd);
            continue;
        }

        /* Processed by hot-plug process */
        if (devfd->ref <= (int32_t)DISK_DELETE) {
            devfd->ref = (int32_t)DISK_RELEASE;
            continue;
        }
        (void)pthread_mutex_unlock(&g_devfd_mutex);

        LibstoragePutBdevThread(devfd->thread, devfd->devname);
        spdk_set_thread(devfd->thread);
        if (devfd->channel != NULL) {
            spdk_put_io_channel(devfd->channel);
        }

        bdev_desc = devfd->bdev_desc;
        if (bdev_desc != NULL) {
            bdev = spdk_bdev_desc_get_bdev(bdev_desc);

            (void)pthread_mutex_lock(&bdev->internal.mutex);
            bdev->internal.status = SPDK_BDEV_STATUS_REMOVING;
            (void)pthread_mutex_unlock(&bdev->internal.mutex);

            /* NVMe resources are released when the module exits */
            spdk_bdev_close(bdev_desc);
        }
#ifdef SPDK_CONFIG_ERR_INJC
        /* this function will need devfd->devname, so call it before free devfd->devname */
        (void)libstorage_err_injc_destory(devfd->devname);
#endif
        free(devfd);
        devfd = NULL;
        (void)pthread_mutex_lock(&g_devfd_mutex);
    }
    (void)pthread_mutex_unlock(&g_devfd_mutex);
    spdk_set_thread(g_masterThread);
    return;
}

static void LibstorageGetIoChannelCb(void *ctx)
{
    if (ctx == NULL) {
        SPDK_ERRLOG("Can't get ctx when get channel\n");
        return;
    }

    LIBSTORAGE_DEVICE_FD_T *devfd = (LIBSTORAGE_DEVICE_FD_T *)ctx;
    bool *done = (bool *)devfd->data;

    if (devfd->bdev_desc != NULL) {
        devfd->channel = spdk_bdev_get_io_channel(devfd->bdev_desc);
        if (devfd->channel == NULL) {
            SPDK_ERRLOG("Failed to get io channel\n");
        }
    } else {
        SPDK_ERRLOG("Can't get desc when get channel\n");
    }

    spdk_wmb();

    if (done != NULL) {
        *done = true;
    }
}

static int32_t LibstorageGetBdevIoChannel(LIBSTORAGE_DEVICE_FD_T *devfd)
{
    volatile bool done = false;
    void *tmp = NULL;
    int32_t rc = 0;

    tmp = devfd->data;

    if (devfd->thread != NULL) {
        /* Get io channel from polling thread */
        devfd->data = (void *)&done;
        spdk_thread_send_msg(devfd->thread, LibstorageGetIoChannelCb, (void *)devfd);

        while (!ACCESS_ONCE(done)) {
            /* do nothing; */
        }
        devfd->data = tmp;

        spdk_rmb();

        if (ACCESS_ONCE(devfd->channel) == NULL) {
            rc = -1;
        }
    } else {
        SPDK_ERRLOG("Failed in get thread when get channel\n");
        rc = -1;
    }
    return rc;
}

static LIBSTORAGE_DEVICE_FD_T* LibstoragePollGetReuseFd(const char *devfullname, bool *isOldFd)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    LIBSTORAGE_DEVICE_FD_T *reuseDevfd = NULL;

    SLIST_FOREACH(devfd, &g_devfd_list, slist) {
        if (devfd->ref == (int32_t)DISK_REUSE) {
            if (reuseDevfd == NULL) {
                /* try to reuse the old devfd */
                reuseDevfd = devfd;
            }
            continue;
        } else if (devfd->ref <= (int32_t)DISK_DELETE) {
            continue;
        } else if (!g_bSameBdevMultiQ || devfd->ref == (int32_t)DISK_CLOSE) {
            if (strcmp(devfd->devname, devfullname) == 0) {
                *isOldFd = true;
                return devfd;
            }
        }
    }

    *isOldFd = false;
    return reuseDevfd;
}

static LIBSTORAGE_DEVICE_FD_T* LibstoragePollAllocDeviceFd(const char *devfullname, bool *isOldFd)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    LIBSTORAGE_DEVICE_FD_T *reuseDevfd = NULL;
    struct spdk_thread *thread = NULL;

    thread = LibstorageGetBdevThread(devfullname);
    if (thread == NULL) {
        SPDK_ERRLOG("No thread allocated for %s\n", devfullname);
        return NULL;
    }
    spdk_set_thread(thread);
    reuseDevfd = LibstoragePollGetReuseFd(devfullname, isOldFd);
    devfd = reuseDevfd;
    if (reuseDevfd == NULL) {
        devfd = calloc(1, sizeof(LIBSTORAGE_DEVICE_FD_T));
        if (devfd == NULL) {
            SPDK_ERRLOG("Failed to alloc memory for devfd when opened %s\n", devfullname);
            LibstoragePutBdevThread(thread, devfullname);
            return NULL;
        }
    }

    if (strcpy_s(devfd->devname, MAX_BDEV_NAME_LEN, devfullname) != 0) {
        LibstoragePutBdevThread(thread, devfullname);
        if (reuseDevfd == NULL) {
            free(devfd);
        }

        return NULL;
    }

    devfd->thread = thread;
    return devfd;
}

int32_t libstorage_open_poll(const char *devfullname)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    bool isOldFd = false;
    int rc;
    static int32_t assignNvmefd = 0;
    bool isParallelWrite = false;
    int32_t ret;

    if (devfullname == NULL) {
        return -1;
    }

    (void)pthread_mutex_lock(&g_devfd_mutex);
    devfd = LibstoragePollAllocDeviceFd(devfullname, &isOldFd);
    if (devfd == NULL) {
        (void)pthread_mutex_unlock(&g_devfd_mutex);
        SPDK_ERRLOG("No fd allocated for %s\n", devfullname);
        return -1;
    }

    if (isOldFd) {
        devfd->ref++;
        (void)pthread_mutex_unlock(&g_devfd_mutex);
        SPDK_NOTICELOG("Libstorage: open_poll %s reuse thread: %p, ref is %d.\n",
                       devfd->devname, devfd->thread, devfd->ref);
        return devfd->fd;
    }

    devfd->disktype = (int32_t)NVME_DISK;
    ++assignNvmefd;
    devfd->fd = (int32_t)NVME_DISK << DISK_TYPE_SHIFT2_FOR_FD |
                (int32_t)NVME_DISK << DISK_TYPE_SHIFT1_FOR_FD | assignNvmefd;
    isParallelWrite = g_bSameBdevMultiQ;
    rc = spdk_bdev_open_ext(devfd->devname, !isParallelWrite, LibstoragePollDiskRemove,
                            (void *)(intptr_t)(devfd->fd), (struct spdk_bdev_desc **)&devfd->bdev_desc);
    if (rc != 0) {
        SPDK_WARNLOG("%s is already opened for writing or deleting\n", devfullname);
        goto EXIT;
    }

    devfd->ctrlr = bdev_nvme_get_ctrlr_by_bdev_desc(devfd->bdev_desc);
    ret = LibstorageGetBdevIoChannel(devfd);
    if (ret != 0) {
        SPDK_ERRLOG("Can't get %s io channel\n", devfullname);
        spdk_bdev_close(devfd->bdev_desc);
        goto EXIT;
    }

    if (devfd->ref != (int32_t)DISK_REUSE) {
        SLIST_INSERT_HEAD(&g_devfd_list, devfd, slist);
    }
    devfd->ref = 1;
#ifdef SPDK_CONFIG_ERR_INJC
    libstorage_err_injc_init(devfd->devname);
#endif
    (void)pthread_mutex_unlock(&g_devfd_mutex);
    SPDK_NOTICELOG("Libstorage: open_poll %s thread: %p\n", devfd->devname, devfd->thread);
    return devfd->fd;

EXIT:
    --assignNvmefd;
    LibstoragePutBdevThread(devfd->thread, devfd->devname);
    devfd->thread = NULL;
    if (devfd->ref != (int32_t)DISK_REUSE) {
        free(devfd);
    }
    (void)pthread_mutex_unlock(&g_devfd_mutex);
    SPDK_ERRLOG("Can't open %s\n", devfullname);
    return -1;
}

int32_t libstorage_close_poll(int32_t fd)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    int32_t err = -1;

    (void)pthread_mutex_lock(&g_devfd_mutex);
    SLIST_FOREACH(devfd, &g_devfd_list, slist) {
        /* Only decrease the device reference. We can use the old fd next time.
         * Donot close device in fact that avoid deleting devfd from g_devfd_list.
         * And we needn't lock when using g_devfd_list for launching io.
         */
        if (devfd->fd == fd) {
            if (devfd->ref > (int32_t)DISK_CLOSE) {
                devfd->ref--;
            }

            err = 0;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_devfd_mutex);
    return err;
}

static struct spdk_thread *LibstorageGetFdThread(int fd)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    struct spdk_thread *thread = NULL;

    /* needn't lock. The value of 'devfd->thread' either NULL or a valid address.
     * Even though getting a wrong value does not affect the system't state.
     * When the disk has been closed or unplugged, the IO will not continue to be issued.
     */
    devfd = LibstorageGetDeviceFd(&g_devfd_list, fd);
    if (devfd != NULL) {
        thread = devfd->thread;
    }
    return thread;
}


static void LibstoragePollLaunchIo(void *launchio) /* �ύIO */
{
    LIBSTORAGE_IO_T *io = (LIBSTORAGE_IO_T *)launchio;
    int32_t err;
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    LIBSTORAGE_CALLBACK_FUNC cb;

    if (io == NULL) {
        SPDK_ERRLOG("Oops, io is NULL form spdk_event_mempool!\n");
        return;
    }

    io->location = (uint8_t)LOCAL_LIBSTORAGE_ASYNC_REQ;

    /* �豸�򿪾��Ѿ����̰߳󶨣������������̲߳���ͬһ��fd��
     * ֻ��ϵͳ�˳�ʱ�Ż�ɾ��dfvfd�������ܱ�֤���ݰ�ȫ�����ü���
     */
    devfd = LibstorageGetDeviceFd(&g_devfd_list, io->fd);
    if (devfd == NULL) {
        io->location = (uint8_t)LOCAL_LIBSTORAGE_CALLBACK;
        io->cb(-EINVAL, 0, io->cb_arg);
        libstorage_io_t_free_buf(io);
        return;
    }

    if (io->opcode == (uint16_t)OP_DEALLOCATE) {
        err = LibstorageDeallocateNvme(devfd, io, async_io_completion_cb);
    } else {
        err = LibstorageLaunchIoToNvme(devfd, io, async_io_completion_cb);
    }

    if (err == -ENOMEM) {
        SPDK_NOTICELOG("Failed to submit io once, try again.\n");
        io->location = (uint8_t)LOCAL_LIBSTORAGE_SUBMIT_RETRY;
        spdk_thread_send_msg(devfd->thread, LibstoragePollLaunchIo, launchio);
        return;
    }

    if (err != 0) {
        SPDK_ERRLOG("Failed to launch I/O, err[%d]. io[%p], fd[%d] op[%u] offset[%lu].\n",
                    err, io, io->fd, io->opcode, io->offset);
        cb = io->cb;
        io->cb = NULL;
        spdk_mb();
        if (cb == NULL) {
            SPDK_ERRLOG("Oops. Invalid io[%p]'s magic[0x%X].\n",io, io->magic);
            libstorage_io_t_free_buf(io);
            return;
        }

        io->location = (uint8_t)LOCAL_LIBSTORAGE_CALLBACK;
        cb(err, 0, io->cb_arg);
        libstorage_io_t_free_buf(io);
        return;
    }
}

int32_t libstorage_submit_io_poll(LIBSTORAGE_IO_T *submitio)
{
    LIBSTORAGE_IO_T *io = submitio;
    struct spdk_thread *thread = NULL;

    if (io == NULL) {
        return -EBADF;
    }

    thread = LibstorageGetFdThread(io->fd);
    if (thread != NULL) {
        io->location = (uint8_t)LOCAL_LIBSTORAGE_SUBMIT;
        spdk_set_thread(NULL);
        spdk_thread_send_msg(thread, LibstoragePollLaunchIo, io);
        return 0;
    }
    return -EBADF;
}

static void LibstoragePollInitThreadCfgInfo(void)
{
    int32_t i;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lcore_thread_info[i].thread = NULL;
        lcore_thread_info[i].state = (int32_t)SPDK_THREAD_STATE_INITIALIZED;
        lcore_thread_info[i].bdevnum = 0;
    }
}

static char LibstoragePollHexNumSet0Bit(char c)
{
    if (c >= '0' && c <= '9') {
        c -= '0';
        c |= 0x1;
        c += '0';
    } else if (c >= 'a' && c <= 'f') {
        c = c - 'a' + 10;   /* 0xa means 10 */
        c |= 0x1;
        c = c - 10 + 'a';   /* 0xa means 10 */
    } else if (c >= 'A' && c <= 'F') {
        c = c - 'A' + 10;   /* 0xA means 10 */
        c |= 0x1;
        c = c - 10 + 'A';   /* 0xA means 10 */
    }

    return c;
}

#define MAX_CPU_MASK_BIT 36
static int32_t LibstoragePollAdjustMask(const char *coremask, char *out_mask)
{
    uint32_t len;
    int8_t c;

    len = strlen(coremask);
    if (len == 0 || len >= MAX_CPU_MASK_BIT - 1) {
        return -1;
    }

    if (strcpy_s(out_mask, MAX_CPU_MASK_BIT, coremask) != 0) {
        return -1;
    }
    c = out_mask[len - 1];

    /* Give the NO.0 core to DPDK, but we will not use it */
    out_mask[len - 1] = LibstoragePollHexNumSet0Bit(c);
    return 0;
}

static int libstorage_init_spdk(struct spdk_conf_section *sp)
{
    int ret;
    int32_t memsize;
    struct spdk_env_opts env_opts;
    char cpu_mask[MAX_CPU_MASK_BIT] = {0};
    char *reactor_mask = NULL;
    char *socket_mem  = NULL;
    char *socket_limit = NULL;
    char socket_cmd[MAX_SOCKET_CMD_SIZE] = "";

    reactor_mask = spdk_conf_section_get_val(sp, "ReactorMask");
    if (reactor_mask == NULL) {
        SPDK_ERRLOG("Cannot find \"ReactorMask\" item in configuration file.\n");
        return -EPERM;
    }
    memsize = spdk_conf_section_get_intval(sp, "MemSize");
    if (memsize < MINIMUM_MEMORY_SIZE_WITH_REACTOR_M) {
        memsize = MINIMUM_MEMORY_SIZE_WITH_REACTOR_M;
    }

    /* Adjust the mask before giving to DPDK. */
    if (LibstoragePollAdjustMask(reactor_mask, cpu_mask) != 0) {
        SPDK_ERRLOG("Invalid ReactorMask[%s] in configuration file.\n", reactor_mask);
        return -EPERM;
    }

    socket_mem = spdk_conf_section_get_val(sp, "SocketMem");
    socket_limit = spdk_conf_section_get_val(sp, "SocketLimit");

    spdk_env_opts_init(&env_opts);
    env_opts.name = "LibStorage";
    env_opts.core_mask = cpu_mask;
    env_opts.mem_size = memsize;
    if (build_socket_cmd(socket_cmd, MAX_SOCKET_CMD_SIZE, socket_mem, socket_limit) > 0) {
        env_opts.env_context = socket_cmd;
        env_opts.mem_size = -1; /* mem and socket-mem can't set same time */
    }

    ret = spdk_env_init(&env_opts);
    if (ret != 0) {
        SPDK_ERRLOG("Failed to initialize SPDK.\n");
        return ret;
    }

    return 0;
}

int32_t libstorage_init_with_reactor(void)
{
    struct spdk_conf_section *sp = NULL;
    int32_t ret;

    LibstoragePollInitThreadCfgInfo();
    sp = spdk_conf_find_section(g_libstorage_config, "Global");
    if (sp == NULL) {
        SPDK_ERRLOG("Cannot find \"Global\" section in configuration file.\n");
        return -EPERM;
    }

    g_bSameBdevMultiQ = spdk_conf_section_get_boolval(sp, "MultiQ", false);
    g_libstorage_iostat = spdk_conf_section_get_boolval(sp, "IoStat", false);

    ret = libstorage_init_spdk(sp);
    if (ret != 0) {
        SPDK_ERRLOG("Failed to init spdk\n");
        return ret;
    }

    libstorage_notify_dpdk_init();
    ret = spdk_reactors_init();
    if (ret != 0) {
        SPDK_ERRLOG("Invalid reactor mask.\n");
        return ret;
    }

    g_masterThread = libstorage_create_spdk_thread();
    if (g_masterThread == NULL) {
        SPDK_ERRLOG("Failed to allocate spdk_thread for master core.\n");
        return -1;
    }

    spdk_set_thread(g_masterThread);
    spdk_reactors_start();
    return 0;
}

int32_t libstorage_exit_with_reactor(void)
{
    uint32_t i;
    uint32_t current_core;

    spdk_reactors_stop(NULL);

    current_core = spdk_env_get_current_core();
    SPDK_ENV_FOREACH_CORE(i) {
        if (i != current_core) {
            while (lcore_thread_info[i].state == (int32_t)SPDK_THREAD_STATE_RUNNING)
                ;
        }
    }
    return 0;
}
