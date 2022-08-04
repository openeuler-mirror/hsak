/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: LibStorage IO statistics API.
 * Author: zhangsaisai@huawei.com
 * Create: 2018-09-01
 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <securec.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include "bdev_rw_common.h"
#include "bdev_rw_internal.h"
#include "spdk/bdev_rw.h"
#include "spdk/conf.h"
#include "spdk/event.h"
#include "spdk/util.h"

int libstorage_stat_init(void)
{
    int shm_fd;
    char *path = LIBSTORAGE_STAT_SHM_FILE_NAME;
    bool is_create = false;

    shm_fd = libstorage_open_shm_set_size(path, sizeof(struct libstorage_bdev_io_stat) * STAT_MAX_NUM, &is_create);
    if (shm_fd < 0) {
        SPDK_ERRLOG("[libstorage_stat]Open share memory failed[err=%d].\n", shm_fd);
        return shm_fd;
    }

    g_io_stat_map = (struct libstorage_bdev_io_stat *)mmap(NULL,
                                                           sizeof(struct libstorage_bdev_io_stat) * STAT_MAX_NUM,
                                                           PROT_WRITE,
                                                           MAP_SHARED,
                                                           shm_fd,
                                                           0);
    /* if mmap failed, do not unlink share memory, because other threads will use the share memory. */
    if (g_io_stat_map == MAP_FAILED) {
        SPDK_ERRLOG("[libstorage_stat] mmap failed[errno=%s].\n", strerror(errno));
        close(shm_fd);
        return -1;
    }

    /* clear ctrlr stat info claimed by the process */
    if (!is_create) {
        nvme_ctrlr_clear_iostat_all();
        close(shm_fd);
        return 0;
    }

    close(shm_fd);
    return 0;
}

int libstorage_stat_exit(void)
{
    if (g_io_stat_map == NULL) {
        SPDK_WARNLOG("[libstorage] g_io_stat_map is NULL.\n");
        return -1;
    }

    (void)munmap(g_io_stat_map, sizeof(struct libstorage_bdev_io_stat) * STAT_MAX_NUM);

    return 0;
}
