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
 * Description: ublock iostat
 * Author: zhoupengchen
 * Create: 2018-9-1
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <limits.h>
#include "ublock.h"
#include "ublock_internal.h"
#include <spdk_internal/nvme_internal.h>

static uint64_t g_cpu_ticks_hz = 0;  /* save cpu ticks hz */
static struct libstorage_bdev_io_stat *io_stat_map; /* Share memory mmap area */

/* get cpu frequency */
static uint64_t get_tsc_freq_local(void)
{
#ifdef CLOCK_MONOTONIC_RAW
#define NS_PER_SEC 1E9

    struct timespec sleeptime = { .tv_nsec = (long)(NS_PER_SEC / 10) }; /* 1/10 second */

    struct timespec t_start, t_end;
    uint64_t tsc_hz;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
        uint64_t ns, end, start = get_tsc_cycles_local();
        nanosleep(&sleeptime, NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
        end = get_tsc_cycles_local();
        if (t_start.tv_sec > t_end.tv_sec ||
                (t_start.tv_sec == t_end.tv_sec && t_start.tv_nsec >= t_end.tv_nsec) ||
                start > end) {
            return 0;
        }

        ns = (uint64_t)((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
        ns += (uint64_t)(t_end.tv_nsec - t_start.tv_nsec);

        double secs = (double)ns / NS_PER_SEC;
        tsc_hz = (uint64_t)((end - start) / secs);
        return tsc_hz;
    }
#endif
    return 0;
}

static int mmap_stat_sharemem(void)
{
    int shm_fd = -1;
    char *path = LIBSTORAGE_STAT_SHM_FILE_NAME;

    /* open share memory */
    shm_fd = shm_open(path, O_RDWR, 0600); /* access mode 0600 */
    if (shm_fd < 0) {
        char *tmp_str = strerror(errno);
        if (tmp_str != NULL) {
            printf("[ublock-iostat] open share memory failed[errno=%s].\n", tmp_str);
        } else {
            printf("[ublock-iostat] open share memory failed[errno=%d].\n", errno);
        }
        return -1;
    }

    io_stat_map = (struct libstorage_bdev_io_stat*)mmap(NULL,
                                                        sizeof(struct libstorage_bdev_io_stat)*STAT_MAX_NUM,
                                                        PROT_READ,
                                                        MAP_SHARED,
                                                        shm_fd,
                                                        0);
    if (io_stat_map == (void*)-1) {
        char *tmp_str = strerror(errno);
        if (tmp_str != NULL) {
            printf("[ublock-iostat] mmap share memory failed[errno=%s].\n", tmp_str);
        } else {
            printf("[ublock-iostat] mmap share memory failed[errno=%d].\n", errno);
        }
        close(shm_fd);
        /* if mmap failed, do not unlink share memory, because other threads will use the share memory. */
        return -1;
    }

    close(shm_fd);
    return 0;
}

static int query_ctrlr_status(const char* pci, char* ctrl_name)
{
    int ret;
    char* sock_addr = NULL;
    int iostat_enable;

    sock_addr = ublock_get_sockaddr_shm(pci, ctrl_name, UBLOCK_CTRLR_NAME_MAX_LEN);
    if (sock_addr == NULL) { // pci is not register in share memory
        return (int)UBLOCK_CTRL_INVALID;
    } else if (access(sock_addr, F_OK) < 0) { // socket is not exist, socket is clean when Io process init and exit
        free (sock_addr);
        sock_addr = NULL;
        return (int)UBLOCK_CTRL_INVALID;
    }

    free (sock_addr);
    sock_addr = NULL;

    /* when IO process abort, socket file exist /var/run, so need rpc to verfiry nvme device is run in IO */
    iostat_enable = (int)UBLOCK_IOSTAT_QUERY;
    ret = ublock_client_iostat_enable(pci, iostat_enable);

    return ret;
}

static int ublock_find_ctrl_stat_by_name(const char *ctrl_name, struct ublock_ctrl_iostat_info *ctrl_iostat)
{
    int i;
    int find_ctrl = 0;
    uint64_t cpu_ticks;
    size_t size;

    size = strnlen(ctrl_name, STAT_NAME_LEN - 2); /* minus 2 to prevent overflowing */

    /* Get cpu frequency per second */
    cpu_ticks = g_cpu_ticks_hz;
    if (cpu_ticks == 0) {
        cpu_ticks = get_tsc_freq_local();
    }

    for (i = 0; i < STAT_MAX_NUM; i++) {
        if (strncmp(io_stat_map[i].bdev_name, ctrl_name, size) != 0) {
            continue;
        }
        if ((io_stat_map[i].bdev_name[size] == 'n') && isdigit(io_stat_map[i].bdev_name[size + 1])) {
            find_ctrl++;
            ctrl_iostat->num_read_ops += io_stat_map[i].num_read_ops;
            ctrl_iostat->num_write_ops += io_stat_map[i].num_write_ops;
            if (cpu_ticks != 0) {
                ctrl_iostat->read_latency_ms += (uint64_t)((double)io_stat_map[i].read_latency_ticks /
                        (double)cpu_ticks * 1000.0); /* 1000.0 convert sec to ms */
                ctrl_iostat->write_latency_ms += (uint64_t)((double)io_stat_map[i].write_latency_ticks /
                        (double)cpu_ticks * 1000.0); /* 1000.0 convert sec to ms */
                ctrl_iostat->io_ticks_ms += (uint64_t)((double)io_stat_map[i].io_ticks /
                        (double)cpu_ticks * 1000.0); /* 1000.0 convert see to ms */
            }
            ctrl_iostat->io_outstanding += io_stat_map[i].io_outstanding;
            ctrl_iostat->num_poll_timeout += io_stat_map[i].num_poll_timeout;
        }
    }

    return find_ctrl;
}

void ublock_init_iostat(void)
{
    g_cpu_ticks_hz = (uint64_t)spdk_get_ticks_hz();
    if (g_cpu_ticks_hz == 0) {
        g_cpu_ticks_hz = get_tsc_freq_local();
    }
    SPDK_NOTICELOG("[ublock-iostat]cpu_ticks_hz was: %lu\n", g_cpu_ticks_hz);
    return;
}

/*
 * Read ctrl io stat info from share memory.
*/
int ublock_get_ctrl_iostat(const char* pci, struct ublock_ctrl_iostat_info *ctrl_iostat)
{
    int rc;
    int find_ctrl;
    char *ctrl_name = NULL;

    if (pci == NULL || ctrl_iostat == NULL) {
        printf("[ublock-iostat] pci or ctrl_iostat is NULL!\n");
        return -1;
    }

    rc = memset_s(ctrl_iostat, sizeof(struct ublock_ctrl_iostat_info), 0, sizeof(struct ublock_ctrl_iostat_info));
    if (rc != 0) {
        printf("[ublock-iostat] memset failed!\n");
        return -1;
    }

    ctrl_name = (char *)malloc(sizeof(char) * UBLOCK_CTRLR_NAME_MAX_LEN);
    if (ctrl_name == NULL) {
        printf("[ublock-iostat] malloc for ctrl name failed!\n");
        return -1;
    }

    rc = query_ctrlr_status(pci, ctrl_name);
    if (rc == -1) { /* EINVAL or invalid parameter or rpc remote error */
        free(ctrl_name);
        return -1;
    } else if ((rc == (int)UBLOCK_CTRL_INVALID)
        || (rc == (int)UBLOCK_IOSTAT_DISABLE_PCI_INVALID)
        || (rc == (int)UBLOCK_IOSTAT_ENABLE_PCI_INVALID)) {
        free(ctrl_name);
        return -2; /* -2 means that nvme device is not in IO process */
    } else if (rc == (int)UBLOCK_IOSTAT_DISABLE_PCI_VALID) {
        free(ctrl_name);
        return -3; /* -3 means that iostat is disable in IO process */
    }

    if (mmap_stat_sharemem() < 0) {
        free(ctrl_name);
        return -1;
    }

    find_ctrl = ublock_find_ctrl_stat_by_name(ctrl_name, ctrl_iostat);
    (void) munmap(io_stat_map, sizeof(struct libstorage_bdev_io_stat) * STAT_MAX_NUM);

    if (find_ctrl == 0) {
        printf("[ublock-iostat] cannot find ctrl iostat info: %s!\n", pci);
        free(ctrl_name);
        return -1;
    }

    free(ctrl_name);
    io_stat_map = NULL;
    return 0;
}
