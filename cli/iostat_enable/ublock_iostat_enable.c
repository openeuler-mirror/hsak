/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: io stat switch
* Author: zhangsaisai
* Create: 2018-10-8
*/

#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spdk/env.h>

#include "ublock.h"
#include "ublock_internal.h"

static struct ublock_bdev_mgr g_bdev_list = {{0x0}};
static int g_iostat_enable = 0;

static void usage(void)
{
    printf("Usage: libstorage-iostat-enable [<commands>]\n");
    printf("The following are all supported commands:\n");
    printf("    libstorage-iostat-enable disable     Disable all NVMe devices iostat in IO process\n");
    printf("    libstorage-iostat-enable enable      Enable all NVMe devices iostat in IO process\n");
    printf("    libstorage-iostat-enable status      Query NVMe devices iostat status\n");
}

static int parse_iostat_status_args(const char *argv)
{
    if (strcmp(argv, "disable") == 0) {
        /* disable iostat */
        g_iostat_enable = (int)UBLOCK_IOSTAT_DISABLE;
    } else if (strcmp(argv, "enable") == 0) {
       /* enable iostat */
        g_iostat_enable = (int)UBLOCK_IOSTAT_ENABLE;
    } else if (strcmp(argv, "status") == 0) {
        /* query iostat */
        g_iostat_enable = (int)UBLOCK_IOSTAT_QUERY;
    } else {
        return -1;
    }

    return 0;
}

static int parse_args(int argc, char * const * argv)
{
    if ((argv == NULL) || (argc <= 1)) {
        return -1;
    }

    if (parse_iostat_status_args(argv[1]) != 0) {
        return -1;
    }

    return 0;
}

static void set_iostat_enable(int iostat_enable)
{
    int ret;
    struct ublock_bdev *bdev = NULL;
    struct ublock_bdev *tmp = NULL;
    char *sock_addr = NULL;

    TAILQ_FOREACH_SAFE(bdev, &g_bdev_list.bdevs, link, tmp) {
        sock_addr = ublock_get_sockaddr(bdev->pci);
        if (sock_addr == NULL) { /* if pci is not register in share memory, ignore it */
            continue;
        } else if (access(sock_addr, F_OK) == -1) { /* socket not exist, clean when Io process init and exit */
            free (sock_addr);
            sock_addr = NULL;
            continue;
        }

        free(sock_addr);
        sock_addr = NULL;

        ret = ublock_client_iostat_enable(bdev->pci, iostat_enable);
        if ((ret == (int)UBLOCK_IOSTAT_DISABLE_PCI_VALID) || ((ret == (int)UBLOCK_IOSTAT_DISABLE_PCI_INVALID))) {
            printf("Nvme deice %-16s iostat disable\n", bdev->pci);
        } else if ((ret == (int)UBLOCK_IOSTAT_ENABLE_PCI_VALID) || ((ret == (int)UBLOCK_IOSTAT_ENABLE_PCI_INVALID))) {
            printf("Nvme deice %-16s iostat enable\n", bdev->pci);
        } else {
            printf("Nvme deice %-16s iostat fail\n", bdev->pci);
        }
    }
}

/**
 * Main entry to the iostat enable switch program.
 * Enable or disable or query IO statistics switch for libstorage Userspace IO stack.
 */
int main(int argc, char **argv)
{
    int ret;

    ret = parse_args(argc, argv);
    if (ret != 0) {
        usage();
        return ret;
    }

    ret = ublock_get_bdevs(&g_bdev_list);
    if (ret != 0) {
        printf("[libstorage-iostat-enable] ublock_get_bdevs failed\n");
        return ret;
    }

    set_iostat_enable(g_iostat_enable);

    ublock_free_bdevs(&g_bdev_list);
    return ret;
}
