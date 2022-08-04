/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: cli of disk shutdown
* Author: louhongxiang
* Create: 2018-10-22
*/

#include <regex.h>
#include <spdk/env.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "ublock.h"
#include "ublock_cli_common.h"
#include "ublock_internal.h"

/* print help information and exit */
static void usage(const char *opt)
{
    printf("Usage: %s <reset> <device> [<device2> ...]\n", opt);
    printf("       The 'reset' is optional, means reset driver from uio to kernel nvme.\n");
    printf("       The '<device>' should be the pci address of NVMe device.\n");
    printf("       The format of pci address is CCCC:BB:DD.F (ex: 0000:00:01.0).\n");
    printf("       Specify one pci address to shutdown at least.\n");
    printf("\n");
    printf("These following commands are all supported:\n");
    printf("       libstorage-shutdown [help or --?]            "
           "Show libstorage-shutdown usage\n");
    printf("       libstorage-shutdown <device>                 "
           "Shutdown NVMe specified by <device>\n");
    printf("       libstorage-shutdown <device1> <device2> ...  "
           "Shutdown NVMes one by one listed by <device1> <device2> ....\n");

    exit(1);
}

int main(int argc, char *argv[])
{
    int rc = 0;
    int arg_index = 1;
    bool reset_flag = false;
    const char *op_name[2] = { "shutdown", "reset driver" }; // 2 kinds of operations

    if (argv == NULL) {
        printf("Incorrect parameter.\n");
        return -1;
    }

    if (argc < 2) { /* 2 parameters at least */
        usage(argv[0]);
    } else {
        if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--?") == 0) {
            usage(argv[0]);
        } else if (strcmp(argv[1], "reset") == 0) {
            reset_flag = true;
            arg_index++;
        }

        while (arg_index < argc) {
            if (ublock_str_is_nvme_pci_addr(argv[arg_index]) == 0) {
                printf("error: pci address '%s' is not in correct format.\n", argv[arg_index]);
                return -1;
            }

            rc = ublock_shutdown_disk(argv[arg_index], reset_flag);
            if (rc != 0) {
                fprintf(stderr, "libstorage %s %s fail!\n", op_name[reset_flag ? 1 : 0], argv[arg_index]);
                fprintf(stderr, "please make sure that pci address is correct or the disk is present in %s.\n",
                        argv[arg_index]);
                return -1;
            } else {
                printf("libstorage %s %s success!\n", op_name[reset_flag ? 1 : 0], argv[arg_index]);
            }
            arg_index++;
        }
    }

    return rc;
}
