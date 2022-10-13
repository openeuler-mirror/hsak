/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * hsak is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: ublock_admin_passthru_llt
 */

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

#include <sys/file.h>
#include <securec.h>
#include <spdk/env.h>
#include <spdk/event.h>
#include <spdk/nvme.h>
#include <spdk/pci_ids.h>
#include <spdk/stdinc.h>
#include "ublock.h"
#include "ublock_internal.h"
#include "spdk/bdev_rw.h"

/* libstorage startup seconds */
#define SLEEPS      5
#define USLEEPS     100000

/* the size of IDENTIFY cmd */
#define UBLOCK_ADMIN_CMD_IDENTIFY_SIZE 4096

struct admin_cmd_key_params {
    char       *pci;
    bool        cmd;
    uint16_t    opc;
    uint32_t    cns : 8;
    bool        buf;
    int         offset;
    bool        success;
};

const char g_pci[] = "0000:00:09.0";

struct admin_cmd_key_params g_param_arr[] = {
    {NULL, true, SPDK_NVME_OPC_IDENTIFY, SPDK_NVME_IDENTIFY_CTRLR, true, 0, false},
    {"0000:00:00.0", true, SPDK_NVME_OPC_IDENTIFY, SPDK_NVME_IDENTIFY_CTRLR, true, 0, false},
    {g_pci, false, 0, 0, true, 0, false},
    {g_pci, true, SPDK_NVME_OPC_IDENTIFY, SPDK_NVME_IDENTIFY_CTRLR, true, -1, false},
    {g_pci, true, SPDK_NVME_OPC_IDENTIFY, SPDK_NVME_IDENTIFY_CTRLR, true, 1, false},
    {g_pci, true, SPDK_NVME_OPC_IDENTIFY, SPDK_NVME_IDENTIFY_CTRLR, false, -4096, false},
};

static void test_ublock_nvme_admin_passthru(void)
{
    struct admin_cmd_key_params *param = NULL;
    struct spdk_nvme_cmd *cmd = NULL ;
    void *buf = NULL;
    size_t nbytes;

    for (int i = 0; i < sizeof(g_param_arr) / sizeof(struct admin_cmd_key_params); i++) {
        param = &g_param_arr[i];

        if (param->cmd) {
            cmd = calloc(1, sizeof(struct spdk_nvme_cmd));
            if (!cmd) {
                printf("cmd calloc error\n");
                CU_ASSERT_EQUAL(1, 0);
                return;
            }
            cmd->opc = param->opc;
            cmd->cdw10_bits.identify.cns = param->cns;
        } else {
            cmd = NULL;
        }

        nbytes = UBLOCK_ADMIN_CMD_IDENTIFY_SIZE + param->offset;
        if (param->buf) {
            buf = calloc(1, nbytes);
            if (!buf) {
                printf("buf calloc error\n");
                free(cmd);
                return;
            }
        } else {
            buf = NULL;
        }

        if (param->success) {
            CU_ASSERT_EQUAL(ublock_nvme_admin_passthru(param->pci, cmd, buf, nbytes), 0);
        } else {
            CU_ASSERT_NOT_EQUAL(ublock_nvme_admin_passthru(param->pci, cmd, buf, nbytes), 0);
        }
        free(buf);
        free(cmd);
    }
}

static void test_ublock_nvme_admin_passthru_local(void)
{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        char *result = NULL;
        init_ublock(NULL, UBLOCK_RPC_SERVER_ENABLE);
        test_ublock_nvme_admin_passthru();
        ublock_fini();

        num_failures = CU_get_number_of_failures();
        result = CU_get_run_results_string();
        printf("%d %s", num_failures, result);
        fflush(stdout);

        free(result);
        exit(num_failures);
    }
    do {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    } while (true);
}

static void test_ublock_nvme_admin_passthru_remote(void)
{
    int wstatus;
    int uio_pid = fork();
    if (uio_pid == 0) {
        const char *cfgfile = "conf/nvme.conf.in";
        int ret = libstorage_init_module(cfgfile);
        if (ret != 0) {
            printf("init module failed\n");
            exit(0);
        }

        libstorage_open("nvme0n1");

        while (true) {
            usleep(USLEEPS);
        };
    }

    sleep(SLEEPS); /* wait libstorage startup */

    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        init_ublock(NULL, UBLOCK_RPC_SERVER_ENABLE);
        test_ublock_nvme_admin_passthru();
        ublock_fini();

        num_failures = CU_get_number_of_failures();
        char *result = CU_get_run_results_string();
        printf("%d %s", num_failures, result);
        fflush(stdout);
        free(result);

        exit(num_failures);
    }

    do {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            kill(uio_pid, SIGQUIT);
            break;
        }
    } while (true);
}

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

int main(int argc, char **argv)
{
    CU_pSuite suite;
    int num_failures;
    CU_RunMode CunitMode = CUNIT_SCREEN;

    if (argc > 1) {
        CunitMode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("ublock_rpc", NULL, NULL);
    if (suite == NULL) {
        goto ERROR;
    }

    if (CU_ADD_TEST(suite, test_ublock_nvme_admin_passthru_local) == NULL ||
        CU_ADD_TEST(suite, test_ublock_nvme_admin_passthru_remote) == NULL) {
        goto ERROR;
    }

    switch (CunitMode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("ublock_bdev");
            CU_automated_run_tests();
            break;
        case CUNIT_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            printf("not support cunit mode, only support: 0 or 1\n");
            goto ERROR;
    }

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;

ERROR:
    CU_cleanup_registry();
    return CU_get_error();
}
