/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2022. All rights reserved.
 * hsak is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: ublock_bdev_llt
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

const char g_pci[] = "0000:00:09.0";
const char *g_driver_name = "uio_pci_generic";
const char g_esn[] = "PHKS7335001L375AGN  ";

static int test_ublock_bdev_setup(void)
{
    return init_ublock(NULL, UBLOCK_RPC_SERVER_ENABLE);
}

static void test_ublock_esn_interfaces(void)
{
    /* basic function testing */
    struct ublock_SMART_info smart;
    struct ublock_bdev bdev;
    CU_ASSERT(ublock_get_bdev_by_esn(g_esn, &bdev) == 0);
    CU_ASSERT(strncmp(bdev.pci, g_pci, sizeof(bdev.pci)) == 0);

    /* esn was invalid */
    CU_ASSERT_NOT_EQUAL(ublock_get_SMART_info_by_esn("", 1, &smart), 0);
    CU_ASSERT_NOT_EQUAL(ublock_get_SMART_info_by_esn(NULL, 1, &smart), 0);
    CU_ASSERT_NOT_EQUAL(ublock_get_SMART_info_by_esn("1", 1, &smart), 0);

    CU_ASSERT_NOT_EQUAL(ublock_get_bdev_by_esn("", &bdev), 0);
    CU_ASSERT_NOT_EQUAL(ublock_get_bdev_by_esn(NULL, &bdev), 0);
    CU_ASSERT_NOT_EQUAL(ublock_get_bdev_by_esn("1", &bdev), 0);
}

static int test_ublock_bdev_cleanup(void)
{
    ublock_fini();
    return 0;
}

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

CU_RunMode g_CunitMode = CUNIT_SCREEN; // default mode

// param1: g_CunitMode < 0, 1, 2 >
int main(int argc, char **argv)
{
    CU_pSuite suite;
    int num_failures;

    if (argc > 1) {
        g_CunitMode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("ublock_bdev", test_ublock_bdev_setup, test_ublock_bdev_cleanup);
    if (suite == NULL) {
        goto ERROR;
    }

    if (CU_ADD_TEST(suite, test_ublock_esn_interfaces) == NULL) {
        goto ERROR;
    }

    switch (g_CunitMode) {
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
            printf("not suport cunit mode, only suport: 0 or 1\n");
            goto ERROR;
    }

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;

ERROR:
    CU_cleanup_registry();
    return CU_get_error();
}
