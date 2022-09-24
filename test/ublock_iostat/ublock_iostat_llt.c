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
 * Description: ublock_get_bdev_llt_test
 * Author: sunshihao
 * Create: 2019-07-04
 */

#include "ublock.h"
#include "ublock_internal.h"

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

static void test_ublock_iostat_llt(void)

{
    int ret;

    char *pci = NULL;
    struct ublock_ctrl_iostat_info *ctrl_iostat = NULL;
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -1);  //-1 means invalid args
    free(ctrl_iostat);

    pci = NULL;
    ctrl_iostat = (struct ublock_ctrl_iostat_info *)calloc(1, sizeof(struct ublock_ctrl_iostat_info));
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -1);
    free(ctrl_iostat);

    pci = "%s";
    ctrl_iostat = NULL;
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -1);
    free(ctrl_iostat);

    pci = "%s";
    ctrl_iostat = (struct ublock_ctrl_iostat_info *)calloc(1, sizeof(struct ublock_ctrl_iostat_info));
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -2);  //-2 means NVMe disk is not taken over by IO process
    free(ctrl_iostat);

    pci = "81:00.0";
    ctrl_iostat = NULL;
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -1);
    free(ctrl_iostat);

    pci = "81:00.0";
    ctrl_iostat = (struct ublock_ctrl_iostat_info *)calloc(1, sizeof(struct ublock_ctrl_iostat_info));
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -2);
    free(ctrl_iostat);

    pci = "";
    ctrl_iostat = NULL;
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -1);
    free(ctrl_iostat);

    pci = "";
    ctrl_iostat = (struct ublock_ctrl_iostat_info *)calloc(1, sizeof(struct ublock_ctrl_iostat_info));
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -2);
    free(ctrl_iostat);

    pci = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    ctrl_iostat = NULL;
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -1);
    free(ctrl_iostat);

    pci = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    ctrl_iostat = (struct ublock_ctrl_iostat_info *)calloc(1, sizeof(struct ublock_ctrl_iostat_info));
    ret = ublock_get_ctrl_iostat(pci, ctrl_iostat);
    CU_ASSERT_EQUAL(ret, -2);
    free(ctrl_iostat);
}

static void test_get_iostat_with_io_ticks(void)
{
    int ret = 0;
    const char *pci_address = "0000:00:09.0";
    struct ublock_ctrl_iostat_info ctrlr_iostat;
    uint64_t last_io_ticks = 0;
    uint64_t curr_ops = 0;
    uint64_t last_ops = 0;
    double svctm = 0.0;
    while (ret == 0) {
        ret = ublock_get_ctrl_iostat(pci_address, &ctrlr_iostat);
        if (ret == 0) {
            CU_ASSERT(ctrlr_iostat.io_ticks_ms >= last_io_ticks);
            curr_ops = ctrlr_iostat.num_read_ops + ctrlr_iostat.num_write_ops;
            CU_ASSERT(curr_ops != last_ops)
            /* svctm = io_ticks_ms/iops stand for latency time per io */
            svctm = ((double)ctrlr_iostat.io_ticks_ms - last_io_ticks) / (curr_ops - last_ops);
            CU_ASSERT(svctm > 0 && svctm < 0.1); /* 0.1 means 100us */
            last_io_ticks = ctrlr_iostat.io_ticks_ms;
            last_ops = curr_ops;
            sleep(1);
        }
    }
}

static int test_ublock_setup(void)
{
    return init_ublock(NULL, UBLOCK_RPC_SERVER_ENABLE);
}

static int test_ublock_cleanup(void)
{
    ublock_fini();
    return 0;
}

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

int main(int argc, char * *argv)
{
    CU_pSuite suite;
    int num_failures;
    CU_RunMode CUnitMode = CUNIT_SCREEN;

    if (argc > 1) {
        CUnitMode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("ublock_iostat", test_ublock_setup, test_ublock_cleanup);
    if (suite == NULL) {
        goto ERROR;
    }

    if (CU_ADD_TEST(suite, test_ublock_iostat_llt) == NULL ||
        CU_ADD_TEST(suite, test_get_iostat_with_io_ticks) == NULL) {
        goto ERROR;
    }

    switch (CUnitMode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("ublock_iostat");
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

