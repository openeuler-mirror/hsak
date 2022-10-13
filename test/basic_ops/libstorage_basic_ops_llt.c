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
 * Description: test for bdev_rw.c 
 * Author: liujiawen <liujiawen10@huawei.com> 
 * Create: 2019-07-30
 */
#include <sys/file.h>
#include "spdk/bdev.h"
#include "bdev_rw_internal.h"
#include "bdev_rw_rpc_internal.h"
#ifdef SPDK_CONFIG_ERR_INJC
#include "bdev_rw_err_injc.h"
#endif

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

#define ESN_SIZE	20

struct libstorage_dpdk_init_notify_arg g_dpdk_mem_info;

static void test_libstorage_open_errinput(void)
{
    CU_ASSERT_EQUAL(libstorage_open(NULL), -1); 
    CU_ASSERT_EQUAL(libstorage_open("%s"), -1);
    CU_ASSERT_EQUAL(libstorage_open(""), -1);
    CU_ASSERT_EQUAL(libstorage_open("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), -1);
}

static void test_libstorage_close_errinput(void)
{
    CU_ASSERT_EQUAL(libstorage_close(0), -1); 
}

static void test_libstorage_open_close_rightinput(void)
{
    int32_t fd;

    fd = libstorage_open("nvme0n1");
    CU_ASSERT(fd > 0);

    CU_ASSERT_NOT_EQUAL(g_dpdk_mem_info.memsegCount, 0);

    CU_ASSERT_EQUAL(libstorage_close(fd), 0);
}

static int test_libstorage_basic_ops_setup(void)
{
    const char* cfgfile = "conf/nvme.conf1.in";

    if (libstorage_init_module(cfgfile) != 0) {
        CU_ASSERT(false);
        return 1;
    }
    return 0;
}

static int test_libstorage_basic_ops_cleanup(void)
{
    libstorage_exit_module();
    return 0;
}

static int test_libstorage_create_delete_ctrlr(void)
{
    const char* cfgfile = "conf/nvme.conf1.in";
    const char* ctrlrname = "nvme0";
    const char* bdevname = "nvme0n1";
    char *new_bdevname = NULL;
    const char* pci = "0000:00:09.0";
    char tmp_sn[ESN_SIZE + 1] = {0};
    struct libstorage_nvme_ctrlr_info *info = NULL;
    struct libstorage_namespace_info *ns_info = NULL;
    struct libstorage_mgr_info mgr_info;
    struct libstorage_smart_info smart_info;
    int cnt = libstorage_get_nvme_ctrlr_info(&info);
    if (cnt > 0) {
        CU_ASSERT_EQUAL(strncmp(info->name, ctrlrname, strlen(ctrlrname)), 0);
        CU_ASSERT_EQUAL(strncmp(info->address, pci, strlen(pci)), 0);
        CU_ASSERT_EQUAL(libstorage_nvme_delete_ctrlr(info->name), 0);
        CU_ASSERT_EQUAL(libstorage_nvme_reload_ctrlr(cfgfile), 0);
        free(info);
        CU_ASSERT_EQUAL(libstorage_get_nvme_ctrlr_info(&info), cnt);
        int rc = memcpy_s(tmp_sn, ESN_SIZE, info->sn, ESN_SIZE);
        if (rc != 0) {
            CU_ASSERT(false);
        }
	if (info->cap_info.ns_manage) {
            CU_ASSERT_EQUAL(libstorage_get_mgr_info_by_esn(tmp_sn, &mgr_info), 0);
            CU_ASSERT_EQUAL(strncmp(mgr_info.pci, pci, strlen(pci)), 0);
            CU_ASSERT_EQUAL(libstorage_get_mgr_smart_by_esn(tmp_sn, 1, &smart_info), 0);
            CU_ASSERT_EQUAL(libstorage_get_bdev_ns_info(bdevname, &ns_info), 1);
            CU_ASSERT_EQUAL(strncmp(ns_info->name, bdevname, strlen(bdevname)), 0);

            CU_ASSERT_EQUAL(libstorage_delete_all_namespace(ctrlrname), 0);
            CU_ASSERT_EQUAL(libstorage_low_level_format_nvm(ctrlrname, 0,
                                                            LIBSTORAGE_FMT_NVM_PROTECTION_DISABLE,
                                                            false, true, 0), 0);
            CU_ASSERT_NOT_EQUAL(libstorage_create_namespace(ctrlrname, ns_info->sectors, &new_bdevname), 0);
            free(ns_info);
	}
        CU_ASSERT_EQUAL(libstorage_get_bdev_ns_info(bdevname, &ns_info), 1);
        free(ns_info);
        free(new_bdevname);
    }
    free(info);
}

static void dpdk_notify(const struct libstorage_dpdk_init_notify_arg *arg)
{
    memcpy_s(&g_dpdk_mem_info, sizeof(struct libstorage_dpdk_init_notify_arg),
             arg, sizeof(struct libstorage_dpdk_init_notify_arg));
}

LIBSTORAGE_REGISTER_DPDK_INIT_NOTIFY(basic_ops, dpdk_notify);

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

int main(int argc, char * *argv)
{
    CU_pSuite suite;
    CU_pTest pTest;
    unsigned int num_failures;
    CU_RunMode CUnitMode = CUNIT_SCREEN;

    if (argc > 1) {
        CUnitMode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("libstorage_basic_ops", test_libstorage_basic_ops_setup, test_libstorage_basic_ops_cleanup);
    if (suite == NULL) {
        goto ERROR;
    }

    pTest = CU_ADD_TEST(suite, test_libstorage_open_close_rightinput);
    if (pTest == NULL) {
        goto ERROR;
    }

    pTest = CU_ADD_TEST(suite, test_libstorage_close_errinput);
    if (pTest == NULL) {
        goto ERROR;
    }

    pTest = CU_ADD_TEST(suite, test_libstorage_open_errinput);
    if (pTest == NULL) {
        goto ERROR;
    }

    pTest = CU_ADD_TEST(suite, test_libstorage_create_delete_ctrlr);
    if (pTest == NULL) {
        goto ERROR;
    }

    switch (CUnitMode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("bdev_rw.c");
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

