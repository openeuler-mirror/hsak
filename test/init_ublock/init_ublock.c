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
 * Description: init_ublock_llt_test
 * Author: sunshihao
 * Create: 2019-07-04
 */

#include "ublock.h"
#include "ublock_internal.h"

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

static void test_init_ublock_001(void)

{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        CU_ASSERT_EQUAL(init_ublock(NULL, UBLOCK_RPC_SERVER_ENABLE), 0);
        ublock_fini();
        num_failures = CU_get_number_of_failures();
        exit(num_failures);
    }
    while (true) {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    }
}

static void test_init_ublock_002(void)

{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        CU_ASSERT_EQUAL(init_ublock("%s", UBLOCK_RPC_SERVER_DISABLE), 0);
        ublock_fini();
        num_failures = CU_get_number_of_failures();
        exit(num_failures);
    }
    while (true) {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    }
}

static void test_init_ublock_003(void)

{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        init_ublock("ublock", UBLOCK_RPC_SERVER_ENABLE);
        CU_ASSERT_EQUAL(init_ublock(NULL, UBLOCK_RPC_SERVER_ENABLE), -1);
        ublock_fini();
        num_failures = CU_get_number_of_failures();
        exit(num_failures);
    }
    while (true) {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    }
}

static void test_init_ublock_007(void)

{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        CU_ASSERT_EQUAL(init_ublock("", UBLOCK_RPC_SERVER_DISABLE), 0);
        ublock_fini();
        num_failures = CU_get_number_of_failures();
        exit(num_failures);
    }
    while (true) {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    }
}

static void test_init_ublock_008(void)

{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        init_ublock("ublock", UBLOCK_RPC_SERVER_ENABLE);
        CU_ASSERT_EQUAL(init_ublock("ublock", UBLOCK_RPC_SERVER_ENABLE), -1);
        ublock_fini();
        num_failures = CU_get_number_of_failures();
        exit(num_failures);
    }
    while (true) {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    }
}

static void test_init_ublock_009(void)

{
    int wstatus;
    int ublock_pid = fork();
    if (ublock_pid == 0) {
        uint8_t num_failures;
        ublock_fini();
        char* name = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        CU_ASSERT_EQUAL(init_ublock(name, UBLOCK_RPC_SERVER_ENABLE), 0);
        ublock_fini();
        num_failures = CU_get_number_of_failures();
        exit(num_failures);
    }
    while (true) {
        int ipid = wait(&wstatus);
        if (ipid == ublock_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    }
}

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

int main(int argc, char * *argv)
{
    CU_pSuite suite;
    CU_pTest pTest;
    int num_failures;
    CU_RunMode CUnitMode = CUNIT_SCREEN;

    if (argc > 1) {
        CUnitMode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("init_ublock.c", NULL, NULL);
    if (suite == NULL) {
        goto ERROR;
    }

    pTest = CU_ADD_TEST(suite, test_init_ublock_001);
    pTest = CU_ADD_TEST(suite, test_init_ublock_002);
    pTest = CU_ADD_TEST(suite, test_init_ublock_003);
    pTest = CU_ADD_TEST(suite, test_init_ublock_007);
    pTest = CU_ADD_TEST(suite, test_init_ublock_008);
    pTest = CU_ADD_TEST(suite, test_init_ublock_009);
    if (pTest == NULL) {
        goto ERROR;
    }

    switch (CUnitMode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("init_ublock.c");
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

