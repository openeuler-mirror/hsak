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
 * Description: test for io read/write
 * Author: suweifeng <suweifeng1@huawei.com>
 * Create: 2020-08-28
*/
#include <sys/file.h>
#include "bdev_rw_internal.h"

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

#define NVME_DEV        "nvme0n1"
#define IO_SIZE         (64 * 1024)
#define BLOCK_CNT       (64 * 2)        /* BLOCK_CNT = IO_SIZE/BLOCK_SIZE */
#define IOV_CNT         3
#define SLEEP_US        100             /* sleep in us */

struct io_status {
    bool done;
    bool rc;
};

static void test_libstorage_sync_rw_smoke(void)
{
    int fd = libstorage_open(NVME_DEV);
    CU_ASSERT_NOT_EQUAL(fd, 0);
    void *io_buf = libstorage_alloc_io_buf(IO_SIZE);
    if (io_buf == NULL) {
        libstorage_close(fd);
        CU_ASSERT(false);
        return;
    }
    /* correct parameter */
    CU_ASSERT_EQUAL(libstorage_sync_read(fd, io_buf, IO_SIZE, 0), 0);
    CU_ASSERT_EQUAL(libstorage_sync_write(fd, io_buf, IO_SIZE, IO_SIZE), 0);
    /* incorrect parameter */
    CU_ASSERT_NOT_EQUAL(libstorage_sync_read(fd, NULL, IO_SIZE, 0), 0);
    CU_ASSERT_NOT_EQUAL(libstorage_sync_write(fd, NULL, IO_SIZE, 0), 0);
    CU_ASSERT_NOT_EQUAL(libstorage_sync_read(fd, io_buf, 0, 0), 0);
    CU_ASSERT_NOT_EQUAL(libstorage_sync_write(fd, io_buf, 0, 0), 0);
    CU_ASSERT_NOT_EQUAL(libstorage_sync_read(fd, io_buf, IO_SIZE, INT_MAX), 0);
    CU_ASSERT_NOT_EQUAL(libstorage_sync_write(fd, io_buf, IO_SIZE, INT_MAX), 0);

    CU_ASSERT_EQUAL(libstorage_close(fd), 0);
}

static void io_complete_callback(int32_t cb_status, int32_t sct_code, void* cb_arg)
{
    struct io_status *status = (struct io_status *)cb_arg;
    if (cb_status == 0) {
        status->rc = true;
    } else {
        status->rc = false;
    }
    status->done = true;
}

static void wait_io_complete(int fd, struct io_status *status)
{
    status->done = false;
    while (status->done == false) {
        usleep(SLEEP_US);
    }
}

static void test_libstorage_async_rw_smoke(void)
{
    int fd = libstorage_open(NVME_DEV);
    CU_ASSERT_NOT_EQUAL(fd, 0);
    void *io_buf = libstorage_alloc_io_buf(IO_SIZE);
    if (io_buf == NULL) {
        libstorage_close(fd);
        CU_ASSERT(false);
        return;
    }
    struct io_status complete_status;
    /* correct parameter */
    CU_ASSERT_EQUAL(libstorage_async_read(fd, io_buf, IO_SIZE, 0, NULL, 0,
                                          LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                          io_complete_callback, &complete_status), 0);
    wait_io_complete(fd, &complete_status);
    CU_ASSERT_EQUAL(complete_status.rc, true);
    CU_ASSERT_EQUAL(libstorage_async_write(fd, io_buf, IO_SIZE, IO_SIZE, NULL, 0,
                                           LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                           io_complete_callback, &complete_status), 0);
    wait_io_complete(fd, &complete_status);
    CU_ASSERT_EQUAL(complete_status.rc, true);
    /* incorrect parameter */
    CU_ASSERT_NOT_EQUAL(libstorage_async_write(fd, NULL, IO_SIZE, IO_SIZE, NULL, 0,
                                               LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                               io_complete_callback, &complete_status), 0);
    CU_ASSERT_NOT_EQUAL(libstorage_async_read(fd, NULL, IO_SIZE, IO_SIZE, NULL, 0,
                                              LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                              io_complete_callback, &complete_status), 0);

    CU_ASSERT_EQUAL(libstorage_close(fd), 0);
}

static void test_libstorage_async_rw_v_smoke(void)
{
    int fd = libstorage_open(NVME_DEV);
    CU_ASSERT_NOT_EQUAL(fd, 0);
    struct io_status complete_status;
    struct libstorage_dsm_range_desc *range;
    struct libstorage_namespace_info *ns_info;

    struct iovec *iov = malloc(sizeof(struct iovec) * IOV_CNT);
    CU_ASSERT_NOT_EQUAL(iov, NULL);
    range = malloc(sizeof(struct libstorage_dsm_range_desc) * IOV_CNT);
    for (int i = 0; i < IOV_CNT; i++) {
        iov[i].iov_base = libstorage_alloc_io_buf(IO_SIZE);
        iov[i].iov_len = IO_SIZE;
        memset_s(iov[i].iov_base, IO_SIZE, i, IO_SIZE);
        range[i].lba = i * BLOCK_CNT;
        range[i].block_count = BLOCK_CNT;
    }

    CU_ASSERT_EQUAL(libstorage_get_bdev_ns_info(NVME_DEV, &ns_info), 0);
    if (ns_info->dsm) {
        CU_ASSERT_EQUAL(libstorage_deallocate_block(fd, range, IOV_CNT, io_complete_callback, &complete_status), 0);
        wait_io_complete(fd, &complete_status);
        CU_ASSERT_EQUAL(complete_status.rc, true);
    }
    free(ns_info);

    CU_ASSERT_EQUAL(libstorage_async_writev(fd, iov, IOV_CNT, IO_SIZE * IOV_CNT, 0, NULL, 0,
                                            LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK,
                                            io_complete_callback, &complete_status), 0);
    wait_io_complete(fd, &complete_status);
    CU_ASSERT_EQUAL(complete_status.rc, true);

    CU_ASSERT_EQUAL(libstorage_async_readv(fd, iov, IOV_CNT, IO_SIZE * IOV_CNT, 0, NULL, 0,
                                           LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK, io_complete_callback,
                                           &complete_status), 0);

    wait_io_complete(fd, &complete_status);
    CU_ASSERT_EQUAL(complete_status.rc, true);
    uint8_t *data = iov[1].iov_base;
    CU_ASSERT_EQUAL(data[IO_SIZE - 1], 1);

    CU_ASSERT_EQUAL(libstorage_async_writev(fd, iov, IOV_CNT, IO_SIZE * IOV_CNT + 1, 0, NULL, 0,
                                                LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK, 
                                                io_complete_callback, &complete_status), 0);
    wait_io_complete(fd, &complete_status);
    CU_ASSERT_EQUAL(complete_status.rc, false);

    CU_ASSERT_EQUAL(libstorage_async_readv(fd, iov, IOV_CNT - 1, IO_SIZE * IOV_CNT, 0, NULL, 0,
                                               LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK, io_complete_callback,
                                               &complete_status), 0);
    wait_io_complete(fd, &complete_status);
    CU_ASSERT_EQUAL(complete_status.rc, true);

    for (int i = 0; i < IOV_CNT; i++) {
        libstorage_free_io_buf(iov[i].iov_base, iov[i].iov_len);
    }
    free(iov);
    free(range);
    CU_ASSERT_EQUAL(libstorage_close(fd), 0);
}

static int suite_pre_test(void)
{
    const char* cfgfile = "conf/nvme.conf1.in";
    return libstorage_init_module(cfgfile);
}

static int suite_post_test(void)
{
    return libstorage_exit_module();
}

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} CU_RunMode;

int main(int argc, char **argv)
{
    CU_pSuite suite, suite_startup;
    unsigned int num_failures;
    CU_RunMode CUnitMode = CUNIT_SCREEN;

    if (argc > 1) {
        CUnitMode = atoi(argv[1]);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite_startup = CU_add_suite("libstorage_io_rw_test", suite_pre_test, suite_post_test);
    if (suite_startup == NULL) {
        goto ERROR;
    }

    if (CU_ADD_TEST(suite_startup, test_libstorage_sync_rw_smoke) == NULL ||
        CU_ADD_TEST(suite_startup, test_libstorage_async_rw_smoke) == NULL ||
        CU_ADD_TEST(suite_startup, test_libstorage_async_rw_v_smoke) == NULL) {
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

