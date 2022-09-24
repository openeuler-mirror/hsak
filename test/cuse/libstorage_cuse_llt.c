/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * hsak is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: test for cuse module
 * Author: suweifeng <suweifeng1@huawei.com>
 * Create: 2021-05-10
*/
#include <sys/file.h>
#include <stdlib.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

#include "bdev_rw_internal.h"

#define ID_CTRL_DATA_LEN        4096
#define LOG_PAGE_LEN            256
#define GET_SMART_LOG_CDW10     4128770
#define GET_LOG_LEN_CDW12       0x10021
#define CUSE_DEVICE_NAME        "/dev/spdk/nvme0"
#define CUSE_BLK_DEVICE_NAME    "/dev/spdk/nvme0n1"
#define ID_CTRLR_CMD_OPCODE     0x06
#define GET_SMART_LOG_OPCODE    0x02
#define SELF_DEFINE_OPCODE      0xC0
#define LPA_OFFSET              261

struct nvme_passthru_cmd {
        __u8    opcode;
        __u8    flags;
        __u16   rsvd1;
        __u32   nsid;
        __u32   cdw2;
        __u32   cdw3;
        __u64   metadata;
        __u64   addr;
        __u32   metadata_len;
        __u32   data_len;
        __u32   cdw10;
        __u32   cdw11;
        __u32   cdw12;
        __u32   cdw13;
        __u32   cdw14;
        __u32   cdw15;
        __u32   timeout_ms;
        __u32   result;
};

static __u8 g_id_ctrlr_data[ID_CTRL_DATA_LEN];
static __u8 g_log_page_data[LOG_PAGE_LEN];

struct nvme_passthru_cmd g_id_ctrlr_cmd = {
    .opcode         = ID_CTRLR_CMD_OPCODE,
    .nsid           = 0,
    .addr           = (__u64)(uintptr_t)g_id_ctrlr_data,
    .data_len       = ID_CTRL_DATA_LEN,
    .cdw10          = 1,
    .cdw11          = 0,
};

struct nvme_passthru_cmd g_get_log_page_cmd = {
    .opcode         = GET_SMART_LOG_OPCODE,
    .nsid           = 0xffffffff,
    .addr           = (__u64)(uintptr_t) g_log_page_data,
    .data_len       = LOG_PAGE_LEN,
    .cdw10          = GET_SMART_LOG_CDW10,
    .cdw11          = 0,
    .cdw12          = 0,
    .cdw13          = 0,
    .cdw14          = 0,
};

struct nvme_passthru_cmd g_get_log_len_cmd = {
    .opcode         = SELF_DEFINE_OPCODE,
    .nsid           = 0,
    .addr           = 0,
    .data_len       = 0,
    .cdw10          = 0,
    .cdw11          = 0,
    .cdw12          = GET_LOG_LEN_CDW12,
    .cdw13          = 0,
    .cdw14          = 0,
};

#define NVME_IOCTL_ADMIN_CMD    _IOWR('N', 0x41, struct nvme_passthru_cmd)

static void libstorage_cuse_config_test(void)
{
    int fd;
    int rc;
    int wstatus;
    const char* cuse_enable_file = "conf/nvme.conf.in";
    const char* cuse_disable_file = "conf/nvme.conf1.in";
    int child_pid = fork();
    if (child_pid == 0) {
        uint8_t num_failures;
        CU_ASSERT_EQUAL(libstorage_init_module(cuse_disable_file), 0);
        fd = open(CUSE_DEVICE_NAME, O_RDONLY);
        CU_ASSERT(fd < 0);
        CU_ASSERT_EQUAL(errno, ENOENT);

        fd = open(CUSE_BLK_DEVICE_NAME, O_RDONLY);
        CU_ASSERT(fd < 0);
        CU_ASSERT_EQUAL(errno, ENOENT);
        libstorage_exit_module();

        num_failures = CU_get_number_of_failures();
        char *result = CU_get_run_results_string();
        printf("%d %s\n", num_failures, result);
        fflush(stdout);
        free(result);
        exit(num_failures);
    }
    do {
        int ipid = wait(&wstatus);
        if (ipid == child_pid) {
            CU_ASSERT_EQUAL(WEXITSTATUS(wstatus), 0);
            break;
        }
    } while (true);

    CU_ASSERT_EQUAL(libstorage_init_module(cuse_enable_file), 0);

    /* open cuse device for checking */
    fd = open(CUSE_DEVICE_NAME, O_RDONLY);
    CU_ASSERT(fd > 0);
    if (fd > 0) {
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_id_ctrlr_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        close(fd);
    }

    fd = open(CUSE_BLK_DEVICE_NAME, O_RDONLY);
    if (fd > 0) {
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_id_ctrlr_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        close(fd);
    }
    libstorage_exit_module();
}

static void libstorage_cuse_get_log_test(void)
{
    int fd;
    int rc;

    /* get identifiy ctlr data */
    fd = open(CUSE_BLK_DEVICE_NAME, O_RDONLY);
    if (fd > 0) {
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_id_ctrlr_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        close(fd);
    }

    if (g_id_ctrlr_data[LPA_OFFSET] <= 1) {
        return;
    }

    /* open cuse device for get log */
    fd = open(CUSE_DEVICE_NAME, O_RDONLY);
    if (fd > 0) {
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_get_log_page_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_get_log_len_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        close(fd);
    }

    fd = open(CUSE_BLK_DEVICE_NAME, O_RDONLY);
    if (fd > 0) {
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_get_log_page_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &g_get_log_len_cmd);
        CU_ASSERT_EQUAL(rc, 0);
        close(fd);
    }
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

    suite_startup = CU_add_suite("libstorage_cuse_test", NULL, NULL);
    if (suite_startup == NULL) {
        goto ERROR;
    }

    if (CU_ADD_TEST(suite_startup, libstorage_cuse_config_test) == NULL ||
        CU_ADD_TEST(suite_startup, libstorage_cuse_get_log_test) == NULL) {
        goto ERROR;
    }

    switch (CUnitMode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("bdev_rw_comon.c");
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

