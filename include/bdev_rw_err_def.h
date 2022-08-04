/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: this is a header file of the data structure definition for LibStorage fault injection.
 * Author: louhongxiang@huawei.com
 * Create: 2018-09-01
 */

#ifndef BDEV_RW_ERR_DEFINE
#define BDEV_RW_ERR_DEFINE
#include <stdbool.h>
#include <stdint.h>

#include <sys/queue.h>

#define LIBSTORAGE_NONE_ERROR_TYPE 0
#define LIBSTORAGE_IO_TIMEOUT_ERROR_TYPE 0x1

struct libstorage_err_injc_lba {
    uint64_t lba_start;
    uint64_t lba_end;
    uint32_t io_delay_us;
    uint32_t slowio_count;
    int32_t sc;
    int32_t sct;
    SLIST_ENTRY(libstorage_err_injc_lba)
    slist;
};

struct libstorage_io_proc_error {
    bool enable;
    SLIST_HEAD(, libstorage_err_injc_lba)
    lba_range_list;
};

struct libstorage_err_injc {
    char *devname;
    uint32_t error_sc_sct_type;
    struct libstorage_io_proc_error error_disk_slow;
    struct libstorage_io_proc_error error_uncov_unc;
    struct libstorage_io_proc_error error_crc_read;
    struct libstorage_io_proc_error error_lba_read;
    struct libstorage_io_proc_error error_crc_write;
    struct libstorage_io_proc_error error_recov_unc;
    struct libstorage_io_proc_error error_status_error;
    SLIST_ENTRY(libstorage_err_injc)
    slist;
};

#endif
