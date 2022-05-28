/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: head file of IO stat
* Author: zhangsaisai
* Create: 2018-9-1
*/

#ifndef LIBSTORAGE_IOSTAT_H
#define LIBSTORAGE_IOSTAT_H

#include <inttypes.h>
#include <stdbool.h>

/* share memory file name */
#define LIBSTORAGE_STAT_SHM_FILE_NAME "libstorage_stat.shm.\
49ce4ec241e017c65812b71b9832a50865f0b7d9b4d5f18d3d03283b"

/* max number of channel+bdev */
#define STAT_MAX_NUM 8192

#define I_D_NVME_CHANNEL 0x00001
#define I_D_DEVICENAME 0x00002

/**
 * Structures for share memory I/O stats.
 * This structures is same as libstorage I/O stats
 * */
struct libstorage_bdev_io_stat {
    bool used;
    uint16_t channel_id;
    char bdev_name[STAT_NAME_LEN];
    uint64_t num_read_ops;
    uint64_t num_write_ops;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t io_outstanding;
    uint64_t read_latency_ticks;
    uint64_t write_latency_ticks;
    uint64_t io_ticks;
    bool     poll_time_used;
    uint64_t num_poll_timeout;
};

/**
 * Structures for I/O stats.
 * */
struct io_stats {
    char dev_name[STAT_NAME_LEN];
    uint64_t rd_ios;
    uint64_t wr_ios;
    uint64_t rd_bytes;
    uint64_t wr_bytes;
    uint64_t rd_ticks;
    uint64_t wr_ticks;
    uint64_t io_outstanding;
    uint64_t tot_ticks;
    bool     poll_time_used;
    uint64_t num_poll_timeout;
};

#endif
