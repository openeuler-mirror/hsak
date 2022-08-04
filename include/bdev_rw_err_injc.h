/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: this is a header file of the function declaration for LibStorage fault injection.
 * Author: louhongxiang@huawei.com
 * Create: 2018-09-01
 */

#ifndef LIBSTORAGE_ERROR_INJECT_H
#define LIBSTORAGE_ERROR_INJECT_H

#include "bdev_rw_internal.h"

void libstorage_err_injc_init(const char *devname);
void libstorage_err_injc_destory(const char *devname);
void libstorage_err_injc_io_process(char *devname, LIBSTORAGE_IO_T *io, int32_t *bserrno, int32_t *scterrno);
#endif
