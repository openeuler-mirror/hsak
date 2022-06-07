 /******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * hsak is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: LibStorage fault injection API.
 * Author: louhongxiang@huawei.com
 * Create: 2018-09-01
 */
#include "bdev_rw_internal.h"
#include "bdev_rw_err_injc.h"

#include "bdev_rw_err_def.h"
#include "spdk/bdev.h"
#include "spdk/nvme.h"
#include "spdk/rpc.h"
#include "spdk/util.h"

struct rpc_dev_error_info {
    char *devname;
    uint8_t type;
    uint8_t enable_flag;
    uint32_t io_delay_us;
    uint64_t lba_start;
    uint64_t lba_end;
    uint32_t slowio_count;
    int32_t sc;
    int32_t sct;
};

enum libstorage_err_injc_decode_class {
    LIBSTORAGE_ERR_INJC_DECODE_CODE = 0,
    LIBSTORAGE_ERR_INJC_DECODE_SLOW_IO = 1,
    LIBSTORAGE_ERR_INJC_DECODE_IO_PROC = 2,
    LIBSTORAGE_ERR_INJC_DECODE_ERROR_STATUS = 3
};

static const struct spdk_json_object_decoder rpc_get_dev_comp_error_decoders[] = {
    { "devname", offsetof(struct rpc_dev_error_info, devname), spdk_json_decode_string },
    { "type", offsetof(struct rpc_dev_error_info, type), spdk_json_decode_uint32 },
    { "flag", offsetof(struct rpc_dev_error_info, enable_flag), spdk_json_decode_uint32 },
};

static const struct spdk_json_object_decoder rpc_get_slow_io_error_decoders[] = {
    { "devname", offsetof(struct rpc_dev_error_info, devname), spdk_json_decode_string },
    { "type", offsetof(struct rpc_dev_error_info, type), spdk_json_decode_uint32 },
    { "flag", offsetof(struct rpc_dev_error_info, enable_flag), spdk_json_decode_uint32 },
    { "io_delay_us", offsetof(struct rpc_dev_error_info, io_delay_us), spdk_json_decode_uint32 },
    { "lba_start", offsetof(struct rpc_dev_error_info, lba_start), spdk_json_decode_uint64 },
    { "lba_end", offsetof(struct rpc_dev_error_info, lba_end), spdk_json_decode_uint64 },
    { "count", offsetof(struct rpc_dev_error_info, slowio_count), spdk_json_decode_uint32 },
};

static const struct spdk_json_object_decoder rpc_get_io_proc_error_decoders[] = {
    { "devname", offsetof(struct rpc_dev_error_info, devname), spdk_json_decode_string },
    { "type", offsetof(struct rpc_dev_error_info, type), spdk_json_decode_uint32 },
    { "flag", offsetof(struct rpc_dev_error_info, enable_flag), spdk_json_decode_uint32 },
    { "lba_start", offsetof(struct rpc_dev_error_info, lba_start), spdk_json_decode_uint64 },
    { "lba_end", offsetof(struct rpc_dev_error_info, lba_end), spdk_json_decode_uint64 },
};

static const struct spdk_json_object_decoder rpc_get_error_status_decoders[] = {
    { "devname", offsetof(struct rpc_dev_error_info, devname), spdk_json_decode_string },
    { "type", offsetof(struct rpc_dev_error_info, type), spdk_json_decode_uint32 },
    { "flag", offsetof(struct rpc_dev_error_info, enable_flag), spdk_json_decode_uint32 },
    { "lba_start", offsetof(struct rpc_dev_error_info, lba_start), spdk_json_decode_uint64 },
    { "lba_end", offsetof(struct rpc_dev_error_info, lba_end), spdk_json_decode_uint64 },
    { "sc", offsetof(struct rpc_dev_error_info, sc), spdk_json_decode_int32 },
    { "sct", offsetof(struct rpc_dev_error_info, sct), spdk_json_decode_int32 },
};

static SLIST_HEAD(, libstorage_err_injc) g_dev_err_injc_list = SLIST_HEAD_INITIALIZER(g_dev_err_injc_list);
static pthread_mutex_t g_err_injc_mutex = PTHREAD_MUTEX_INITIALIZER;

static void libstorage_err_injc_clean_lba_range_list(struct libstorage_io_proc_error *io_proc_err)
{
    struct libstorage_err_injc_lba *each_lba = NULL;

    while (!SLIST_EMPTY(&io_proc_err->lba_range_list)) {
        each_lba = (struct libstorage_err_injc_lba *)SLIST_FIRST(&io_proc_err->lba_range_list);
        SLIST_REMOVE_HEAD(&io_proc_err->lba_range_list, slist);

        free(each_lba);
        each_lba = NULL;
    }
}

void libstorage_err_injc_destory(const char *devname)
{
    struct libstorage_err_injc *err_injc = NULL;

    (void)pthread_mutex_lock(&g_err_injc_mutex);
    SLIST_FOREACH(err_injc, &g_dev_err_injc_list, slist) {
        if (strcmp(err_injc->devname, devname) == 0) {
            SLIST_REMOVE(&g_dev_err_injc_list, err_injc, libstorage_err_injc, slist);
            break;
        }
    }

    (void)pthread_mutex_unlock(&g_err_injc_mutex);
    if (err_injc == NULL) {
        return;
    }

    libstorage_err_injc_clean_lba_range_list(&err_injc->error_uncov_unc);
    libstorage_err_injc_clean_lba_range_list(&err_injc->error_crc_read);
    libstorage_err_injc_clean_lba_range_list(&err_injc->error_lba_read);
    libstorage_err_injc_clean_lba_range_list(&err_injc->error_crc_write);
    libstorage_err_injc_clean_lba_range_list(&err_injc->error_recov_unc);
    libstorage_err_injc_clean_lba_range_list(&err_injc->error_disk_slow);
    libstorage_err_injc_clean_lba_range_list(&err_injc->error_status_error);

    free(err_injc->devname);
    free(err_injc);
    return;
}

static bool libstorage_err_injc_info_exist(const char *devname)
{
    struct libstorage_err_injc *err_injc = NULL;

    /* find out if the info of "devname" is already in err_injc_list */
    SLIST_FOREACH(err_injc, &g_dev_err_injc_list, slist) {
        if (strcmp(err_injc->devname, devname) == 0) {
            return true;
        }
    }

    return false;
}

void libstorage_err_injc_init(const char *devname)
{
    size_t err_injc_len = sizeof(struct libstorage_err_injc);
    struct libstorage_err_injc *err_injc = NULL;

    (void)pthread_mutex_lock(&g_err_injc_mutex);
    /* if devname is existed then skip to init a new info to insert to list. */
    if (libstorage_err_injc_info_exist(devname)) {
        SPDK_NOTICELOG("[libstorage_err_injc] %s is already in error inject info list\n", devname);
        (void)pthread_mutex_unlock(&g_err_injc_mutex);
        return;
    }

    err_injc = (struct libstorage_err_injc *)calloc(err_injc_len, 1);
    if (err_injc == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] malloc for %s err_injc failed!\n", devname);
        (void)pthread_mutex_unlock(&g_err_injc_mutex);
        return;
    }

    err_injc->devname = strdup(devname);
    if (err_injc->devname == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] malloc for %s err_injc name failed\n", devname);
        free(err_injc);
        (void)pthread_mutex_unlock(&g_err_injc_mutex);
        return;
    }

    /* initialize for the slist of lba range. */
    SLIST_INIT(&(err_injc->error_uncov_unc.lba_range_list));
    SLIST_INIT(&(err_injc->error_lba_read.lba_range_list));
    SLIST_INIT(&(err_injc->error_crc_read.lba_range_list));
    SLIST_INIT(&(err_injc->error_crc_write.lba_range_list));
    SLIST_INIT(&(err_injc->error_recov_unc.lba_range_list));
    SLIST_INIT(&(err_injc->error_disk_slow.lba_range_list));
    SLIST_INIT(&(err_injc->error_status_error.lba_range_list));

    SLIST_INSERT_HEAD(&g_dev_err_injc_list, err_injc, slist);
    (void)pthread_mutex_unlock(&g_err_injc_mutex);

    return;
}

static struct libstorage_err_injc *libstorage_err_injc_get_err_injc(const char *devname)
{
    struct libstorage_err_injc *err_injc = NULL;

    SLIST_FOREACH(err_injc, &g_dev_err_injc_list, slist) {
        if (strcmp(err_injc->devname, devname) == 0) {
            break;
        }
    }
    return err_injc;
}

static int libstorage_err_injc_status_code_to_devfd(struct rpc_dev_error_info *error_info)
{
    struct libstorage_err_injc *err_injc = NULL;

    err_injc = libstorage_err_injc_get_err_injc(error_info->devname);
    if (err_injc == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] error injection info of %s is NULL\n", error_info->devname);
        return -1;
    }

    if (error_info->enable_flag > 1) {
        SPDK_ERRLOG("[libstorage_err_injc] error type is invalid %u\n", error_info->enable_flag);
        return -1;
    } else if (error_info->enable_flag == 1) {
        err_injc->error_sc_sct_type = error_info->type;
        return 0;
    }

    err_injc->error_sc_sct_type = 0;
    return 0;
}

static void libstorage_rpc_return_success_result(struct spdk_jsonrpc_request *request)
{
    struct spdk_json_write_ctx *w = NULL;

    /* begin to send successful response message */
    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] start to response rpc call failed!\n");
        return;
    }

    spdk_json_write_object_begin(w);

    /* return result to caller. */
    spdk_json_write_name(w, "result");
    spdk_json_write_string(w, "success");

    spdk_json_write_object_end(w);
    spdk_jsonrpc_end_result(request, w);
    return;
}

static int libstorage_parse_errorinfo(enum libstorage_err_injc_decode_class type,
                                      const struct spdk_json_val *params,
                                      struct rpc_dev_error_info *error_info)
{
    int rc;
    switch (type) {
        case LIBSTORAGE_ERR_INJC_DECODE_CODE:
            rc = spdk_json_decode_object(params,
                                         rpc_get_dev_comp_error_decoders,
                                         SPDK_COUNTOF(rpc_get_dev_comp_error_decoders),
                                         error_info);
            break;
        case LIBSTORAGE_ERR_INJC_DECODE_SLOW_IO:
            rc = spdk_json_decode_object(params,
                                         rpc_get_slow_io_error_decoders,
                                         SPDK_COUNTOF(rpc_get_slow_io_error_decoders),
                                         error_info);
            break;
        case LIBSTORAGE_ERR_INJC_DECODE_IO_PROC:
            rc = spdk_json_decode_object(params,
                                         rpc_get_io_proc_error_decoders,
                                         SPDK_COUNTOF(rpc_get_io_proc_error_decoders),
                                         error_info);
            break;
        case LIBSTORAGE_ERR_INJC_DECODE_ERROR_STATUS:
            rc = spdk_json_decode_object(params,
                                         rpc_get_error_status_decoders,
                                         SPDK_COUNTOF(rpc_get_error_status_decoders),
                                         error_info);
            break;
        default:
            SPDK_ERRLOG("[libstorage_err_injc] type is wrong\n");
            rc = -1;
    }
    return rc;
}

static struct rpc_dev_error_info *libstorage_get_error_info_decode(const struct spdk_json_val *params,
                                                                   enum libstorage_err_injc_decode_class type)
{
    int rc;
    struct rpc_dev_error_info *error_info = NULL;

    error_info = (struct rpc_dev_error_info *)malloc(sizeof(struct rpc_dev_error_info));
    if (error_info == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] cannot malloc for error info\n");
        return NULL;
    }

    error_info->devname = NULL;

    rc = libstorage_parse_errorinfo(type, params, error_info);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] type is wrong, or spdk_json_decode_object failed\n");
        goto invalid;
    }

    if (error_info->devname == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] cannot get device name from rpc remote call\n");
        goto invalid;
    }

    return error_info;

invalid:
    free(error_info);
    error_info = NULL;
    return NULL;
}

static void libstorage_free_rpc_error_injc_info(struct rpc_dev_error_info *error_info)
{
    if (error_info->devname != NULL) {
        free(error_info->devname);
        error_info->devname = NULL;
    }
    free(error_info);
}

static inline void *libstorage_injc_check_and_decode(struct spdk_jsonrpc_request *request,
                                                     const struct spdk_json_val *params,
                                                     enum libstorage_err_injc_decode_class decode_type)
{
    if (request == NULL || params == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] invalid parameters\n");
        return NULL;
    }

    return libstorage_get_error_info_decode(params, decode_type);
}

static void libstorage_err_injc_for_complete_cb(struct spdk_jsonrpc_request *request,
                                                const struct spdk_json_val *params)
{
    int rc;
    struct rpc_dev_error_info *error_info = NULL;

    error_info = libstorage_injc_check_and_decode(request, params, LIBSTORAGE_ERR_INJC_DECODE_CODE);
    if (error_info == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] decode for error info failed\n");
        goto invalid;
    }

    (void)pthread_mutex_lock(&g_err_injc_mutex);
    /* start to update error injection information in */
    rc = libstorage_err_injc_status_code_to_devfd(error_info);
    (void)pthread_mutex_unlock(&g_err_injc_mutex);

    libstorage_free_rpc_error_injc_info(error_info);

    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject error to status code returned\n");
        goto invalid;
    }

    libstorage_rpc_return_success_result(request);
    return;

invalid:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to inject error");
    return;
}
SPDK_RPC_REGISTER("error_injc_code", libstorage_err_injc_for_complete_cb, SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static void libstorage_err_injc_delete_lba(struct libstorage_io_proc_error *io_proc_err,
                                           uint64_t lba_start, uint64_t lba_end)
{
    struct libstorage_err_injc_lba *each_lba = NULL;

    SLIST_FOREACH(each_lba, &io_proc_err->lba_range_list, slist) {
        if (each_lba->lba_start != lba_start) {
            continue;
        }
        if (each_lba->lba_end == lba_end) {
            SLIST_REMOVE(&io_proc_err->lba_range_list, each_lba, libstorage_err_injc_lba, slist);
            break;
        }
    }

    if (SLIST_EMPTY(&io_proc_err->lba_range_list)) {
        io_proc_err->enable = false;
    }
    return;
}

static int libstorage_err_injc_error_to_io_proc_stru(struct libstorage_io_proc_error *io_proc_err,
                                                     struct rpc_dev_error_info *error_info)
{
    uint64_t lba_start;
    uint64_t lba_end;
    struct libstorage_err_injc_lba *lba_range = NULL;

    lba_start = error_info->lba_start;
    lba_end = error_info->lba_end;

    if (error_info->enable_flag > 2) { /* flag 2 means delete one element from the list */
        SPDK_ERRLOG("[libstorage_err_injc] invalid flag %u\n", error_info->enable_flag);
        return -1;
    }

    if (error_info->enable_flag == 2) { /* flag 2 means delete one element from the list */
        libstorage_err_injc_delete_lba(io_proc_err, error_info->lba_start, error_info->lba_end);
        return 0;
    } else if (error_info->enable_flag == 0) {
        libstorage_err_injc_clean_lba_range_list(io_proc_err);
        io_proc_err->enable = false;
        return 0;
    }

    if (lba_start > lba_end) {
        SPDK_ERRLOG("[libstorage_err_injc] lba range is invalid: %lu~%lu\n", lba_start, lba_end);
        return -1;
    }
    /* delete repeated lba range element in slist. */
    libstorage_err_injc_delete_lba(io_proc_err, error_info->lba_start, error_info->lba_end);

    lba_range = (struct libstorage_err_injc_lba *)malloc(sizeof(struct libstorage_err_injc_lba));
    if (lba_range == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] cannot malloc for lba range\n");
        return -1;
    }
    lba_range->lba_start = lba_start;
    lba_range->lba_end = lba_end;
    lba_range->io_delay_us = error_info->io_delay_us;
    lba_range->slowio_count = error_info->slowio_count;
    lba_range->sc = error_info->sc;
    lba_range->sct = error_info->sct;
    SLIST_INSERT_HEAD(&io_proc_err->lba_range_list, lba_range, slist);

    io_proc_err->enable = true;
    return 0;
}

static bool libstorage_err_injc_is_in_dif_format(const char *devname)
{
    struct spdk_nvme_ns *ns = NULL;

    ns = libstorage_get_ns_by_devname(devname);
    if (ns == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] cannot get namespace %s\n", devname);
        return false;
    }

    if (spdk_nvme_ns_get_pi_type(ns) <= SPDK_NVME_FMT_NVM_PROTECTION_DISABLE) {
        SPDK_ERRLOG("[libstorage_err_injc] %s does not enable DIF\n", devname);
        return false;
    }

    return true;
}

static int libstorage_injc_io_proc_err(struct rpc_dev_error_info *error_info, struct libstorage_err_injc *err_injc)
{
    struct libstorage_io_proc_error *io_proc_err = NULL;

    switch (error_info->type) {
        case 2: // type 2 is UNC error
            if (error_info->enable_flag == 3) { /* flag 3 means UNC error is recoverable */
                io_proc_err = &err_injc->error_recov_unc;
                error_info->enable_flag = 1;
            } else {
                io_proc_err = &err_injc->error_uncov_unc;
            }
            goto inject;
        case 9: // type 9 is read CRC error
            io_proc_err = &err_injc->error_crc_read;
            break;
        case 10: // type 10 is read LBA error
            io_proc_err = &err_injc->error_lba_read;
            break;
        case 11: // type 11 is write CRC error
            io_proc_err = &err_injc->error_crc_write;
            break;
        default:
            SPDK_ERRLOG("[libstorage_err_injc] invalid type to inject error in io process\n");
            return -1;
    }

    if (!libstorage_err_injc_is_in_dif_format(error_info->devname)) {
        SPDK_ERRLOG("[libstorage_ere_injc] %s is not in DIF enable format, cannot inject CRC errors\n",
                    error_info->devname);
        return -1;
    }

inject:
    if (libstorage_err_injc_error_to_io_proc_stru(io_proc_err, error_info) != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject type %u flag %u lba_range %lu~%lu error\n",
                    error_info->type, error_info->enable_flag, error_info->lba_start, error_info->lba_end);
        return -1;
    }

    return 0;
}

static int libstorage_err_injc_in_io_proc_to_devfd(struct rpc_dev_error_info *error_info)
{
    struct libstorage_err_injc *err_injc = NULL;

    err_injc = libstorage_err_injc_get_err_injc(error_info->devname);
    if (err_injc == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] error injection info of %s is NULL\n", error_info->devname);
        return -1;
    }

    return libstorage_injc_io_proc_err(error_info, err_injc);
}

static void libstorage_err_injc_in_io_proc(struct spdk_jsonrpc_request *request,
                                           const struct spdk_json_val *params)
{
    int rc;
    struct rpc_dev_error_info *error_info = NULL;

    error_info = libstorage_injc_check_and_decode(request, params, LIBSTORAGE_ERR_INJC_DECODE_IO_PROC);
    if (error_info == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] decode for error info failed\n");
        goto invalid;
    }

    (void)pthread_mutex_lock(&g_err_injc_mutex);
    /* start to update error injection information */
    rc = libstorage_err_injc_in_io_proc_to_devfd(error_info);
    (void)pthread_mutex_unlock(&g_err_injc_mutex);

    libstorage_free_rpc_error_injc_info(error_info);

    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject error to io process\n");
        goto invalid;
    }

    libstorage_rpc_return_success_result(request);
    return;

invalid:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to inject error");
    return;
}
SPDK_RPC_REGISTER("error_injc_io_proc", libstorage_err_injc_in_io_proc, SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static int libstorage_err_injc_slowio_to_devfd(struct rpc_dev_error_info *error_info_slowio)
{
    struct libstorage_err_injc *err_injc = NULL;
    struct libstorage_io_proc_error *io_proc_err = NULL;

    err_injc = libstorage_err_injc_get_err_injc(error_info_slowio->devname);
    if (err_injc == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] error injection info of %s is NULL\n", error_info_slowio->devname);
        return -1;
    }

    if (error_info_slowio->type != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] invalid type for inject error of slow io\n");
        return -1;
    }

    io_proc_err = &err_injc->error_disk_slow;
    if (libstorage_err_injc_error_to_io_proc_stru(io_proc_err, error_info_slowio) != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject type %u flag %u lba_range %lu~%lu error\n",
                    error_info_slowio->type,
                    error_info_slowio->enable_flag,
                    error_info_slowio->lba_start,
                    error_info_slowio->lba_end);
        return -1;
    }

    return 0;
}

static void libstorage_err_injc_slow_io(struct spdk_jsonrpc_request *request,
                                        const struct spdk_json_val *params)
{
    int rc;
    struct rpc_dev_error_info *error_info = NULL;

    error_info = libstorage_injc_check_and_decode(request, params, LIBSTORAGE_ERR_INJC_DECODE_SLOW_IO);
    if (error_info == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] decode for error info failed\n");
        goto invalid;
    }

    (void)pthread_mutex_lock(&g_err_injc_mutex);
    /* start to update error injection information */
    rc = libstorage_err_injc_slowio_to_devfd(error_info);
    (void)pthread_mutex_unlock(&g_err_injc_mutex);

    libstorage_free_rpc_error_injc_info(error_info);

    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject slow io error\n");
        goto invalid;
    }

    libstorage_rpc_return_success_result(request);
    return;

invalid:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to inject error");
    return;
}
SPDK_RPC_REGISTER("error_injc_slowio", libstorage_err_injc_slow_io, SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static int libstorage_err_injc_error_status_to_devfd(struct rpc_dev_error_info *error_info_err_status)
{
    struct libstorage_err_injc *err_injc = NULL;
    struct libstorage_io_proc_error *io_proc_err = NULL;

    err_injc = libstorage_err_injc_get_err_injc(error_info_err_status->devname);
    if (err_injc == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] error injection info of %s is NULL\n", error_info_err_status->devname);
        return -1;
    }

    if (error_info_err_status->type != 13) {
        SPDK_ERRLOG("[libstorage_err_injc] invalid type for inject error of nvme error status\n");
        return -1;
    }

    io_proc_err = &err_injc->error_status_error;
    if (libstorage_err_injc_error_to_io_proc_stru(io_proc_err, error_info_err_status) != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject type %u flag %u lba_range %lu~%lu error\n",
                    error_info_err_status->type,
                    error_info_err_status->enable_flag,
                    error_info_err_status->lba_start,
                    error_info_err_status->lba_end);
        return -1;
    }

    return 0;
}

static void libstorage_err_injc_error_status(struct spdk_jsonrpc_request *request,
                                             const struct spdk_json_val *params)
{
    int rc;
    struct rpc_dev_error_info *error_info = NULL;

    error_info = libstorage_injc_check_and_decode(request, params, LIBSTORAGE_ERR_INJC_DECODE_ERROR_STATUS);
    if (error_info == NULL) {
        SPDK_ERRLOG("[libstorage_err_injc] decode for error info failed\n");
        goto invalid;
    }

    (void)pthread_mutex_lock(&g_err_injc_mutex);
    /* start to update error injection information */
    rc = libstorage_err_injc_error_status_to_devfd(error_info);
    (void)pthread_mutex_unlock(&g_err_injc_mutex);

    libstorage_free_rpc_error_injc_info(error_info);

    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_err_injc] fail to inject slow io error\n");
        goto invalid;
    }

    libstorage_rpc_return_success_result(request);
    return;

invalid:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to inject error");
    return;
}
SPDK_RPC_REGISTER("error_injc_error_status", libstorage_err_injc_error_status, SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static void libstorage_err_injc_io_status_code(struct libstorage_err_injc *err_injc,
                                               LIBSTORAGE_IO_T *io, int32_t *bserrno, int32_t *scterrno)
{
    if (err_injc->error_sc_sct_type == LIBSTORAGE_IO_TIMEOUT_ERROR_TYPE) {
            *bserrno = (int32_t)SPDK_NVME_SC_ABORTED_BY_REQUEST;
            *scterrno = (int32_t)SPDK_NVME_SCT_GENERIC;
            return;
    }
}

static inline bool libstorage_err_injc_is_valid_lba(const struct libstorage_err_injc_lba *each_lba,
                                                    uint64_t io_offset, uint32_t nbytes)
{
    if (each_lba->lba_start > (io_offset + nbytes)) {
        return false;
    }

    if (each_lba->lba_end < io_offset) {
        return false;
    }

    return true;
}

static bool libstorage_err_injc_is_in_lba_range(struct libstorage_io_proc_error *io_proc_err, uint64_t io_offset,
                                                uint32_t nbytes, bool to_del)
{
    struct libstorage_err_injc_lba *each_lba = NULL;

    if (!io_proc_err->enable) {
        return false;
    }

    SLIST_FOREACH(each_lba, &io_proc_err->lba_range_list, slist) {
        if (libstorage_err_injc_is_valid_lba(each_lba, io_offset, nbytes)) {
            if (to_del) {
                libstorage_err_injc_delete_lba(io_proc_err, each_lba->lba_start, each_lba->lba_end);
            }

            return true;
        }
    }

    return false;
}

static uint32_t libstorage_err_injc_slow_io_delay(struct libstorage_err_injc *err_injc, LIBSTORAGE_IO_T *io)
{
    struct libstorage_io_proc_error *io_proc_err = NULL;
    struct libstorage_err_injc_lba *each_lba = NULL;
    uint32_t io_delay_us;

    io_proc_err = &err_injc->error_disk_slow;
    if (!io_proc_err->enable) {
        return 0;
    }

    SLIST_FOREACH(each_lba, &io_proc_err->lba_range_list, slist) {
        if (libstorage_err_injc_is_valid_lba(each_lba, io->offset, io->nbytes)) {
            io_delay_us = each_lba->io_delay_us;
            each_lba->slowio_count--;

            if (each_lba->slowio_count == 0) {
                libstorage_err_injc_delete_lba(io_proc_err, each_lba->lba_start, each_lba->lba_end);
            }

            return io_delay_us;
        }
    }

    return 0;
}

static void libstorage_err_injc_write_judge_lba(struct libstorage_err_injc *err_injc,
                                                LIBSTORAGE_IO_T *io, int32_t *bserrno, int32_t *scterrno)
{
    (void)libstorage_err_injc_is_in_lba_range(&err_injc->error_recov_unc, io->offset, io->nbytes, true);

    if (libstorage_err_injc_is_in_lba_range(&err_injc->error_crc_write, io->offset, io->nbytes, false)) {
        *bserrno = (int32_t)SPDK_NVME_SC_GUARD_CHECK_ERROR;
        *scterrno = (int32_t)SPDK_NVME_SCT_MEDIA_ERROR;
        SPDK_NOTICELOG("[libstorage_err_injc] offset %lu + length %u is in lba range of write crc error\n",
                       io->offset, io->nbytes);
    }
}

static void libstorage_err_injc_read_judge_lba(struct libstorage_err_injc *err_injc,
                                               LIBSTORAGE_IO_T *io, int32_t *bserrno, int32_t *scterrno)
{
    if (libstorage_err_injc_is_in_lba_range(&err_injc->error_uncov_unc, io->offset, io->nbytes, false) ||
        libstorage_err_injc_is_in_lba_range(&err_injc->error_recov_unc, io->offset, io->nbytes, false)) {
        *bserrno = (int32_t)SPDK_NVME_SC_UNRECOVERED_READ_ERROR;
        *scterrno = (int32_t)SPDK_NVME_SCT_MEDIA_ERROR;
        SPDK_NOTICELOG("[libstorage_err_injc] offset %lu + length %u is in lba range of uncov unc error\n",
                       io->offset, io->nbytes);
        return;
    }

    if (libstorage_err_injc_is_in_lba_range(&err_injc->error_crc_read, io->offset, io->nbytes, false)) {
        *bserrno = (int32_t)SPDK_NVME_SC_GUARD_CHECK_ERROR;
        *scterrno = (int32_t)SPDK_NVME_SCT_MEDIA_ERROR;
        SPDK_NOTICELOG("[libstorage_err_injc] offset %lu + length %u is in lba range of read crc error\n",
                       io->offset, io->nbytes);
        return;
    }

    if (libstorage_err_injc_is_in_lba_range(&err_injc->error_lba_read, io->offset, io->nbytes, false)) {
        *bserrno = (int32_t)SPDK_NVME_SC_REFERENCE_TAG_CHECK_ERROR;
        *scterrno = (int32_t)SPDK_NVME_SCT_MEDIA_ERROR;
        SPDK_NOTICELOG("[libstorage_err_injc] offset %lu + length %u is in lba range of read lba error\n",
                       io->offset, io->nbytes);
        return;
    }
}

static void libstorage_err_injc_io_judge_lba(struct libstorage_err_injc *err_injc,
                                             LIBSTORAGE_IO_T *io, int32_t *bserrno, int32_t *scterrno)
{
    if (io->opcode == (uint16_t)OP_WRITE || io->opcode == (uint16_t)OP_WRITEV) {
        libstorage_err_injc_write_judge_lba(err_injc, io, bserrno, scterrno);
    } else if (io->opcode == (uint16_t)OP_READ || io->opcode == (uint16_t)OP_READV) {
        libstorage_err_injc_read_judge_lba(err_injc, io, bserrno, scterrno);
    }

    return;
}

static void libstorage_err_injc_io_error_status(struct libstorage_err_injc *err_injc,
                                                LIBSTORAGE_IO_T *io, int32_t *bserrno, int32_t *scterrno)
{
    struct libstorage_io_proc_error *io_proc_err = NULL;
    struct libstorage_err_injc_lba *each_lba = NULL;

    io_proc_err = &err_injc->error_status_error;
    if (!io_proc_err->enable) {
        return;
    }

    SLIST_FOREACH(each_lba, &io_proc_err->lba_range_list, slist) {
        if (libstorage_err_injc_is_valid_lba(each_lba, io->offset, io->nbytes)) {
            *bserrno = each_lba->sc;
            *scterrno = each_lba->sct;
            return;
        }
    }
}

static void libstorage_err_injc_delay_us(uint32_t io_delay_us)
{
    uint64_t begin;
    uint64_t end;
    uint64_t ticks_hz;
    uint64_t spend_time = 0;

    begin = spdk_get_ticks();
    ticks_hz = spdk_get_ticks_hz();
    if (ticks_hz == 0) {
        SPDK_ERRLOG("[libstorage_err_injc] failed to get cpu ticks\n");
        return;
    }

    while (spend_time < io_delay_us) {
        end = spdk_get_ticks();
        if (end < begin) {
            spend_time = (((uint64_t)-1) - begin + end) * 1000000 / ticks_hz; // 1 second is 1000000 us
            continue;
        }

        spend_time = (end - begin) * 1000000 / ticks_hz; // 1 second is 1000000 us
    }

    return;
}

void libstorage_err_injc_io_process(char *devname, LIBSTORAGE_IO_T *io, int32_t *bserrno,
                                    int32_t *scterrno)
{
    uint32_t io_delay_us;
    struct libstorage_err_injc *err_injc = NULL;

    if ((bserrno == NULL) || (scterrno == NULL) || (devname == NULL) || (io == NULL)) {
        SPDK_ERRLOG("[libstorage_err_injc] invalid parameters\n");
        return;
    }

    /* this function is called in io path by reactor thread or product thread, */
    /* so there is no need to get lock. */
    (void)pthread_mutex_lock(&g_err_injc_mutex);
    err_injc = libstorage_err_injc_get_err_injc(devname);
    if (err_injc == NULL) {
        (void)pthread_mutex_unlock(&g_err_injc_mutex);
        return;
    }

    /* firstly, judge the result of io status code that returned back */
    libstorage_err_injc_io_status_code(err_injc, io, bserrno, scterrno);
    if (*bserrno != 0) {
        SPDK_NOTICELOG("[libstorage_err_injc] error of return status code is injected\n");
    }

    /* then judge the result of crc or lba error */
    libstorage_err_injc_io_judge_lba(err_injc, io, bserrno, scterrno);

    /* secondly, get nvme error status code */
    libstorage_err_injc_io_error_status(err_injc, io, bserrno, scterrno);

    /* finally, delay io to io_delay_us time */
    io_delay_us = libstorage_err_injc_slow_io_delay(err_injc, io);

    (void)pthread_mutex_unlock(&g_err_injc_mutex);

    libstorage_err_injc_delay_us(io_delay_us);
    return;
}
