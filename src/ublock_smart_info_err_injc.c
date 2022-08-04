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
 * Description: ublock smart info
 * Author: louhongxiang
 * Create: 2018-9-1
 */

#include <stdlib.h>
#include <pthread.h>
#include <spdk/log.h>
#include <spdk/rpc.h>
#include <spdk/util.h>
#include <stdint.h>  /* for uint64_t */

#include "ublock.h"
#include "ublock_internal.h"

#define SMART_INFO_CRITICAL_TEMPERATURE 1
#define SMART_INFO_CRITICAL_AVAILABLE_SPARE 0
#define SMART_INFO_CRITICAL_VOLATILE_MEM 4
#define SMART_INFO_CRITICAL_SIGNI_ERROR 2
#define SMART_INFO_CRITICAL_READ_ONLY 3

struct ublock_error_info {
    char *pci;
    uint8_t err_flag;
    uint8_t percentage_used;
    uint64_t unsafe_shutdowns;
    uint64_t media_errors;
    SLIST_ENTRY(ublock_error_info)
    slist;
};

static const struct spdk_json_object_decoder rpc_error_inject_decoders[] = {
    {
        "pci",
        offsetof(struct ublock_error_info, pci),
        spdk_json_decode_string,
    },
    { "type", offsetof(struct ublock_error_info, err_flag), spdk_json_decode_uint32 },
    { "per_used", offsetof(struct ublock_error_info, percentage_used), spdk_json_decode_uint32 },
    { "shutdowns", offsetof(struct ublock_error_info, unsafe_shutdowns), spdk_json_decode_uint64 },
    { "media_errors", offsetof(struct ublock_error_info, media_errors), spdk_json_decode_uint64 },
};

static SLIST_HEAD(, ublock_error_info) g_ublock_error_info_list = SLIST_HEAD_INITIALIZER(g_ublock_error_info_list);

static void ublock_rpc_error_inject_smart_info(struct spdk_jsonrpc_request *request,
    const struct spdk_json_val *params)
{
    struct ublock_error_info *error_info = NULL;
    struct ublock_error_info *each_err_info = NULL;
    struct spdk_json_write_ctx *w = NULL;

    if (request == NULL || params == NULL) {
        SPDK_ERRLOG("[ublock] ublock decode rpc invalid parameters\n");
        return;
    }

    error_info = (struct ublock_error_info *)malloc(sizeof(struct ublock_error_info));
    if (error_info == NULL) {
        SPDK_ERRLOG("[ublock] fail to malloc for error info to decode\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        return;
    }

    /* string pointer will be freed in spdk_json_decode_string() without judgement */
    /* assign pci string pointer to NULL incase the memory malloced is illegal and not NULL */
    error_info->pci = NULL;
    if (spdk_json_decode_object(params,
                                rpc_error_inject_decoders,
                                SPDK_COUNTOF(rpc_error_inject_decoders),
                                error_info)) {
        SPDK_ERRLOG("[ublock] spdk_json_decode_object for error info failed\n");
        ublock_client_safe_free((void **)&error_info->pci);
        ublock_client_safe_free((void **)&error_info);
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_PARSE_ERROR, "Fail to decode request");
        return;
    }
    SPDK_NOTICELOG("[ublock] smart error inject: %s -t %d -p %d -D %lu -M %lu\n",
                   error_info->pci,
                   error_info->err_flag,
                   error_info->percentage_used,
                   error_info->unsafe_shutdowns,
                   error_info->media_errors);

    SLIST_FOREACH(each_err_info, &g_ublock_error_info_list, slist) {
        /* check for updating error injection information. */
        /* because it will not inject several smart error at the same time. */
        if (strcmp(each_err_info->pci, error_info->pci) == 0) {
            each_err_info->err_flag = error_info->err_flag;
            /* only error injection of percentage_used will use this field. */
            /* other error injections will ignore this field. */
            each_err_info->percentage_used = error_info->percentage_used;
            each_err_info->unsafe_shutdowns = error_info->unsafe_shutdowns;
            each_err_info->media_errors = error_info->media_errors;
            ublock_client_safe_free((void **)&error_info->pci);
            ublock_client_safe_free((void **)&error_info);
            goto end;
        }
    }

    SLIST_INSERT_HEAD(&g_ublock_error_info_list, error_info, slist);

end:
    /* begin to send successful response message */
    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[ublock]start to response rpc call failed!\n");
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
UBLOCK_RPC_REGISTER("smart_error_inject", ublock_rpc_error_inject_smart_info)


static void set_read_only(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->critical_warning = 1 << SMART_INFO_CRITICAL_READ_ONLY;
}

static void set_percentage_used(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    if (each_err_info->percentage_used == 0) {
        return;
    }
    smart_info->percentage_used = each_err_info->percentage_used;
}

static void set_critical_temp(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->critical_warning = 1 << SMART_INFO_CRITICAL_TEMPERATURE;
    smart_info->temperature = 500; /* set temperature to 500 */
}

static void set_available_space(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->critical_warning = 1 << SMART_INFO_CRITICAL_AVAILABLE_SPARE;
    smart_info->available_spare = 0;
    smart_info->available_spare_threshold = 10; /* set available threshold to 10 */
}

static void set_volatile_memory(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->critical_warning = 1 << SMART_INFO_CRITICAL_VOLATILE_MEM;
}

static void set_signiture_error(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->critical_warning = 1 << SMART_INFO_CRITICAL_SIGNI_ERROR;
}

static void set_unsafe_shutdowns_count(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->unsafe_shutdowns[0] = each_err_info->unsafe_shutdowns;
}

static void set_media_errors_count(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    smart_info->media_errors[0] = each_err_info->media_errors;
}

static void set_default(struct ublock_SMART_info *smart_info, struct ublock_error_info *each_err_info)
{
    SPDK_ERRLOG("error flag is invalid\n");
}

typedef void (*inject_smart_info_set_func)(struct ublock_SMART_info *, struct ublock_error_info *);

#define MAX_INJ_SMART_SET_FUNCS_COUNTS 16 /* max 16 functions */

void ublock_error_inject_smart_info(const char *pci, struct ublock_SMART_info *smart_info)
{
    struct ublock_error_info *each_err_info = NULL;
    inject_smart_info_set_func set_funcs[MAX_INJ_SMART_SET_FUNCS_COUNTS] = {set_default, /* 0 */
                                                                            set_default, /* 1 */
                                                                            set_default, /* 2 */
                                                                            set_read_only, /* 3 */
                                                                            set_percentage_used, /* 4 */
                                                                            set_critical_temp, /* 5 */
                                                                            set_available_space, /* 6 */
                                                                            set_volatile_memory, /* 7 */
                                                                            set_signiture_error, /* 8 */
                                                                            set_default, /* 9 */
                                                                            set_default, /* 10 */
                                                                            set_default, /* 11 */
                                                                            set_default, /* 12 */
                                                                            set_default, /* 13 */
                                                                            set_unsafe_shutdowns_count, /* 14 */
                                                                            set_media_errors_count}; /* 15 */

    if (pci == NULL || smart_info == NULL) {
        SPDK_ERRLOG("invalid parameters to inject error in smart info.\n");
        return;
    }

    SLIST_FOREACH(each_err_info, &g_ublock_error_info_list, slist) {
        /* find device to inject error by pci address */
        if (strcmp(each_err_info->pci, pci) != 0) {
            continue;
        }
        if (each_err_info->err_flag == 0) {
            break;
        }

        if (each_err_info->err_flag >= MAX_INJ_SMART_SET_FUNCS_COUNTS) {
            set_default(NULL, NULL);
            continue;
        }

        set_funcs[each_err_info->err_flag](smart_info, each_err_info);
    }

    return;
}

void ublock_error_inject_print_smart_info(const struct ublock_SMART_info *smart_info)
{
    if (smart_info == NULL) {
        SPDK_ERRLOG("[ublock_err_injc] invalid parameter");
        return;
    }
    syslog(LOG_USER | LOG_INFO, "critical_warning:    %d\n", smart_info->critical_warning);
    syslog(LOG_USER | LOG_INFO, "temperature:         %d\n", smart_info->temperature);
    syslog(LOG_USER | LOG_INFO, "available_spare:     %d\n", smart_info->available_spare);
    syslog(LOG_USER | LOG_INFO, "available_spare_threshold:  %d\n", smart_info->available_spare_threshold);
    syslog(LOG_USER | LOG_INFO, "percentage_used      %d\n", smart_info->percentage_used);
    syslog(LOG_USER | LOG_INFO, "data_units_read      %lu\n", smart_info->data_units_read[0]);
    syslog(LOG_USER | LOG_INFO, "data_units_written   %lu\n", smart_info->data_units_written[0]);
    syslog(LOG_USER | LOG_INFO, "controller_busy_time %lu\n", smart_info->controller_busy_time[0]);
    syslog(LOG_USER | LOG_INFO, "power_cycles         %lu\n", smart_info->power_cycles[0]);
    syslog(LOG_USER | LOG_INFO, "unsafe_shutdowns     %lu\n", smart_info->unsafe_shutdowns[0]);
    syslog(LOG_USER | LOG_INFO, "media_errors         %lu\n", smart_info->media_errors[0]);
}

