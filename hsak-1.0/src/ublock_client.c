/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: ublock prc client
* Author: zhoupengchen
* Create: 2018-9-1
*/

#include <spdk/log.h>
#include <spdk/util.h>
#include <spdk/base64.h>
#include <stddef.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "ublock.h"
#include "ublock_internal.h"

#define UBLOCK_CLIENT_GET_SMART "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\
\"get_smart\",\"params\":{\"pci\":\"%s\",\"nsid\": %u}}"

#define UBLOCK_CLIENT_GET_INFO "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"get_info\",\"params\":{\"pci\":\"%s\"}}"

#define UBLOCK_CLIENT_GET_SMART_LOCAL_RPC "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\
\"get_smart_info\",\"params\":{\"pci\":\"%s\",\"nsid\": %u}}"

#define UBLOCK_CLIENT_GET_INFO_LOCAL_RPC "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"get_bdev_info\",\"params\":{\"pci\":\"%s\"}}"

#define UBLOCK_CLIENT_GET_ERROR_LOG_LOCAL_RPC "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\
\"get_error_log_info\",\"params\":{\"pci\":\"%s\",\"err_entries\": %u}}"

#define UBLOCK_CLIENT_GET_ERROR_LOG "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\
\"get_error_log\",\"params\":{\"pci\":\"%s\",\"err_entries\": %u}}"

#define UBLOCK_CLIENT_RESET_DISK "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"reset_ctrlr\",\"params\":{\"pci\":\"%s\"}}"

#define UBLOCK_CLIENT_RESET_DISK_LOCAL_RPC "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"reset_ctrlr_local\",\"params\":{\"pci\":\"%s\"}}"

#define UBLOCK_CLIENT_ENABLE_IOSTAT "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"enable_iostat\",\"params\":{\"pci\":\"%s\",\"iostat_enable\": %d}}"

#define UBLOCK_CLIENT_QUERY_LOG_PAGE "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"query_log_page\",\"params\":{\"pci\":\"%s\",\"nsid\": %u,\"pageid\": %u,\"size\": %u}}"

#define UBLOCK_CLIENT_ADMIN_PASSTHRU "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"admin_passthru\",\"params\":{\"pci\":\"%s\",\"nbytes\": %d,\"cmd\":\"%s\"}}"

#define UBLOCK_CLIENT_ADMIN_PASSTHRU_LOCAL_RPC "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"admin_passthru_local\",\"params\":{\"pci\":\"%s\",\"nbytes\": %d,\"cmd\":\"%s\"}}"

#define UBLOCK_JSON_PARSE_INCOMPLETE (-2)

#define UBLOCK_RPC_CLIENT_TIMEOUT 10

/* define 511 because the buffer malloced by ublock_client_send_prepare is (cmd_len + 1) */
#define UBLOCK_CLIENT_RPC_CMD_LEN_MAX 511

void ublock_client_safe_free(void **ptr)
{
    if (ptr == NULL || *ptr == NULL) {
        return;
    }
    free(*ptr);
    *ptr = NULL;
}

static int ublock_client_conn_setopt(int sockfd, struct sockaddr_un client_addr_unix)
{
    int rc;
    struct timeval timeout = { UBLOCK_RPC_CLIENT_TIMEOUT, 0 };

    /* set client socket send time out in UBLOCK_RPC_CLIENT_TIMEOUT second */
    rc = setsockopt(sockfd,
                    SOL_SOCKET,
                    SO_SNDTIMEO,
                    (const char *)&timeout,
                    sizeof(timeout));
    if (rc < 0) {
        SPDK_ERRLOG("[ublock] fail to set the sending timeout\n");
        return -1;
    }
    /* set client socket recv time out in UBLOCK_RPC_CLIENT_TIMEOUT second */
    rc = setsockopt(sockfd,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    (const char *)&timeout,
                    sizeof(timeout));
    if (rc < 0) {
        SPDK_ERRLOG("[ublock] fail to set the reciving timeout\n");
        return -1;
    }

    rc = connect(sockfd,
                 (struct sockaddr *)&client_addr_unix,
                 sizeof(client_addr_unix));
    if (rc < 0) {
        SPDK_ERRLOG("[ublock] fail to connect socket address, errno is %d\n", errno);
        return -1;
    }

    return 0;
}

int ublock_client_conn(const char *listen_addr)
{
    if (listen_addr == NULL) {
        SPDK_ERRLOG("[ublock] fail to listen at an empty address\n");
        return -1;
    }
    int sockfd = -1;
    struct sockaddr_un client_addr_unix = {0x0};
    int rc;

    if (listen_addr[0] != '/') {
        SPDK_ERRLOG("[ublock] error socket address\n");
        return -1;
    }

    sockfd = socket(AF_UNIX, (int)SOCK_STREAM, 0);
    if (sockfd < 0) {
        SPDK_ERRLOG("[ublock] socket() failed\n");
        return -1;
    }
    client_addr_unix.sun_family = AF_UNIX;
    rc = snprintf_s(client_addr_unix.sun_path,
                    sizeof(client_addr_unix.sun_path),
                    strlen(UBLOCK_RPC_ADDR),
                    "%s",
                    listen_addr);
    if (rc < 0 || (size_t)rc >= sizeof(client_addr_unix.sun_path)) {
        SPDK_ERRLOG("[ublock] RPC Listen address Unix socket path too long\n");
        client_addr_unix.sun_path[0] = '\0';
        close(sockfd);
        return -1;
    }
    if (ublock_client_conn_setopt(sockfd, client_addr_unix) == -1) {
        SPDK_ERRLOG("[ublock] fail to connect socket address %s\n", listen_addr);
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/* json parse bdev info */
struct _ublock_bdev_info {
    uint64_t ctrlr; /* nvme ctrlr pointer value */
    uint64_t sector_size;
    uint64_t cap_size; /* cap_size */
    uint32_t md_size;
    uint16_t device_id;
    uint16_t subsystem_device_id; /* subsystem device id of nvme control */
    uint16_t vendor_id;
    uint16_t subsystem_vendor_id;
    uint16_t controller_id;
    char *serial_number;
    char *model_number;
    char *firmware_revision;
};

struct ublock_rpc_info {
    char *jsonrpc;
    int id;
    struct _ublock_bdev_info result;
};

static const struct spdk_json_object_decoder info_decoders[] = {
    {
        "ctrlr",
        offsetof(struct _ublock_bdev_info, ctrlr),
        spdk_json_decode_uint64,
    },
    {
        "sector_size",
        offsetof(struct _ublock_bdev_info, sector_size),
        spdk_json_decode_uint64,
    },
    {
        "cap_size",
        offsetof(struct _ublock_bdev_info, cap_size),
        spdk_json_decode_uint64,
    },
    {
        "md_size",
        offsetof(struct _ublock_bdev_info, md_size),
        spdk_json_decode_uint32,
    },
    {
        "device_id",
        offsetof(struct _ublock_bdev_info, device_id),
        spdk_json_decode_uint32,
    },
    {
        "subsystem_device_id",
        offsetof(struct _ublock_bdev_info, subsystem_device_id),
        spdk_json_decode_uint32,
    },
    {
        "vendor_id",
        offsetof(struct _ublock_bdev_info, vendor_id),
        spdk_json_decode_uint32,
    },
    {
        "subsystem_vendor_id",
        offsetof(struct _ublock_bdev_info, subsystem_vendor_id),
        spdk_json_decode_uint32,
    },
    {
        "controller_id",
        offsetof(struct _ublock_bdev_info, controller_id),
        spdk_json_decode_uint32,
    },
    {
        "serial_number",
        offsetof(struct _ublock_bdev_info, serial_number),
        spdk_json_decode_string,
    },
    {
        "model_number",
        offsetof(struct _ublock_bdev_info, model_number),
        spdk_json_decode_string,
    },
    {
        "firmware_revision",
        offsetof(struct _ublock_bdev_info, firmware_revision),
        spdk_json_decode_string,
    },

};

static int ublock_decode_info(const struct spdk_json_val *val, void *out)
{
    struct _ublock_bdev_info *dev_info = out;

    return spdk_json_decode_object(val, info_decoders,
                                   SPDK_COUNTOF(info_decoders), dev_info);
}

static const struct spdk_json_object_decoder parse_info_decoders[] = {
    {
        "jsonrpc",
        offsetof(struct ublock_rpc_info, jsonrpc),
        spdk_json_decode_string,
    },
    {
        "id",
        offsetof(struct ublock_rpc_info, id),
        spdk_json_decode_int32,
    },
    {
        "result",
        offsetof(struct ublock_rpc_info, result),
        ublock_decode_info,
    },
};

static int ublock_parse_rpcinfo(uint8_t *buf, ssize_t buf_len, struct ublock_rpc_info *result)
{
    void *end = NULL;
    int rc;
    struct spdk_json_val *values = NULL;

    values = (struct spdk_json_val *)calloc(SPDK_JSONRPC_MAX_VALUES, sizeof(struct spdk_json_val));
    if (values == NULL) {
        SPDK_ERRLOG("[ublock] init values failed!\n");
        return -1;
    }

    spdk_json_parse(buf, buf_len, values,
                    SPDK_JSONRPC_MAX_VALUES, &end,
                    SPDK_JSON_PARSE_FLAG_DECODE_IN_PLACE);

    if (values[0].type == SPDK_JSON_VAL_ARRAY_BEGIN) {
        SPDK_ERRLOG("[ublock] Got batch array (not currently supported)\n");
        free(values);
        return -1;
    } else if (values[0].type != SPDK_JSON_VAL_OBJECT_BEGIN) {
        SPDK_ERRLOG("[ublock] top-level JSON value was not array or object\n");
        free(values);
        return -1;
    }

    rc = spdk_json_decode_object(values, parse_info_decoders,
                                 SPDK_COUNTOF(parse_info_decoders),
                                 result);
    free(values);
    return rc;
}

static int ublock_rpcinfo_to_bdevinfo(const struct ublock_rpc_info *result, struct ublock_bdev *out)
{
    int rc;

    out->ctrlr = (struct spdk_nvme_ctrlr *)result->result.ctrlr;
    out->info.sector_size = result->result.sector_size;
    out->info.cap_size = result->result.cap_size;
    out->info.md_size = result->result.md_size;
    out->info.vendor_id = result->result.vendor_id;
    out->info.device_id = result->result.device_id;
    out->info.subsystem_device_id = result->result.subsystem_device_id;
    out->info.subsystem_vendor_id = result->result.subsystem_vendor_id;
    out->info.controller_id = result->result.controller_id;
    rc = memcpy_s(&(out->info.serial_number[0]),
                  sizeof(out->info.serial_number),
                  result->result.serial_number,
                  strlen(result->result.serial_number));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memcpy failed!\n");
        return rc;
    }
    rc = memcpy_s(&(out->info.model_number[0]),
                  sizeof(out->info.model_number),
                  result->result.model_number,
                  strlen(result->result.model_number));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memcpy failed!\n");
        return rc;
    }
    rc = memcpy_s(&(out->info.firmware_revision[0]),
                  sizeof(out->info.firmware_revision),
                  result->result.firmware_revision,
                  strlen(result->result.firmware_revision));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memcpy failed!\n");
        return rc;
    }

    return 0;
}

static int ublock_parse_bdevinfo(uint8_t *buf, ssize_t buf_len, struct ublock_bdev *out)
{
    struct ublock_rpc_info result = {0x0};
    int rc;

    if (buf == NULL || out == NULL) {
        SPDK_ERRLOG("[ublock] ublock_parser_bdevinfo get NULL parameter\n");
        return -1;
    }

    rc = ublock_parse_rpcinfo(buf, buf_len, &result);
    if (rc == -1) {
        SPDK_ERRLOG("[ublock] decode error\n");
        goto out_func;
    }

    rc = ublock_rpcinfo_to_bdevinfo(&result, out);
    if (rc != 0) {
        goto out_func;
    }

out_func:
    ublock_client_safe_free((void **)&result.jsonrpc);
    ublock_client_safe_free((void **)&result.result.serial_number);
    ublock_client_safe_free((void **)&result.result.model_number);
    ublock_client_safe_free((void **)&result.result.firmware_revision);

    return rc;
}

struct _ublock_SMART_info {
    char *smart_str;
    size_t smart_len;
};

struct ublock_rpc_SMART_info {
    char *jsonrpc;
    int id;
    struct _ublock_SMART_info result;
};

static const struct spdk_json_object_decoder ublock_json_SMART_str_decoders[] = {
    {
        "smart_str",
        offsetof(struct _ublock_SMART_info, smart_str),
        spdk_json_decode_string,
    },
    {
        "smart_len",
        offsetof(struct _ublock_SMART_info, smart_len),
        spdk_json_decode_int32,
    },
};

static int ublock_json_decode_SMART_info(const struct spdk_json_val *val, void *out)
{
    struct _ublock_SMART_info *smart_str = out;

    return spdk_json_decode_object(val, ublock_json_SMART_str_decoders,
                                   SPDK_COUNTOF(ublock_json_SMART_str_decoders), smart_str);
}

static const struct spdk_json_object_decoder parse_SMART_info_decoders[] = {
    {
        "jsonrpc",
        offsetof(struct ublock_rpc_SMART_info, jsonrpc),
        spdk_json_decode_string,
    },
    {
        "id",
        offsetof(struct ublock_rpc_SMART_info, id),
        spdk_json_decode_int32,
    },
    {
        "result",
        offsetof(struct ublock_rpc_SMART_info, result),
        ublock_json_decode_SMART_info,
    },
};

static void ublock_free_smart_parse_info(struct ublock_rpc_SMART_info *result)
{
    if (result == NULL) {
        return;
    }
    ublock_client_safe_free((void **)(&(result->jsonrpc)));
    ublock_client_safe_free((void **)(&(result->result.smart_str)));

    return;
}

static int ublock_check_full_value(uint8_t *buf, ssize_t buf_len, void *end, int max_values_size)
{
    int rc;

    rc = spdk_json_parse(buf, buf_len, NULL, 0, &end, 0);
    if (rc == UBLOCK_JSON_PARSE_INCOMPLETE) {
        SPDK_ERRLOG("[ublock] Receive SMART info response failed, the response message is not complete\n");
        return -1;
    } else if (rc < 0 || rc > max_values_size) {
        SPDK_ERRLOG("[ublock] JSON parse error\n");
        /*
         * Can't recover from parse error (no guaranteed resync point in streaming JSON).
         * Return an error to indicate that the connection should be closed.
         */
        return -1;
    }
    return rc;
}

static int ublock_spdk_json_parse(uint8_t *buf, ssize_t buf_len, struct spdk_json_val *values, int max_values_size)
{
    int rc;
    void *end = NULL;

    if (values == NULL) {
        return -1;
    }
    /* Check to see if we have received a full JSON value. */
    rc = ublock_check_full_value(buf, buf_len, end, max_values_size);
    if (rc < 0) {
        return rc;
    }

    /* Decode a second time now that there is a full JSON value available. */
    rc = spdk_json_parse(buf, buf_len, values, max_values_size, &end, SPDK_JSON_PARSE_FLAG_DECODE_IN_PLACE);
    if (rc < 0 || rc > max_values_size) {
        SPDK_ERRLOG("[ublock] JSON parse error on second pass\n");
        return -1;
    }

    if (values[0].type == SPDK_JSON_VAL_ARRAY_BEGIN) {
        SPDK_ERRLOG("[ublock] Got batch array (not currently supported)\n");
        return -1;
    } else if (values[0].type != SPDK_JSON_VAL_OBJECT_BEGIN) {
        SPDK_ERRLOG("[ublock] top-level JSON value was not array or object\n");
        return -1;
    }

    return 0;
}

int ublock_parse_smart(uint8_t *buf, ssize_t buf_len, struct ublock_SMART_info *out)
{
    int rc;
    char *str_for_smart_info = NULL;
    struct spdk_json_val *values = NULL;

    values = (struct spdk_json_val *)calloc(SPDK_JSONRPC_MAX_VALUES, sizeof(struct spdk_json_val));
    if (values == NULL) {
        SPDK_ERRLOG("[ublock] fail to init values");
        return -1;
    }

    if (ublock_spdk_json_parse(buf, buf_len, values, SPDK_JSONRPC_MAX_VALUES) != 0) {
        free(values);
        return -1;
    }

    struct ublock_rpc_SMART_info result = {0x0};
    rc = spdk_json_decode_object(values, parse_SMART_info_decoders,
                                 SPDK_COUNTOF(parse_SMART_info_decoders), &result);
    if (rc == -1) {
        SPDK_ERRLOG("[ublock] decode error\n");
        goto out_func;
    }

    str_for_smart_info = (char *)malloc(sizeof(char) * (UBLOCK_SMART_INFO_LEN * 2)); /* 2 times of mem to store */
    if (str_for_smart_info == NULL) {
        SPDK_ERRLOG("[ublock] malloc strinf mem error\n");
        rc = -1;
        goto out_func;
    }

    result.result.smart_str[result.result.smart_len] = '\0';
    rc = memset_s(str_for_smart_info, UBLOCK_SMART_INFO_LEN * 2, /* 2 times of mem to store */
                  0, UBLOCK_SMART_INFO_LEN * 2); /* 2 times of mem to store */
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memset failed!\n");
        goto out_func;
    }
    rc = spdk_base64_decode(str_for_smart_info, &result.result.smart_len, result.result.smart_str);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] base64 decode fail\n");
        goto out_func;
    }

    rc = memcpy_s((char *)out, UBLOCK_SMART_INFO_LEN, str_for_smart_info, UBLOCK_SMART_INFO_LEN);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memcpy failed!\n");
    }

out_func:
    ublock_client_safe_free((void **)(&str_for_smart_info));
    ublock_free_smart_parse_info(&result);
    free(values);
    return rc;
}

/* json parse error log info */
struct _ublock_nvme_error_information_entry {
    uint64_t error_count;
    uint16_t sqid;
    uint16_t cid;
    uint16_t status;
    uint16_t error_location;
    uint64_t lba;
    uint32_t nsid;
    uint8_t vendor_specific;
};

struct ublock_rpc_error_log_array {
    size_t error_entries;
    struct _ublock_nvme_error_information_entry errs[UBLOCK_RPC_ERROR_LOG_MAX_COUNT];
};

struct ublock_rpc_errlog_infos {
    struct ublock_rpc_error_log_array error_info;
};

struct ublock_rpc_errlog_total_info {
    char *jsonrpc;
    int id;
    struct ublock_rpc_errlog_infos result;
};

static const struct spdk_json_object_decoder errs_decoders[] = {
    {
        "error_count",
        offsetof(struct _ublock_nvme_error_information_entry, error_count),
        spdk_json_decode_uint64,
    },
    {
        "sqid",
        offsetof(struct _ublock_nvme_error_information_entry, sqid),
        spdk_json_decode_uint32,
    },
    {
        "cid",
        offsetof(struct _ublock_nvme_error_information_entry, cid),
        spdk_json_decode_uint32,
    },
    {
        "status",
        offsetof(struct _ublock_nvme_error_information_entry, status),
        spdk_json_decode_uint32,
    },
    {
        "error_location",
        offsetof(struct _ublock_nvme_error_information_entry, error_location),
        spdk_json_decode_uint32,
    },
    {
        "lba",
        offsetof(struct _ublock_nvme_error_information_entry, lba),
        spdk_json_decode_uint64,
    },
    {
        "nsid",
        offsetof(struct _ublock_nvme_error_information_entry, nsid),
        spdk_json_decode_uint32,
    },
    {
        "vendor_specific",
        offsetof(struct _ublock_nvme_error_information_entry, vendor_specific),
        spdk_json_decode_uint32,
    },
};

static int ublock_json_decode_errs(const struct spdk_json_val *val, void *out)
{
    struct _ublock_nvme_error_information_entry *errs = (struct _ublock_nvme_error_information_entry *)out;
    if (spdk_json_decode_object(val, errs_decoders, SPDK_COUNTOF(errs_decoders), errs)) {
        SPDK_ERRLOG("spdk_json_decode_object failed\n");
        return -1;
    }
    return 0;
}

static int ublock_json_decode_errlog_info(const struct spdk_json_val *val, void *out)
{
    if (val == NULL || out == NULL) {
        return -1;
    }
    size_t max_size;
    struct ublock_rpc_error_log_array *rpc_errlog_info = (struct ublock_rpc_error_log_array *)out;

    /* for this array, an element is an object. */
    /* an object contains '{','}' and 8 pairs of spdk_json_value like "id":0. */
    /* so the max size is max count of object multiply the total number of containers in an object upabove. */
    max_size = UBLOCK_RPC_ERROR_LOG_MAX_COUNT * (SPDK_COUNTOF(errs_decoders) * 2 + 2); /* 2 times of mem to store */
    return spdk_json_decode_array(val, ublock_json_decode_errs, &rpc_errlog_info->errs, max_size,
                                  &rpc_errlog_info->error_entries,
                                  sizeof(struct _ublock_nvme_error_information_entry));
}

static const struct spdk_json_object_decoder errlog_infos_decoders[] = {
    {
        "error_info",
        offsetof(struct ublock_rpc_errlog_infos, error_info),
        ublock_json_decode_errlog_info,
    },
};

static int ublock_json_decode_errlog_total_info(const struct spdk_json_val *val, void *out)
{
    if (val == NULL || out == NULL) {
        return -1;
    }
    struct ublock_rpc_errlog_infos *rpc_errlog_infos = out;

    return spdk_json_decode_object(val, errlog_infos_decoders,
                                     SPDK_COUNTOF(errlog_infos_decoders), rpc_errlog_infos);
}

static const struct spdk_json_object_decoder errlog_total_info_decoders[] = {
    {
        "jsonrpc",
        offsetof(struct ublock_rpc_errlog_total_info, jsonrpc),
        spdk_json_decode_string,
    },
    {
        "id",
        offsetof(struct ublock_rpc_errlog_total_info, id),
        spdk_json_decode_int32,
    },
    {
        "result",
        offsetof(struct ublock_rpc_errlog_total_info, result),
        ublock_json_decode_errlog_total_info,
    },
};

static void ublock_free_error_log_parse_info(struct ublock_rpc_errlog_total_info *total_info)
{
    if (total_info == NULL) {
        return;
    }
    ublock_client_safe_free((void **)(&(total_info->jsonrpc)));
    return;
}

static int ublock_parse_err_log_obj_begin(struct spdk_json_val *values, struct ublock_nvme_error_info **tmp_out)
{
    uint32_t err_index;
    struct ublock_rpc_errlog_total_info *total_info = NULL;
    uint32_t error_entries;
    int rc;
    struct ublock_nvme_error_info *tmp = NULL;
    struct ublock_nvme_error_info *tmp_ptr = NULL;

    if (tmp_out == NULL) {
        return -1;
    }

    total_info = (struct ublock_rpc_errlog_total_info *)calloc(1, /* mem to store */
                                                               sizeof(struct ublock_rpc_errlog_total_info));
    if (total_info == NULL) {
        SPDK_ERRLOG("[ublock] fail to init total_info\n");
        return -1;
    }

    rc = spdk_json_decode_object(values, errlog_total_info_decoders, SPDK_COUNTOF(errlog_total_info_decoders),
                                   total_info);
    if (rc < 0) {
        SPDK_ERRLOG("[ublock] decode error\n");
        ublock_free_error_log_parse_info(total_info);
        free(total_info);
        return -1;
    }

    error_entries = total_info->result.error_info.error_entries;

    if (error_entries == 0) {
        SPDK_ERRLOG("[ublock] error_entries is 0\n");
        ublock_free_error_log_parse_info(total_info);
        free(total_info);
        return -1;
    }
    tmp = (struct ublock_nvme_error_info *)malloc(sizeof(struct ublock_nvme_error_info) * error_entries);
    if (tmp == NULL) {
        SPDK_ERRLOG("[ublock] malloc error\n");
        ublock_free_error_log_parse_info(total_info);
        free(total_info);
        return -1;
    }

    *tmp_out = tmp;
    rc = memset_s(tmp,
                  sizeof(struct ublock_nvme_error_info) * error_entries,
                  0,
                  sizeof(struct ublock_nvme_error_info) * error_entries);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memset failed\n");
        ublock_free_error_log_parse_info(total_info);
        free(total_info);
        free(tmp);
        *tmp_out = NULL;
        return -1;
    }

    for (err_index = 0; err_index < error_entries; err_index++) {
        tmp_ptr = tmp + err_index;
        tmp_ptr->error_count = total_info->result.error_info.errs[err_index].error_count;
        tmp_ptr->sqid = total_info->result.error_info.errs[err_index].sqid;
        tmp_ptr->cid = total_info->result.error_info.errs[err_index].cid;
        tmp_ptr->status = total_info->result.error_info.errs[err_index].status;
        tmp_ptr->error_location = total_info->result.error_info.errs[err_index].error_location;
        tmp_ptr->lba = total_info->result.error_info.errs[err_index].lba;
        tmp_ptr->nsid = total_info->result.error_info.errs[err_index].nsid;
        tmp_ptr->vendor_specific = total_info->result.error_info.errs[err_index].vendor_specific;
    }

    ublock_free_error_log_parse_info(total_info);
    free(total_info);
    return (int)err_index;
}

int ublock_parse_err_log(uint8_t *buf, ssize_t buf_len, struct ublock_nvme_error_info **out)
{
    int rc;
    /* error log page may return with too many values, so double size the 'values' for this situation. */
    struct spdk_json_val *values = NULL;
    struct ublock_nvme_error_info **tmp_out = out;

    values = (struct spdk_json_val *)calloc(SPDK_JSONRPC_MAX_VALUES * 2, /* 2 times of mem to store */
                                            sizeof(struct spdk_json_val));
    if (values == NULL) {
        SPDK_ERRLOG("[ublock] fail to init values\n");
        return -1;
    }

    rc = ublock_spdk_json_parse(buf, buf_len, values, SPDK_JSONRPC_MAX_VALUES * 2); /* 2 times of mem to store */
    if (rc < 0) {
        free(values);
        return -1;
    }

    rc = ublock_parse_err_log_obj_begin(values, tmp_out);
    free(values);
    return rc;
}

int ublock_client_send(int sockfd, const char *req,
                       size_t req_len, uint8_t *out)
{
    if (req == NULL) {
        SPDK_ERRLOG("[ublock] empty request\n");
        return -1;
    }

    ssize_t rc;
    ssize_t recv_len;
    int send_again = 0;
    int recv_again = 0;
    bool need_reoperate = false;

retry_send:
    rc = send(sockfd, req, req_len, 0);
    if (rc < 0) {
        need_reoperate = ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                          && send_again == 0);
        /* try to send again only once for the following error number */
        if (need_reoperate) {
            send_again = 1;
            SPDK_WARNLOG("[ublock] cmd_string %s send errno %d, retry\n", req, errno);
            goto retry_send;
        }

        SPDK_ERRLOG("[ublock] cmd_string %s send errno %d, return\n", req, errno);
        return -1;
    }

retry_recv:
    recv_len = recv(sockfd, out, SPDK_JSONRPC_RECV_BUF_SIZE, 0);
    if (recv_len < 0) {
        need_reoperate = ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                         && recv_again == 0);
        /* try to recv again only once for the following error number */
        if (need_reoperate) {
            recv_again = 1;
            SPDK_WARNLOG("[ublock] cmd_string %s recv errno %d, retry\n", req, errno);
            goto retry_recv;
        }

        SPDK_ERRLOG("[ublock] cmd_string %s recv errno %d, return\n", req, errno);
        return -1;
    }
    if (recv_len >= SPDK_JSONRPC_RECV_BUF_SIZE) {
        SPDK_ERRLOG("[ublock] recv buf too long\n");
        return -1;
    }

    return (int)recv_len;
}

typedef enum ublock_client_cmd_type {
    UBLOCK_CLIENT_CMD_TYPE_QUERY_INFO,
    UBLOCK_CLIENT_CMD_TYPE_QUERY_INFO_LOCAL_RPC,
    UBLOCK_CLIENT_CMD_TYPE_QUERY_SMART_INFO,
    UBLOCK_CLIENT_CMD_TYPE_QUERY_SMART_INFO_LOCAL_RPC,
    UBLOCK_CLIENT_CMD_TYPE_QUERY_ERR_LOG,
    UBLOCK_CLIENT_CMD_TYPE_QUERY_ERR_LOG_LOCAL_RPC,
    UBLOCK_CLIENT_CMD_TYPE_RESET_DISK,
    UBLOCK_CLIENT_CMD_TYPE_RESET_DISK_LOCAL_RPC,
    UBLOCK_CLIENT_CMD_TYPE_IOSTAT_ENABLE,
    UBLOCK_CLIENT_CMD_TYPE_QUERY_LOG_PAGE,
    UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU,
    UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU_LOCAL_RPC
}UBLOCK_CLIENT_CMD_TYPE_E;

struct ublock_client_cmd_params	{
    const char *pci;
    UBLOCK_CLIENT_CMD_TYPE_E type;
    size_t cmd_len;
    uint32_t param1;
    uint32_t param2;
    uint32_t param3;
    uint64_t param4;
};

static void ublock_client_snprint_cmd(struct ublock_client_cmd_params *cmd_params,
                                      char *cmd_string)
{
    int rc = 0;
    UBLOCK_CLIENT_CMD_TYPE_E i;
    bool found_type = false;

    if (cmd_params == NULL || cmd_params->pci == NULL || cmd_string == NULL) {
        SPDK_ERRLOG("[ublock] ublock_client_snprint_cmd invalid params\n");
        return;
    }
    char client_cmd_string[][UBLOCK_CLIENT_RPC_CMD_LEN_MAX] = {
        UBLOCK_CLIENT_GET_INFO,
        UBLOCK_CLIENT_GET_INFO_LOCAL_RPC,
        UBLOCK_CLIENT_GET_SMART,
        UBLOCK_CLIENT_GET_SMART_LOCAL_RPC,
        UBLOCK_CLIENT_GET_ERROR_LOG,
        UBLOCK_CLIENT_GET_ERROR_LOG_LOCAL_RPC,
        UBLOCK_CLIENT_RESET_DISK,
        UBLOCK_CLIENT_RESET_DISK_LOCAL_RPC,
        UBLOCK_CLIENT_ENABLE_IOSTAT,
        UBLOCK_CLIENT_QUERY_LOG_PAGE,
        UBLOCK_CLIENT_ADMIN_PASSTHRU,
        UBLOCK_CLIENT_ADMIN_PASSTHRU_LOCAL_RPC
    };

    for (i = UBLOCK_CLIENT_CMD_TYPE_QUERY_INFO; i <= UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU_LOCAL_RPC; i++) {
        if (i != cmd_params->type) {
            continue;
        }
        if (i >= UBLOCK_CLIENT_CMD_TYPE_QUERY_SMART_INFO && i <= UBLOCK_CLIENT_CMD_TYPE_QUERY_ERR_LOG_LOCAL_RPC) {
            rc = snprintf_s(cmd_string, cmd_params->cmd_len + 1, cmd_params->cmd_len,
                            client_cmd_string[cmd_params->type], cmd_params->pci, cmd_params->param1);
        } else if (i == UBLOCK_CLIENT_CMD_TYPE_IOSTAT_ENABLE) {
            rc = snprintf_s(cmd_string, cmd_params->cmd_len + 1, cmd_params->cmd_len,
                            client_cmd_string[cmd_params->type], cmd_params->pci, (int)(cmd_params->param1));
        } else if (i == UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU ||
                   i == UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU_LOCAL_RPC) {
            rc = snprintf_s(cmd_string, cmd_params->cmd_len + 1, cmd_params->cmd_len,
                            client_cmd_string[cmd_params->type], cmd_params->pci,
                            (size_t)(cmd_params->param1), (char *)(cmd_params->param4));
        } else if (i == UBLOCK_CLIENT_CMD_TYPE_QUERY_LOG_PAGE) {
            rc = snprintf_s(cmd_string, cmd_params->cmd_len + 1, cmd_params->cmd_len,
                            client_cmd_string[cmd_params->type], cmd_params->pci,
                            cmd_params->param1, cmd_params->param2, cmd_params->param3);
        } else {
            rc = snprintf_s(cmd_string, cmd_params->cmd_len + 1, cmd_params->cmd_len,
                            client_cmd_string[cmd_params->type], cmd_params->pci);
        }
        found_type = true;
        break;
    }

    if (!found_type) {
        SPDK_ERRLOG("[ublock] not supported cmd type\n");
    }

    if (rc < 0) {
        SPDK_ERRLOG("[ublock] snprintf failed\n");
    }
}

/* ublock client might send to LibStorage UIO RPC server and LibStorage Ublock RPC server, */
/* this function use flg to identify which one is to send. */
/* 1. rpc_flg = 0, LibStorage UIO RPC Server */
/* 2. rpc_flg != 0, LibStorage Ublock RPC Server */
static ssize_t ublock_client_send_prepare(enum ublock_query_type rpc_flg, uint8_t **buf,
                                          struct ublock_client_cmd_params *cmd_params)
{
    int fd = -1;
    ssize_t buf_len;
    char *cmd_string = NULL;
    char *sock_addr = NULL;

    if (cmd_params == NULL || cmd_params->pci == NULL || buf == NULL) {
        return 0;
    }

    if (rpc_flg == REMOTE_RPC_QUERY) {
        sock_addr = ublock_get_sockaddr(cmd_params->pci);
        if (sock_addr == NULL) {
            SPDK_ERRLOG("[ublock] unknow socket address of plog_server: %s\n", cmd_params->pci);
            return 0;
        }
    } else {
        sock_addr = (char *)malloc(strlen(UBLOCK_RPC_ADDR) + 1);
        if (sock_addr == NULL) {
            SPDK_ERRLOG("[ublock] fail to malloc ublock rpc socket adress\n");
            return 0;
        }
        if (strcpy_s(sock_addr, strlen(UBLOCK_RPC_ADDR) + 1, UBLOCK_RPC_ADDR) != 0) {
            ublock_client_safe_free((void **)(&sock_addr));
            SPDK_ERRLOG("[ublock] strcpy failed!\n");
            return 0;
        }
    }

    fd = ublock_client_conn(sock_addr);
    if (fd == -1) {
        SPDK_ERRLOG("[ublock] fail to connect socket address: %s\n", sock_addr);
        ublock_client_safe_free((void **)(&sock_addr));
        return 0;
    }
    ublock_client_safe_free((void **)(&sock_addr));

    cmd_string = (char *)calloc(cmd_params->cmd_len + 1, sizeof(char));
    if (cmd_string == NULL) {
        close(fd);
        SPDK_ERRLOG("[ublock] fail to malloc cmd string\n");
        return 0;
    }

    ublock_client_snprint_cmd(cmd_params, cmd_string);

    *buf = (uint8_t *)malloc(SPDK_JSONRPC_RECV_BUF_SIZE);
    if (*buf == NULL) {
        ublock_client_safe_free((void **)(&cmd_string));
        close(fd);
        SPDK_ERRLOG("[ublock] fail to malloc buf\n");
        return 0;
    }

    if (memset_s(*buf, SPDK_JSONRPC_RECV_BUF_SIZE, 0, SPDK_JSONRPC_RECV_BUF_SIZE) != 0) {
        close(fd);
        ublock_client_safe_free((void **)buf);
        ublock_client_safe_free((void **)(&cmd_string));
        SPDK_ERRLOG("[ublock] memset failed!\n");
        return 0;
    }

    buf_len = ublock_client_send(fd, cmd_string, strlen(cmd_string), *buf);

    ublock_client_safe_free((void **)(&cmd_string));
    close(fd);

    if (buf_len <= 0) {
        SPDK_ERRLOG("[ublock] fail to send to socket address\n");
        ublock_client_safe_free((void **)buf);
        return 0;
    }

    return buf_len;
}

/* remote query device info */
int ublock_client_queryinfo(enum ublock_query_type rpc_flg, const char *pci, struct ublock_bdev *bdev)
{
    if (pci == NULL || bdev == NULL) {
        SPDK_ERRLOG("[ublock] error(NULL) input parameter\n");
        return -1;
    }

    int rc = 0;
    uint8_t *buf = NULL;
    ssize_t buf_len;
    struct ublock_client_cmd_params cmd_params;

    cmd_params.pci = pci;
    cmd_params.cmd_len = UBLOCK_CLIENT_RPC_CMD_LEN_MAX;
    if (rpc_flg == REMOTE_RPC_QUERY) {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_INFO;
    } else {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_INFO_LOCAL_RPC;
    }

    buf_len = ublock_client_send_prepare(rpc_flg, &buf, &cmd_params);
    if (buf_len == 0) {
        return -1;
    }

    rc += memset_s(bdev, sizeof(struct ublock_bdev), 0, sizeof(struct ublock_bdev));
    rc += memcpy_s(bdev->pci, UBLOCK_PCI_ADDR_MAX_LEN, pci, strlen(pci));
    if (rc == 0) {
        rc = ublock_parse_bdevinfo(buf, buf_len, bdev);
    }

    ublock_client_safe_free((void **)(&buf));

    if (rc != 0) {
        SPDK_ERRLOG("[ublock] client query info failed!\n");
    }

    return rc;
}

/* remote query smart info */
int ublock_client_querySMARTinfo(enum ublock_query_type rpc_flg, const char *pci, uint32_t nsid,
                                 struct ublock_SMART_info *smart_info)
{
    if (pci == NULL || smart_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameter\n");
        return -1;
    }
    int rc;
    uint8_t *buf = NULL;
    ssize_t buf_len;
    struct ublock_client_cmd_params cmd_params;

    cmd_params.pci = pci;
    cmd_params.cmd_len = UBLOCK_CLIENT_RPC_CMD_LEN_MAX;
    cmd_params.param1 = nsid;
    if (rpc_flg == REMOTE_RPC_QUERY) {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_SMART_INFO;
    } else {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_SMART_INFO_LOCAL_RPC;
    }

    buf_len = ublock_client_send_prepare(rpc_flg, &buf, &cmd_params);
    if (buf_len == 0) {
        return -1;
    }

    rc = memset_s(smart_info, sizeof(struct ublock_SMART_info), 0, sizeof(struct ublock_SMART_info));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memset failed!\n");
        goto out_func;
    }
    rc = ublock_parse_smart(buf, buf_len, smart_info);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fail to parse SMART info\n");
        goto out_func;
    }

out_func:
    ublock_client_safe_free((void **)(&buf));
    return rc;
}

/* remote query error log info */
int ublock_client_query_err_log_info(enum ublock_query_type rpc_flg, const char *pci,
                                     uint32_t err_entries_arg,
                                     struct ublock_nvme_error_info *error_log_info)
{
    int32_t err_index;
    int32_t err_entries;
    ssize_t buf_len;
    uint8_t *buf = NULL;
    struct ublock_nvme_error_info *out = NULL;
    struct ublock_client_cmd_params cmd_params;

    if (pci == NULL || error_log_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    cmd_params.pci = pci;
    cmd_params.cmd_len = UBLOCK_CLIENT_RPC_CMD_LEN_MAX;
    cmd_params.param1 = err_entries_arg;
    if (rpc_flg == REMOTE_RPC_QUERY) {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_ERR_LOG;
    } else {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_ERR_LOG_LOCAL_RPC;
    }

    buf_len = ublock_client_send_prepare(rpc_flg, &buf, &cmd_params);
    if (buf_len == 0) {
        return -1;
    }
    err_entries = ublock_parse_err_log(buf, buf_len, &out);
    ublock_client_safe_free((void **)(&buf));
    if (err_entries == -1) {
        SPDK_ERRLOG("[ublock] fail to parse bdevinfo\n");
        return -1;
    }

    if (memset_s(error_log_info, sizeof(struct ublock_nvme_error_info) * err_entries,
                 0, sizeof(struct ublock_nvme_error_info) * err_entries) != 0) {
        SPDK_ERRLOG("[ublock] memset failed!\n");
        ublock_client_safe_free((void **)(&out));
        return -1;
    }
    for (err_index = 0; err_index < err_entries; err_index++) {
        error_log_info[err_index].error_count = out[err_index].error_count;
        error_log_info[err_index].sqid = out[err_index].sqid;
        error_log_info[err_index].cid = out[err_index].cid;
        error_log_info[err_index].status = out[err_index].status;
        error_log_info[err_index].error_location = out[err_index].error_location;
        error_log_info[err_index].lba = out[err_index].lba;
        error_log_info[err_index].nsid = out[err_index].nsid;
        error_log_info[err_index].vendor_specific = out[err_index].vendor_specific;
    }

    ublock_client_safe_free((void **)(&out));

    /* return the actual count of error log entries. */
    return err_entries;
}

static int ublock_parse_iostat_info(const char *buf, const char *pci)
{
    int rc;

    if (strstr(buf, "Invalid parameters") != NULL) {
        rc = -1;
        SPDK_ERRLOG("[ublock] iostat remote invalid parameters\n");
    } else if (strstr(buf, "enable-pci-exist") != NULL) {
        rc = (int)UBLOCK_IOSTAT_ENABLE_PCI_VALID;
#ifdef DEBUG
        SPDK_NOTICELOG("[ublock] iostat remote status is enable, pci %s is exist\n", pci);
#endif
    } else if (strstr(buf, "enable-pci-invalid") != NULL) {
        rc = (int)UBLOCK_IOSTAT_ENABLE_PCI_INVALID;
#ifdef DEBUG
        SPDK_NOTICELOG("[ublock] iostat remote status is enable, pci %s is invalid\n", pci);
#endif
    } else if (strstr(buf, "disable-pci-exist") != NULL) {
        rc = (int)UBLOCK_IOSTAT_DISABLE_PCI_VALID;
#ifdef DEBUG
        SPDK_NOTICELOG("[ublock] iostat remote status is disable, pci %s is exist\n", pci);
#endif
    } else if (strstr(buf, "disable-pci-invalid") != NULL) {
        rc = (int)UBLOCK_IOSTAT_DISABLE_PCI_INVALID;
#ifdef DEBUG
        SPDK_NOTICELOG("[ublock] iostat remote status is disable, pci %s is invalid\n", pci);
#endif
    } else {
        rc = -1;
        SPDK_ERRLOG("[ublock] iostat rpc remote fail\n");
    }

    return rc;
}

/* remote set and query iostat switch */
int ublock_client_iostat_enable(const char *pci, int iostat_enable)
{
    if (pci == NULL) {
        SPDK_ERRLOG("[ublock] ublock_client_iostat_enable failed for pci is NULL\n");
        return -1;
    }

    int rc;
    uint8_t *buf = NULL;
    ssize_t buf_len;
    /* add pci param */
    struct ublock_client_cmd_params cmd_params;

    cmd_params.pci = pci;
    cmd_params.cmd_len = UBLOCK_CLIENT_RPC_CMD_LEN_MAX;
    cmd_params.param1 = (uint32_t)iostat_enable;
    cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_IOSTAT_ENABLE;

    buf_len = ublock_client_send_prepare(REMOTE_RPC_QUERY, &buf, &cmd_params);
    if (buf == NULL || buf_len == 0) {
        return -1;
    }
    rc = ublock_parse_iostat_info((const char *)buf, pci);
    ublock_client_safe_free((void **)(&buf));

    return rc;
}

struct ublock_log_page_result {
    char *log_page;
    uint32_t log_page_len;
};

struct ublock_rpc_log_page {
    char *jsonrpc;
    int id;
    struct ublock_log_page_result result;
};

static const struct spdk_json_object_decoder ublock_json_log_page_decoders[] = {
    {
        "log_page",
        offsetof(struct ublock_log_page_result, log_page),
        spdk_json_decode_string,
    },
    {
        "log_page_len",
        offsetof(struct ublock_log_page_result, log_page_len),
        spdk_json_decode_uint32,
    },
};

static int ublock_json_decode_log_page_info(const struct spdk_json_val *val, void *out)
{
    struct ublock_log_page_result *log_page_str = out;
    return spdk_json_decode_object(val, ublock_json_log_page_decoders,
                                     SPDK_COUNTOF(ublock_json_log_page_decoders), log_page_str);
}

static const struct spdk_json_object_decoder parse_log_page_info_decoders[] = {
    {
        "jsonrpc",
        offsetof(struct ublock_rpc_log_page, jsonrpc),
        spdk_json_decode_string,
    },
    {
        "id",
        offsetof(struct ublock_rpc_log_page, id),
        spdk_json_decode_int32,
    },
    {
        "result",
        offsetof(struct ublock_rpc_log_page, result),
        ublock_json_decode_log_page_info,
    },
};

static int ublock_parse_log_page(uint8_t *buf, ssize_t buf_len, uint8_t *out)
{
    int rc;
    struct spdk_json_val *values = NULL;
    struct ublock_rpc_log_page result = {0};
    char *str_for_log_page_info = NULL;
    size_t decode_len;

    values = (struct spdk_json_val *)calloc(SPDK_JSONRPC_MAX_VALUES * 2, /* 2 times of mem to store */
                                            sizeof(struct spdk_json_val));
    if (values == NULL) {
        SPDK_ERRLOG("[ublock] fail to init values\n");
        return -1;
    }

    rc = ublock_spdk_json_parse(buf, buf_len, values, SPDK_JSONRPC_MAX_VALUES * 2); /* 2 times of mem to store */
    if (rc < 0) {
        free(values);
        return -1;
    }

    rc = spdk_json_decode_object(values, parse_log_page_info_decoders,
                                   SPDK_COUNTOF(parse_log_page_info_decoders), &result);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] decode error\n");
        goto out_func;
    }

    str_for_log_page_info = (char *)malloc((size_t)buf_len); /* buf_len > raw len */
    if (str_for_log_page_info == NULL) {
        SPDK_ERRLOG("[ublock] memory malloc failed!\n");
        rc = -1;
        goto out_func;
    }
    rc = spdk_base64_decode(str_for_log_page_info, (size_t *)&result.result.log_page_len, result.result.log_page);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] base64 decode fail\n");
        goto out_func;
    }

    decode_len = spdk_base64_get_decoded_len(result.result.log_page_len);

    rc = memcpy_s(out, decode_len, str_for_log_page_info, decode_len);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] memcpy failed!\n");
    }

out_func:
    ublock_client_safe_free((void **)&result.jsonrpc);
    ublock_client_safe_free((void **)&result.result.log_page);
    ublock_client_safe_free((void **)&str_for_log_page_info);
    ublock_client_safe_free((void **)&values);
    return rc;
}

int ublock_client_query_log_page_info(enum ublock_query_type rpc_flg, struct rpc_log_page *rpc_param)
{
    uint8_t *buf = NULL;
    ssize_t buf_len;
    int rc;
    struct ublock_client_cmd_params cmd_params;

    cmd_params.pci = rpc_param->pci;
    cmd_params.cmd_len = UBLOCK_CLIENT_RPC_CMD_LEN_MAX;
    cmd_params.param1 = rpc_param->nsid;
    cmd_params.param2 = rpc_param->log_page;
    cmd_params.param3 = rpc_param->payload_size;
    cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_QUERY_LOG_PAGE;

    buf_len = ublock_client_send_prepare(rpc_flg, &buf, &cmd_params);
    if (buf == NULL || buf_len == 0) {
        SPDK_ERRLOG("[ublock]query_log_page_info failed! buflen:%ld\n", buf_len);
        return -1;
    }

    rc = ublock_parse_log_page(buf, buf_len, rpc_param->payload);
    ublock_client_safe_free((void **)(&buf));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fail to parse log page\n");
        return -1;
    }

    return 0;
}

struct _ublock_admin_resp {
    char *admin_resp;
};

struct ublock_rpc_admin_resp {
    char *jsonrpc;
    int  id;
    struct _ublock_admin_resp result;
};

static const struct spdk_json_object_decoder ublock_admin_resp_decoders[] = {
    {
        "admin_resp",
        offsetof(struct _ublock_admin_resp, admin_resp),
        spdk_json_decode_string,
    }
};

static int ublock_json_decode_admin_resp(const struct spdk_json_val *val, void *out)
{
    struct _ublock_admin_resp *admin_resp = out;

    return spdk_json_decode_object(val, ublock_admin_resp_decoders,
                                   SPDK_COUNTOF(ublock_admin_resp_decoders), admin_resp);
};

static const struct spdk_json_object_decoder parse_admin_resp_decoders[] = {
    {
        "jsonrpc",
        offsetof(struct ublock_rpc_admin_resp, jsonrpc),
        spdk_json_decode_string,
    },
    {
        "id",
        offsetof(struct ublock_rpc_admin_resp, id),
        spdk_json_decode_int32,
    },
    {
        "result",
        offsetof(struct ublock_rpc_admin_resp, result),
        ublock_json_decode_admin_resp,
    },
};

static void ublock_free_admin_resp(struct ublock_rpc_admin_resp *result)
{
    if (result == NULL) {
        return;
    }
    ublock_client_safe_free((void **)(&(result->jsonrpc)));
    ublock_client_safe_free((void **)(&(result->result.admin_resp)));

    return;
}

static int ublock_parse_admin_resp(uint8_t *buf, size_t *buf_len, void *out)
{
    int rc;
    struct spdk_json_val *values = NULL;
    struct ublock_rpc_admin_resp result = {0x0};

    values = (struct spdk_json_val *)calloc(SPDK_JSONRPC_MAX_VALUES,
                                            sizeof(struct spdk_json_val));
    if (values == NULL) {
        SPDK_ERRLOG("[ublock] fail to init values\n");
        return -1;
    }

    if (ublock_spdk_json_parse(buf, (ssize_t)*buf_len, values, SPDK_JSONRPC_MAX_VALUES) != 0) {
        rc = -1;
        goto out;
    }

    rc = spdk_json_decode_object(values, parse_admin_resp_decoders,
                                 SPDK_COUNTOF(parse_admin_resp_decoders), &result);
    if (rc == -1) {
        SPDK_ERRLOG("[ublock] decode error\n");
        goto out1;
    }

    rc = spdk_base64_decode(out, buf_len, result.result.admin_resp);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] base64 decode fail\n");
    }

out1:
    ublock_free_admin_resp(&result);
out:
    free(values);
    return rc;
}

int32_t ublock_client_nvme_admin_passthru(enum ublock_query_type rpc_flg, const char *pci,
                                          void *cmd, void *admin_buf, size_t nbytes)
{
    int rc;
    size_t buf_len;
    uint8_t *buf = NULL;
    char cmd_chr[NVME_ADMIN_CMD_SIZE * 2] = {0}; /* multiply 2 to hold str safely */
    struct ublock_client_cmd_params cmd_params;

    if (pci == NULL || cmd == NULL || admin_buf == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameter\n");
        return -1;
    }
    rc = spdk_base64_encode(cmd_chr, cmd, NVME_ADMIN_CMD_SIZE);
    if (rc != 0) {
        SPDK_ERRLOG("Encode cmd failed!\n");
        return -1;
    }

    cmd_params.pci = pci;
    cmd_params.cmd_len = UBLOCK_CLIENT_RPC_CMD_LEN_MAX;
    cmd_params.param1 = (uint32_t)nbytes;
    cmd_params.param4 = (uint64_t)cmd_chr;
    if (rpc_flg == REMOTE_RPC_QUERY) {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU;
    } else {
        cmd_params.type = UBLOCK_CLIENT_CMD_TYPE_ADMIN_PASSTHRU_LOCAL_RPC;
    }

    buf_len = (size_t)ublock_client_send_prepare(rpc_flg, &buf, &cmd_params);
    if (buf_len == 0) {
        SPDK_ERRLOG("nvme_admin_passthru failed!\n");
        return -1;
    }
    rc = ublock_parse_admin_resp(buf, &buf_len, admin_buf);
    if (rc != 0 || buf_len != nbytes) {
        SPDK_ERRLOG("[ublock] fail to parse admin resp, buf_len is %lu\n", buf_len);
        rc = -1;
    }

    ublock_client_safe_free((void **)(&buf));
    return rc;
}
