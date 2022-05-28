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
 * Description: ublock internal head file
 * Author: zhoupengchen
 * Create: 2018-9-1
 */

#ifndef __UBLOCK_INTERNAL_H__
#define __UBLOCK_INTERNAL_H__

#include <spdk/jsonrpc.h>
#include <spdk/nvme.h>

#include <sys/queue.h>
#include <securec.h>

/* ublock RPC server */
typedef void (*ublock_rpc_method_handler)(struct spdk_jsonrpc_request *request,
    const struct spdk_json_val *params);

enum RPC_ERR_CODE {
    JSON_DECODE_ERR = 1000,
    GETINFO_ERR,
};

/* ublock set iostat status */
enum ublock_set_iostat {
    UBLOCK_IOSTAT_DISABLE = 0,
    UBLOCK_IOSTAT_ENABLE = 1,
    UBLOCK_IOSTAT_QUERY = 2,
};

/* ublock query iostat status */
enum ublock_query_iostat {
    UBLOCK_IOSTAT_DISABLE_PCI_INVALID = 0,
    UBLOCK_IOSTAT_ENABLE_PCI_INVALID = 1,
    UBLOCK_IOSTAT_DISABLE_PCI_VALID  = 2,
    UBLOCK_IOSTAT_ENABLE_PCI_VALID  = 3,
    UBLOCK_CTRL_INVALID = 4,
};

struct ublock_rpc_method {
    char *name;
    ublock_rpc_method_handler func;
    SLIST_ENTRY(ublock_rpc_method)
    slist;
    uint32_t state_mask;
};

/* create thread to start listening rpc server */
int ublock_start_rpc(const char *listen_addr);
void ublock_stop_rpc(void);
int ublock_rpc_listen(const char *listen_addr);
void ublock_rpc_accept(void);
void ublock_rpc_close(void);
char *ublock_get_sockaddr_shm(const char *pci, char *ctrl_name, size_t ctrl_name_size);
char *ublock_get_sockaddr(const char *pci);
void ublock_rpc_register_method(const char *method, ublock_rpc_method_handler func);

#define UBLOCK_RPC_REGISTER(method, func)                              \
    static void __attribute__((constructor)) rpc_register_##func(void) \
    {                                                                  \
        ublock_rpc_register_method(method, func);                      \
    }

#define UBLOCK_RPC_ADDR "/var/tmp/ublock.\
sock.27D72DB485453A7D5FD4F0D4968009D967A40BDBAC57B3666C02F999"

#define UBLOCK_RPC_SHM_FILE_NAME "ublock_plog_server.shm.\
5eabb7f9f48edb77e6b7c62979d7cb425a66838187727775d2872ed2"

#define LIBSTORAGE_STAT_SHM_FILE_NAME   "libstorage_stat.shm.\
49ce4ec241e017c65812b71b9832a50865f0b7d9b4d5f18d3d03283b"

/* max number of channel bdev in iostat shm */
#define STAT_MAX_NUM 8192

/* lenth of device name in iostat shm */
#define STAT_NAME_LEN 24

/* flag of iostat argc with device */
#define I_D_DEVICENAME 0x00002

/* max length of libstorage socket file name */
#define UBLOCK_PLG_SOCK_ADDR_MAX_LEN    4096

/* max number of nvme devices that libstorage can occupy */
#define UBLOCK_PLG_DEVICE_MAX_NUM 512

/* max length of libstorage ctrlr name */
#define UBLOCK_CTRLR_NAME_MAX_LEN 256

/* it is admin_passthru cmd size */
#define NVME_ADMIN_CMD_SIZE 64

#ifdef SPDK_CONFIG_ERR_INJC
#define UBLOCK_DEVICE_NAME_MAX_LEN      64

// interface to inject error into smart info
void ublock_error_inject_smart_info(const char *pci, struct ublock_SMART_info *smart_info);
/* interface to print smart info */
void ublock_error_inject_print_smart_info(const struct ublock_SMART_info *smart_info);
// interface to send error inject rpc message
int ublock_send_request_err_injc(char *sockaddr, char *request_line);
#endif

#define UBLOCK_SERVER_LOCKFILE "/var/run/ublock_server.pid"

#define UBLOCK_BUFFER_SIZE 1024

/* the shm file for probe operation */
#define UBLOCK_UIO_LOCKFILE          "/var/run/ublock_uio.pid"

/* lock ublock server lockfile to check server process exist
 * (lock file is "/var/run/ublock_server.pid")
 *
 * return:
 *  true, server exist
 *  false, server not exist
 */
bool ublock_query_server_exist(const char *pidfile, bool update, pid_t pid);

/* robust mutex lock functions */
int32_t ublock_robust_mutex_init_recursive(pthread_mutex_t *mtx);
int32_t ublock_robust_mutex_lock(pthread_mutex_t *mtx);
int32_t ublock_robust_mutex_unlock(pthread_mutex_t *mtx);

/* basic querying function of ublock module */
/* ublock query function including two types: */
/* 1. remote rpc query which is querying from libstorage uio rpc service */
/*    (used in basic querying function) */
/* 2. local rpc query which is querying form libstorage ublock rpc service */
/*    (used in outside process calling) */
enum ublock_query_type {
    REMOTE_RPC_QUERY = 0,
    LOCAL_RPC_QUERY = 1,
};
/* basic bdev info query function interface */
int _ublock_get_bdev(const char *pci, struct ublock_bdev *bdev);
/* basic bdev SMART info query function interface */
int _ublock_get_SMART_info(const char *pci, uint32_t nsid, struct ublock_SMART_info *smart_info);
/* basic bdev error log info query function interface */
int _ublock_get_error_log_info(const char *pci, uint32_t err_entries, struct ublock_nvme_error_info *errlog_info);
/* basic bdev log page info query function interface */
int _ublock_get_log_page(const char *pci, uint8_t log_page, uint32_t nsid,
                         uint8_t *payload, uint32_t payload_size);
/* basic nvme admin cmd passthru interface */
int _ublock_nvme_admin_passthru(const char* pci, void *cmd, void *buf, uint32_t nbytes);

/* ublock RPC client */
/* calling remote thread plog_server */
int ublock_client_conn(const char *listen_addr);
int ublock_client_send(int sockfd, const char *req,
                       size_t req_len, uint8_t *out);
int ublock_client_querySMARTinfo(enum ublock_query_type rpc_flg,
                                 const char *pci,
                                 uint32_t nsid,
                                 struct ublock_SMART_info *smart_info);
int ublock_parse_smart(uint8_t *buf, ssize_t buf_len, struct ublock_SMART_info *out);
int ublock_client_queryinfo(enum ublock_query_type rpc_flg,
                            const char *pci,
                            struct ublock_bdev *bdev);
int ublock_client_query_err_log_info(enum ublock_query_type rpc_flg,
                                     const char *pci,
                                     uint32_t err_entries_arg,
                                     struct ublock_nvme_error_info *erro_log_info);
int ublock_parse_err_log(uint8_t *buf, ssize_t buf_len, struct ublock_nvme_error_info **out);
int ublock_client_iostat_enable(const char *pci, int iostat_enable);
int ublock_client_nvme_admin_passthru(enum ublock_query_type rpc_flg, const char *pci,
                                      void *cmd, void *admin_buf, size_t nbytes);
void ublock_init_iostat(void);
struct rpc_log_page {
    const char  *pci;
    uint32_t    nsid;
    uint32_t    log_page;
    uint8_t     *payload;
    uint32_t    payload_size;
};
int ublock_client_query_log_page_info(enum ublock_query_type rpc_flg, struct rpc_log_page *rpc_param);

/* shutdown the nvme specified by pci address. */
/* if it returns successful value, then it is safe to shutdown the nvme disk. */
int ublock_shutdown_disk(const char *pci, bool reset_flag);

/* basic client shutdown and reset function interface */
int ublock_client_shutdown_disk(enum ublock_query_type rpc_flg, const char *pci, bool reset_flag);

/* basic bdev shutdown and reset function interface */
int _ublock_nvme_ctrlr_shutdown_reset(const char *pci, bool reset_flag);

/* free buf safely */
void ublock_client_safe_free(void **ptr);

/* defined struct according to jsonrpc_internal.h */
#define SPDK_JSONRPC_RECV_BUF_SIZE (32 * 1024)
#define SPDK_JSONRPC_SEND_BUF_SIZE (32 * 1024)
#define SPDK_JSONRPC_ID_MAX_LEN 128
#define SPDK_JSONRPC_MAX_CONNS 64
#define SPDK_JSONRPC_MAX_VALUES (8 * 1024)
/* the max count of error log page information that controller supports */
#define UBLOCK_RPC_ERROR_LOG_MAX_COUNT 256
#define UBLOCK_RPC_MAX_LOG_PAGE_SIZE   4096

struct spdk_jsonrpc_request {
    struct spdk_jsonrpc_server_conn *conn;

    /* Copy of request id value */
    struct spdk_json_val id;
    uint8_t id_data[SPDK_JSONRPC_ID_MAX_LEN];

    /* Total space allocated for send_buf */
    size_t send_buf_size;

    /* Number of bytes used in send_buf (<= send_buf_size) */
    size_t send_len;

    size_t send_offset;

    uint8_t *send_buf;

    STAILQ_ENTRY(spdk_jsonrpc_request) link;
};

struct spdk_jsonrpc_server_conn {
    struct spdk_jsonrpc_server *server;
    int sockfd;
    bool closed;
    struct spdk_json_val values[SPDK_JSONRPC_MAX_VALUES];
    size_t recv_len;
    uint8_t recv_buf[SPDK_JSONRPC_RECV_BUF_SIZE];
    uint32_t outstanding_requests;

    pthread_spinlock_t queue_lock;
    STAILQ_HEAD(, spdk_jsonrpc_request) send_queue;

    struct spdk_jsonrpc_request *send_request;

    TAILQ_ENTRY(spdk_jsonrpc_server_conn) link;
};

struct spdk_jsonrpc_server {
    int sockfd;
    spdk_jsonrpc_handle_request_fn handle_request;

    TAILQ_HEAD(, spdk_jsonrpc_server_conn) free_conns;
    TAILQ_HEAD(, spdk_jsonrpc_server_conn) conns;

    struct spdk_jsonrpc_server_conn conns_array[SPDK_JSONRPC_MAX_CONNS];
};

/* define struct for plog register info in shm file */
typedef struct {
    char pci[UBLOCK_PCI_ADDR_MAX_LEN];
    char plg_sock_addr[UBLOCK_PLG_SOCK_ADDR_MAX_LEN];
    char ctrlr_name[UBLOCK_CTRLR_NAME_MAX_LEN];
} plog_server_sh;

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

int base64_encode(const char *src, int len, char *dec);
int base64_decode(const char *src, int len, char *dec);

int ublock_string_to_int(const char *str, int *result);

#if defined(__i386__) || defined(__x86_64__)
static inline uint64_t get_tsc_cycles_local(void)
{
    uint32_t lo_32 = 0;
    uint32_t hi_32 = 0;

    asm volatile("rdtsc" :
                "=a" (lo_32),
                "=d" (hi_32));

    return ((uint64_t)hi_32 << 32) | lo_32; /* left shift 32 bits */
}
#elif defined(__aarch64__)
static inline uint64_t get_tsc_cycles_local(void)
{
    uint64_t tsc;

    asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
    return tsc;
}
#else
#error Unknown architecture
#endif

#endif
