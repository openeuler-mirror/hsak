/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: interaction API between LibStorage and ublock.
 * Author: louhongxiang@huawei.com
 * Create: 2018-09-01
 */

#include <dirent.h>
#include <pthread.h>
#include <regex.h>
#include <securec.h>
#include <signal.h>

#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include "bdev_rw_internal.h"
#include "bdev_rw_rpc_internal.h"
#include "spdk/bdev_rw.h"
#include "spdk/log.h"
#include "spdk/nvme.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk_internal/bdev_stat.h"
#include "spdk/base64.h"
#include "spdk_internal/nvme_internal.h"

/* the address of socket fd that listened by libstorage rpc server. */
#define LIBSTORAGE_RPC_ADDR "/var/run/libstorage_rpc"
#define LIBSTORAGE_RPC_ADDR_LEN 256
#define LIBSTORAGE_PID_FILE_LEN 128

/* the address of socket fd that listened by ublock rpc server. */
#define UBLOCK_RPC_ADDR "/var/tmp/ublock.\
sock.27D72DB485453A7D5FD4F0D4968009D967A40BDBAC57B3666C02F999"

/* the length of libstorage rpc receive buffer */
#define LIBSTORAGE_RPC_RECEIVE_BUF_LEN 1024

#define LIBSTORAGE_CLIENT_REGISTER_TO_UBLOCK "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"reg_plogserver\",\
\"params\":{\"pci\":\"%s\",\"plg_sock_addr\":\"%s\",\"ctrlr_name\":\"%s\"}}"

/* the total length of SMART information is 512 bytes. */
#define LIBSTORAGE_SMART_INFO_LEN 512

#define LIBSTORAGE_RPC_CLIENT_TIMEOUT 10
#define LIBSTORAGE_RPC_REGISTER_SLEEP_USECS 1000
#define LIBSTORAGE_RPC_REGISTER_TIMEOUT_SECS 15
#define LIBSTORAGE_CTRLR_RESET  1
#define LIBSTORAGE_CTRLR_SHUTDOWN 0

/* it is admin_passthru cmd size */
#define NVME_ADMIN_CMD_SIZE 64

/* the size of buf to save return value of admin cmd */
#define LIBSTORAGE_ADMIN_CMD_BUF_MAX_SIZE 4096

bool g_bRpcServer = false;
bool g_bRpcServerIsInit = false;
bool g_bRpcThreadIsStart = false;

static bool g_exit_flag = false;
static pthread_t g_rpc_server_thread;
static char *g_rpc_sockfd_addr = NULL;
static SLIST_HEAD(, libstorage_rpc_register_ublock_info) g_register_ublock_info_list =
    SLIST_HEAD_INITIALIZER(g_register_ublock_info_list);
static pthread_mutex_t g_register_info_mutex;
static pthread_mutex_t g_register_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_register_count = 0;

static const struct spdk_json_object_decoder rpc_get_plogserver_decoders[] = {
    { "pci", offsetof(struct rpc_pci_dev, pci), spdk_json_decode_string },
};

static const struct spdk_json_object_decoder rpc_get_iostat_decoders[] = {
    { "pci", offsetof(struct rpc_iostat_dev, pci), spdk_json_decode_string },
    { "iostat_enable", offsetof(struct rpc_iostat_dev, iostat_enable), spdk_json_decode_int32 },
};

static const struct spdk_json_object_decoder rpc_get_pci_nsid_decoders[] = {
    { "pci", offsetof(struct rpc_pci_nsid_dev, pci), spdk_json_decode_string },
    { "nsid", offsetof(struct rpc_pci_nsid_dev, nsid), spdk_json_decode_uint32 },
};

static const struct spdk_json_object_decoder rpc_get_pci_errs_decoders[] = {
    { "pci", offsetof(struct rpc_pci_errs_dev, pci), spdk_json_decode_string },
    { "err_entries", offsetof(struct rpc_pci_errs_dev, err_entries), spdk_json_decode_uint32 },
};

static const struct spdk_json_object_decoder rpc_get_log_page_decoders[] = {
    { "pci", offsetof(struct rpc_pci_log_page, pci), spdk_json_decode_string },
    { "nsid", offsetof(struct rpc_pci_log_page, nsid), spdk_json_decode_uint32 },
    { "pageid", offsetof(struct rpc_pci_log_page, pageid), spdk_json_decode_uint32 },
    { "size", offsetof(struct rpc_pci_log_page, size), spdk_json_decode_uint32 },
};

static const struct spdk_json_object_decoder rpc_admin_passthru_decoders[] = {
    { "pci", offsetof(struct rpc_admin_passthru, pci), spdk_json_decode_string },
    { "nbytes", offsetof(struct rpc_admin_passthru, nbytes), spdk_json_decode_uint32 },
    { "cmd", offsetof(struct rpc_admin_passthru, cmd), spdk_json_decode_string },
};

struct completion_poll_status {
    struct spdk_nvme_cpl    cpl;
    bool                    done;
    int                     status;
};

static pid_t libstorage_gettid(void)
{
    return (pid_t)syscall(__NR_gettid);
}

static int libstorage_rpc_open_socket(void)
{
    int sockfd = -1;
    struct timeval timeout = { LIBSTORAGE_RPC_CLIENT_TIMEOUT, 0 };
    int rc;

    sockfd = socket((int)AF_UNIX, (int)SOCK_STREAM, 0);
    if (sockfd < 0) {
        SPDK_ERRLOG("[libstorage_rpc]socket() failed\n");
        return -1;
    }

    /* set timeout for socket to send in LIBSTORAGE_RPC_CLIENT_TIMEOUT */
    rc = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    if (rc < 0) {
        SPDK_ERRLOG("[libstorage_rpc] fail to set timeout for sending opt\n");
        close(sockfd);
        return -1;
    }
    /* set timeout for socket to receive in LIBSTORAGE_RPC_CLIENT_TIMEOUT */
    rc = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    if (rc < 0) {
        SPDK_ERRLOG("[libstorage_rpc] fail to set timeout for receiving opt\n");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/* connet to the socket file provided by listen_addr */
static int libstorage_client_conn(const char *listen_addr)
{
    int sockfd;
    int rc;
    struct sockaddr_un client_addr_unix = {};

    if (listen_addr[0] != '/') {
        return -1;
    }

    client_addr_unix.sun_family = AF_UNIX;
    rc = sprintf_s(client_addr_unix.sun_path, sizeof(client_addr_unix.sun_path), "%s", listen_addr);
    if (rc < 0 || (size_t)rc >= sizeof(client_addr_unix.sun_path)) {
        SPDK_ERRLOG("[libstorage_rpc]RPC Listen address Unix socket path too long\n");
        client_addr_unix.sun_path[0] = '\0';
        return -1;
    }

    sockfd = libstorage_rpc_open_socket();
    if (sockfd < 0) {
        SPDK_ERRLOG("[libstorage_rpc] Failed to open socket for connecting. err: %d.\n", sockfd);
        return -1;
    }

    rc = connect(sockfd, (struct sockaddr *)&client_addr_unix, sizeof(client_addr_unix));
    if (rc < 0) {
        SPDK_WARNLOG("[libstorage_rpc]Failed to connect ublock, error[%s-%d]\n", strerror(errno), errno);
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/* send rpc request as a client to the sockfd listened by ublock */
static int libstorage_client_send(int sockfd, const struct libstorage_rpc_register_ublock_info *info_item)
{
    size_t pci_len;
    size_t sock_addr_len;
    size_t cmd_len = strlen(LIBSTORAGE_CLIENT_REGISTER_TO_UBLOCK);
    size_t total_len;
    const char *pci = NULL;
    const char *plg_sock_addr = NULL;
    char *register_cmd = NULL;
    int ret;
    size_t ctrlName_len;
    const char *ctrlr_name = NULL;

    pci = info_item->pci;
    plg_sock_addr = info_item->plg_sock_addr;
    ctrlr_name = info_item->ctrlName;
    if (plg_sock_addr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]pci or socket address shouln't be NULL!\n");
        return -1;
    }

    SPDK_NOTICELOG("[libstorage_rpc] send pci: %s register info: %s to ublock\n", pci, plg_sock_addr);

    pci_len = strlen(pci);
    sock_addr_len = strnlen(plg_sock_addr, LIBSTORAGE_RPC_ADDR_LEN);
    ctrlName_len = strlen(ctrlr_name);

    total_len = pci_len + sock_addr_len + cmd_len + ctrlName_len + 1;

    register_cmd = (char *)malloc(total_len);
    if (register_cmd == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]allocate memory for register cmd to send to ublock failed\n");
        return -1;
    }

    if (sprintf_s(register_cmd, total_len, LIBSTORAGE_CLIENT_REGISTER_TO_UBLOCK, pci, plg_sock_addr, ctrlr_name) < 0) {
        SPDK_ERRLOG("[libstorage_rpc] sprintf failed\n");
        free(register_cmd);
        return -1;
    }

    ret = send(sockfd, register_cmd, total_len, 0);
    if (ret < 0) {
        SPDK_ERRLOG("[libstorage_rpc]Send rpc request fail, errno[%s-%d]\n", strerror(errno), errno);
        ret = -1;
    }

    free(register_cmd);
    return ret;
}

/* return true if find the fail keyword, return false if not find */
static bool libstorage_resv_find_fail_keyword(const char *recmsg)
{
    /* if the message responsed by server contains "error", "code" and "message",
     * that means the remote call is failed in handling by server.
     */
    if (strstr(recmsg, "error") != NULL && strstr(recmsg, "code") != NULL && strstr(recmsg, "message") != NULL) {
        SPDK_ERRLOG("[libstorage_rpc]Get RPC error response\n");
        return true;
    }

    return false;
}

/* mainly for getting response from ublock after sending a rpc request. */
static int libstorage_client_recv(int sockfd)
{
    int ret;
    char *recmsg = NULL;
    uint8_t *recv_buf = NULL;
    ssize_t recv_len = LIBSTORAGE_RPC_RECEIVE_BUF_LEN;

    recv_buf = (uint8_t *)calloc(recv_len, 1);
    if (recv_buf == NULL) {
        SPDK_WARNLOG("[libstorage_rpc]Allocate memory of receive buf for get response failed in register operation!\n");
        return -1;
    }

    ret = recv(sockfd, recv_buf, recv_len, 0);
    if (ret < 0) {
        SPDK_ERRLOG("[libstorage_rpc] recv rpc message fail, errno[%s-%d]\n", strerror(errno), errno);
        goto FREE_AND_EXIT;
    }
    if (ret >= recv_len) {
        /* we do not hope to receive such long message, drop it. */
        SPDK_ERRLOG("[libstorage_rpc]recv buf too long\n");
        ret = -1;
        goto FREE_AND_EXIT;
    }

    recmsg = (char *)recv_buf;
    recmsg[recv_len - 1] = '\0';
    if (libstorage_resv_find_fail_keyword(recmsg)) {
        ret = 0;
        goto FREE_AND_EXIT;
    }

FREE_AND_EXIT:
    free(recv_buf);
    return ret;
}

/* disconnet to the sockfd listened by ublock. */
static void libstorage_client_disconn(int sockfd)
{
    close(sockfd);
    return;
}

/* construct the struct for every register info for inserting into the global list. */
static void* libstorage_rpc_construct_register_info(const char *pci, const char *ctrlName)
{
    struct libstorage_rpc_register_ublock_info *p_register_info = NULL;
    int rc;

    /* initialize the p_register_info struct */
    p_register_info = malloc(sizeof(struct libstorage_rpc_register_ublock_info));
    if (p_register_info == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]Failed to allocate memory for registering info to ublock.\n");
        return NULL;
    }

    /* copy string to the members of struct correctly. */
    p_register_info->plg_sock_addr = g_rpc_sockfd_addr;
    rc = strcpy_s(p_register_info->pci, MAX_PCI_ADDR_LEN, pci);
    rc += strcpy_s(p_register_info->ctrlName, MAX_CTRL_NAME_LEN, ctrlName);
    if (rc != 0) {
        SPDK_WARNLOG("[libstorage_rpc] strcpy failed\n");
        free(p_register_info);
        return NULL;
    }

    return p_register_info;
}

static bool libstorage_is_already_register_info(const char *pci)
{
    struct libstorage_rpc_register_ublock_info *register_info_item = NULL;

    libstorage_process_mutex_lock(&g_register_info_mutex);
    SLIST_FOREACH(register_info_item, &g_register_ublock_info_list, slist) {
        if (strcmp(register_info_item->pci, pci) == 0) {
            /* pci address has been in the list. */
            SPDK_NOTICELOG("[libstorage_rpc]PCI device-%s has been in the register_info list.\n", pci);
            libstorage_process_mutex_unlock(&g_register_info_mutex);
            return true;
        }
    }

    libstorage_process_mutex_unlock(&g_register_info_mutex);
    return false;
}

/* initialize the list of register info that would be send to ublock to registe. */
static int libstorage_init_rpc_register_info_list(void)
{
    struct libstorage_rpc_register_ublock_info *register_info = NULL;
    struct nvme_ctrlr_info *pCtrlInfo = NULL;
    int32_t num_ctrl;
    int32_t ctrlindex;
    int info_count = 0;

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);
    /* get the number of ctrlr in the system, and get the information of them. */
    num_ctrl = nvme_ctrlr_get_info(NULL, &pCtrlInfo);
    if (num_ctrl <= 0) {
        SPDK_ERRLOG("[libstorage_rpc]There is not any controller!\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    for (ctrlindex = 0; ctrlindex < num_ctrl; ctrlindex++) {
        /* if the pci address has been in the list, skip adding it into the list. */
        if (libstorage_is_already_register_info(pCtrlInfo[ctrlindex].pciAddr)) {
            continue;
        }

        register_info = libstorage_rpc_construct_register_info(pCtrlInfo[ctrlindex].pciAddr,
                                                               pCtrlInfo[ctrlindex].ctrlName);
        if (register_info == NULL) {
            goto end;
        }

        /* inster to the info list */
        libstorage_process_mutex_lock(&g_register_info_mutex);
        SLIST_INSERT_HEAD(&g_register_ublock_info_list, register_info, slist);
        libstorage_process_mutex_unlock(&g_register_info_mutex);
        info_count++;
    }

end:
    free(pCtrlInfo);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    /* return the count of register info in the global list. */
    return info_count;
}

int libstorage_remove_rpc_register_info(const char *ctrlrName)
{
    struct libstorage_rpc_register_ublock_info *info_item = NULL;

    if (ctrlrName == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] ctrlrName should not be NULL\n");
        return -1;
    }

    /* this slist is only related with operation of ublock rpc,
     * there is no need to add mutex_lock for this remove operation,
     * because rpc here is realized by listening socket, it's not intercurrent.
     */
    libstorage_process_mutex_lock(&g_register_info_mutex);
    SLIST_FOREACH(info_item, &g_register_ublock_info_list, slist) {
        if (strcmp(info_item->ctrlName, ctrlrName) == 0) {
            SLIST_REMOVE(&g_register_ublock_info_list, info_item, libstorage_rpc_register_ublock_info, slist);
            libstorage_process_mutex_unlock(&g_register_info_mutex);
            free(info_item);
            return 0;
        }
    }

    libstorage_process_mutex_unlock(&g_register_info_mutex);
    SPDK_NOTICELOG("[libstorage_rpc] fail to find register info of %s to remove\n", ctrlrName);
    return -1;
}

static int libstorage_destory_rpc_register_info_list(void)
{
    struct libstorage_rpc_register_ublock_info *register_info_item = NULL;

    libstorage_process_mutex_lock(&g_register_info_mutex);
    while (!SLIST_EMPTY(&g_register_ublock_info_list)) {
        register_info_item = (struct libstorage_rpc_register_ublock_info *)SLIST_FIRST(&g_register_ublock_info_list);
        SLIST_REMOVE_HEAD(&g_register_ublock_info_list, slist);

        free(register_info_item);
        register_info_item = NULL;
    }
    libstorage_process_mutex_unlock(&g_register_info_mutex);

    return 0;
}

/* send the information to ulbock for register, and get the reponse from ublock. */
/* returning -1 means the operation of whole register is failed. */
/* returning 0 means sending request is ok, but it's not clear whether ublock have done with the register. */
static int libstorage_client_send_reg_info(int sockfd, const struct libstorage_rpc_register_ublock_info *info_item)
{
    const char *pci = NULL;
    const char *plg_sock_addr = NULL;
    int ret;

    pci = info_item->pci;
    plg_sock_addr = info_item->plg_sock_addr;
    if (plg_sock_addr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]pci or socket address shouln't be NULL!\n");
        return -1;
    }

    ret = libstorage_client_send(sockfd, info_item);
    if (ret <= 0) {
        SPDK_ERRLOG("[libstorage_rpc]fail to register %s-%s to socket fd: %d\n", pci, plg_sock_addr, sockfd);
        return -1;
    }

    ret = libstorage_client_recv(sockfd);
    if (ret < 0) {
        SPDK_WARNLOG("[libstorage_rpc]Get response of register operation failed. nvme-%s.\n", pci);
        ret = 0;
    } else if (ret == 0) {
        SPDK_ERRLOG("[libstorage_rpc]Register to ublock failed! nvme-%s-%s\n", pci, plg_sock_addr);
        ret = -1;
    }

    return ret;
}

static void *libstorage_pth_client_send_info(void *arg)
{
    int sockfd;
    int ret = 1;
    int retry_times = 3;
    struct libstorage_rpc_register_ublock_info *info_item = (struct libstorage_rpc_register_ublock_info *)arg;

    pthread_detach(pthread_self());
    if (info_item == NULL) {
        return NULL;
    }

TRY_TO_REGISTER:
    /* connect to ublock socket fd */
    sockfd = libstorage_client_conn(UBLOCK_RPC_ADDR);
    if (sockfd < 0) {
        SPDK_ERRLOG("[libstorage_rpc]Fail to connect ublock socket address\n");
    } else {
        /* send rpc message */
        ret = libstorage_client_send_reg_info(sockfd, info_item);

        /* close the connection after register operation is done. */
        libstorage_client_disconn(sockfd);
    }

    if (ret <= 0 && retry_times > 0) {
        retry_times--;
        SPDK_WARNLOG("[libstorage_rpc]retry to register to ublock %d... \n", 3 - retry_times);  /* retry time is 3 */
        goto TRY_TO_REGISTER;
    }

    libstorage_process_mutex_lock(&g_register_count_mutex);
    if (g_register_count > 0) {
        g_register_count--;
    }
    libstorage_process_mutex_unlock(&g_register_count_mutex);

    free(arg);
    return NULL;
}

static int libstorage_send_register_info_to_ublock(const struct libstorage_rpc_register_ublock_info *info_item)
{
    pthread_t pid;
    int ret;
    struct libstorage_rpc_register_ublock_info *info_item_pth = NULL;

    info_item_pth = libstorage_rpc_construct_register_info(info_item->pci, info_item->ctrlName);
    if (info_item_pth == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]construct for info_item to send in pthread failed\n");
        return -1;
    }

    /* info_item_pth malloced here needs to be freed in libstorage_pth_client_send_info */
    ret = pthread_create(&pid, NULL, libstorage_pth_client_send_info, info_item_pth);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

int libstorage_register_one_info_to_ublock(const char *pci, const char *name)
{
    if ((pci == NULL) || (name == NULL)) {
        return -1;
    }

    struct libstorage_rpc_register_ublock_info *register_info = NULL;
    int ret = 0;

    libstorage_process_mutex_lock(&g_register_info_mutex);
    /* check if info was registered */
    SLIST_FOREACH(register_info, &g_register_ublock_info_list, slist) {
        if (strcmp(register_info->pci, pci) == 0) {
            /* update register info */
            ret = strcpy_s(register_info->ctrlName, MAX_CTRL_NAME_LEN, name);
            if (ret != 0) {
                libstorage_process_mutex_unlock(&g_register_info_mutex);
                SPDK_ERRLOG("strcpy %s failed", name);
                return -1;
            }

            break;
        }
    }

    /* info was not registered */
    if (register_info == NULL) {
        register_info = libstorage_rpc_construct_register_info(pci, name);
        if (register_info == NULL) {
            SPDK_ERRLOG("construct register info for %s:%s failed", name, pci);
            libstorage_process_mutex_unlock(&g_register_info_mutex);
            return -1;
        }

        SLIST_INSERT_HEAD(&g_register_ublock_info_list, register_info, slist);
    }

    ret = libstorage_send_register_info_to_ublock(register_info);
    libstorage_process_mutex_unlock(&g_register_info_mutex);
    return ret;
}

/* the main function for libstorage rpc server to call, for register to ublock. */
static int libstorage_register_info_to_ublock(void)
{
    int ret;
    int numctrl;
    int send_fail_count = 0;
    int info_count = 0;
    struct libstorage_rpc_register_ublock_info *info_item = NULL;

    /* initialize the global list to storing all the pci information of nvme. */
    numctrl = libstorage_init_rpc_register_info_list();
    if (numctrl < 0) {
        SPDK_ERRLOG("[libstorage_rpc]Cannot init information for nvme in system, cancel register operation.\n");
        return -1;
    } else if (numctrl == 0) {
        SPDK_WARNLOG("[libstorage_rpc]The information of nvme in system is incomplete,"
                     " maybe because memory allocation failed.\n");
    }

    /* set register count first */
    /* judge the value of g_bRpcServerIsInit to avoid making influnce on rpc funtion get_reg_info_response */
    if (!g_bRpcServerIsInit) {
        libstorage_process_mutex_lock(&g_register_count_mutex);
        g_register_count = numctrl;
        libstorage_process_mutex_unlock(&g_register_count_mutex);
    }

    /* loop for sending the information stored in the global list. */
    libstorage_process_mutex_lock(&g_register_info_mutex);
    SLIST_FOREACH(info_item, &g_register_ublock_info_list, slist) {
        info_count++;
        ret = libstorage_send_register_info_to_ublock(info_item);
        if (ret < 0) {
            send_fail_count++;
        }
    }
    libstorage_process_mutex_unlock(&g_register_info_mutex);

    /* all the register operations are failed, return -1 to terminate the rpc server. */
    if (info_count == send_fail_count) {
        SPDK_ERRLOG("[libstorage_rpc]all the operations of registering to ublock are failed!\n");
        return -1;
    }

    return send_fail_count;
}

static void libstorage_close_rpc_server(void)
{
    SPDK_NOTICELOG("[libstorage_rpc]stop libstorage rpc server...\n");
    spdk_rpc_close();

    if (g_rpc_sockfd_addr != NULL) {
        free(g_rpc_sockfd_addr);
        g_rpc_sockfd_addr = NULL;
    }
    (void)libstorage_destory_rpc_register_info_list();
}

static void libstorage_exit_rpc_server(void)
{
    g_exit_flag = true;
    /* wait for rpc pthread is stoped, and ignore the result returned. */
    pthread_join(g_rpc_server_thread, NULL);
}

void libstorage_stop_rpc_server(void)
{
    int kill_rc;

    if (!g_bRpcServer || !g_bRpcThreadIsStart) {
        return;
    }

    kill_rc = pthread_kill(g_rpc_server_thread, 0);
    /* the rpc pthread is still alive */
    if (kill_rc != ESRCH && kill_rc != EINVAL) {
        libstorage_exit_rpc_server();
        libstorage_close_rpc_server();
    }
}

static int libstorage_init_rpc_server_socket(void)
{
    char *rpc_addr;
    int ret;

#if defined(__linux__)
    prctl(PR_SET_NAME, "rpc-server", 0, 0, 0);
#endif
    rpc_addr = (char *)malloc(LIBSTORAGE_RPC_ADDR_LEN);
    if (rpc_addr == NULL) {
        SPDK_ERRLOG("Allocate memory to store rpc server address failed!\n");
        g_bRpcServer = false;
        return -1;
    }

    if (sprintf_s(rpc_addr, LIBSTORAGE_RPC_ADDR_LEN, "%s_%d.sock", LIBSTORAGE_RPC_ADDR, libstorage_gettid()) < 0) {
        SPDK_ERRLOG("[libstorage_rpc] sprintf failed!\n");
        g_bRpcServer = false;
        free(rpc_addr);
        return -1;
    }

    spdk_rpc_set_state(SPDK_RPC_RUNTIME);
    g_rpc_sockfd_addr = rpc_addr;

    /* initialize socket */
    ret = spdk_rpc_listen(rpc_addr);
    if (ret != 0) {
        SPDK_ERRLOG("[libstorage_rpc]Unable to start RPC service for libstorage at %s\n", rpc_addr);
        free(rpc_addr);
        g_bRpcServer = false;
        g_rpc_sockfd_addr = NULL;
        return -1;
    }

    return 0;
}

static void *libstorage_run_rpc_server(void *arg)
{
    int ret;
    int retry_count = 3;

    if (libstorage_init_rpc_server_socket() != 0) {
        SPDK_ERRLOG("[libstorage_rpc]Unable to start RPC service at %s\n", g_rpc_sockfd_addr);
        return NULL;
    }

    SPDK_WARNLOG("[libstorage_rpc] rpc server addr %s is running!\n", g_rpc_sockfd_addr);

register_to_ublock:
    /* register to ublock first */
    /* if ret is greater than 0, it means not all but some devices failed to register, then retry 3 times. */
    /* if ret is less than 0, it means there is no NVMe in system or all devices failed to regsiter. */
    ret = libstorage_register_info_to_ublock();
    if (ret > 0 && retry_count != 0) {
        retry_count--;
        SPDK_ERRLOG("[libstorage_rpc]Libstorage register pci info to ublock failed![%d]\n",
                    3 - retry_count);   /* retry time is 3 */
        /* if register operation is failed, try 3 times. */
        goto register_to_ublock;
    }
    g_bRpcServerIsInit = true;

    /* loop for executing connection connecting and message operation. */
    while (!g_exit_flag) {
        /* main loop of rpc server */
        spdk_rpc_accept();
        usleep(100000); /* sleep for 100000 us */
        /* if the socket file is deleted, restart the socket listen */
        if (access(g_rpc_sockfd_addr, F_OK) == -1) {
            spdk_rpc_close();
            spdk_rpc_listen(g_rpc_sockfd_addr);
        }
    }

    libstorage_close_rpc_server();
    SPDK_WARNLOG("[libstorage_rpc]libstorage_rpc_server is going to exit\n");
    g_bRpcServer = false;
    return ((void *)0);
}

/**
 * IN:
 * @id   PID or TID
 * @path /proc or /proc/PID/
 *
 * RETURN:
 * false, not found given `id' in `path'
 * true, found given `id' in `path'
 */
static bool libstorage_searchID(const char *id, const char *path)
{
    DIR *dir = NULL;
    struct dirent *dirent_tmp = NULL;

    dir = opendir(path);
    if (dir == NULL) {
        SPDK_ERRLOG("unable to open directory: %s\n", path);
        return false;
    }

    dirent_tmp = readdir(dir);
    while (dirent_tmp != NULL) {
        if (strcmp(id, dirent_tmp->d_name) == 0) {
#ifdef DEBUG
            SPDK_NOTICELOG("found pid(tid) in %s/%s\n", path, dirent_tmp->d_name);
#endif
            closedir(dir);
            return true;
        }
        dirent_tmp = readdir(dir);
    }

    closedir(dir);
    return false;
}

/**
 * filename is number(ex: directory '1209' in /proc/1209/)
 */
static bool libstorage_is_number_str(const char *ppid)
{
    char *pattern = "^[0-9]\\{1,\\}$";
    int ret;
    int cflags = 0;
    const size_t cnmatch = 10;
    regmatch_t pm[10]; /* to store 10 number 0~9 */
    regex_t reg;

    ret = regcomp(&reg, pattern, cflags);
    if (ret == 0) {
        ret = regexec(&reg, ppid, cnmatch, pm, cflags);
    }
    regfree(&reg);

    return (ret == 0);
}

/**
 * search PID or TID in system to
 * make sure the given `pid' is still running or not
 */
static bool libstorage_searchPTID(const char *pid)
{
    DIR *dir = NULL;
    struct dirent *dirent = NULL;
    char path[LIBSTORAGE_PID_FILE_LEN];
    int rc = 0;

    /* find if match with pid in /proc/ */
    if (libstorage_searchID(pid, "/proc/")) {
        return true;
    }

    /* find if match with tid in /proc/pid/task */
    dir = opendir("/proc/");
    if (dir == NULL) {
        SPDK_ERRLOG("fail to open directory: /proc/\n");
        return false;
    }

    dirent = readdir(dir);
    while (dirent != NULL) {
        if (!libstorage_is_number_str(dirent->d_name)) {
            dirent = readdir(dir);
            continue;
        }

        rc = snprintf_s(path, LIBSTORAGE_PID_FILE_LEN, LIBSTORAGE_PID_FILE_LEN - 1, "/proc/%s/task/", dirent->d_name);
        if (rc < 0) {
            break;
        }

        if (libstorage_searchID(pid, path)) {
            closedir(dir);
            return true;
        }
        dirent = readdir(dir);
    }

    closedir(dir);
    return false;
}

/**
 * filter PID(TID) from spdk shared files
 * (ex:
 *  1./var/run/libstorage_rpc_PID.sock
 * )
 * if PID(TID) is still running in system, ignore it,
 * or delete it.
 *
 */
static void libstorage_rpc_cleanup(void)
{
    DIR *pdir = NULL;
    struct dirent *pdirent = NULL;
    char *tmp = NULL;
    char pid[LIBSTORAGE_PID_FILE_LEN];
    char file[LIBSTORAGE_PID_FILE_LEN];
    int idx = 0;
    int rc = 0;

    pdir = opendir("/var/run");
    if (pdir == NULL) {
        SPDK_ERRLOG("unable to open directory\n");
        return;
    }

    pdirent = readdir(pdir);
    while (pdirent != NULL) {
        if (strncmp(pdirent->d_name, "libstorage_rpc_", 15) != 0) { /* length ot string to compare is 15 */
            pdirent = readdir(pdir);
            continue;
        }

        idx = 0;
        tmp = pdirent->d_name + 15;     /* length ot string to compare is 15 */

        while ((*tmp) != '.') {
            pid[idx++] = *tmp++;
            if (idx >= LIBSTORAGE_PID_FILE_LEN - 1) {
                break;
            }
        }
        pid[idx] = '\0';

        if (libstorage_searchPTID(pid)) {
            pdirent = readdir(pdir);
            continue;
        }
        rc = snprintf_s(file, LIBSTORAGE_PID_FILE_LEN, LIBSTORAGE_PID_FILE_LEN - 1, "/var/run/%s", pdirent->d_name);
        if (rc < 0) {
            continue;
        }
        (void)unlink(file);
        pdirent = readdir(pdir);
    }

    closedir(pdir);
}

static void libstorage_ignore_sig(int sig)
{
    if (sig == SIGPIPE) {
        /* ignore SIGPIPE for send to a exit socket connection, */
        /* or it will lead to process exit */
        signal(SIGPIPE, SIG_IGN);
    }
}

void libstorage_start_rpc_server(void)
{
    uint32_t register_timeout_cnt = LIBSTORAGE_RPC_REGISTER_TIMEOUT_SECS *
                                    1000000 /       /* make timeout to second level by multiplying 1000000 */
                                    LIBSTORAGE_RPC_REGISTER_SLEEP_USECS;

    /* decide whether to start rpc server by this flag from config file. */
    if (!g_bRpcServer) {
        SPDK_NOTICELOG("[libstorage_rpc]Do not start libstorage rpc server.\n");
        return;
    }

    spdk_rpc_set_state(SPDK_RPC_STARTUP);
    SPDK_NOTICELOG("[libstorage_rpc]Start to create pthread for rpc server.\n");

    /* init lock for register info list */
    if (libstorage_robust_mutex_init_recursive_shared(&g_register_info_mutex) != 0) {
        SPDK_ERRLOG("[libstorage_rpc]Libstorage init lock failed!\n");
        return;
    }

    /* cleanup remaining rpc socket file if it is not used */
    libstorage_rpc_cleanup();

    /* ignore SIGPIPE for sending an exited socket connection */
    /* which will lead to procee exit */
    signal(SIGPIPE, libstorage_ignore_sig);

    if (pthread_create(&g_rpc_server_thread, NULL, libstorage_run_rpc_server, NULL) != 0) {
        SPDK_ERRLOG("[libstorage_rpc]Libstorage create pthread for rpc server fail!\n");
        return;
    }
    g_bRpcThreadIsStart = true;

    do {
        register_timeout_cnt--;
        usleep(LIBSTORAGE_RPC_REGISTER_SLEEP_USECS);
        if (register_timeout_cnt == 0) {
            break;
        }
    } while ((!g_bRpcServerIsInit) || (g_register_count != 0));
    return;
}

/* get the ctrlr_name by a pci name which is specified. */
static char *libstorage_get_ctrlr_name_by_pci_addr(const char *pci)
{
    char *ctrlName = NULL;
    struct libstorage_rpc_register_ublock_info *register_info_item = NULL;

    /* look for the global list that initiliazed before, to get the cltrlName. */
    libstorage_process_mutex_lock(&g_register_info_mutex);
    SLIST_FOREACH(register_info_item, &g_register_ublock_info_list, slist) {
        if (strcmp(register_info_item->pci, pci) == 0) {
            ctrlName = register_info_item->ctrlName;
            if (strlen(ctrlName) == 0) {
                SPDK_ERRLOG("[libstorage_rpc]Cannot get ctrlName by pci address %s!\n", pci);
                libstorage_process_mutex_unlock(&g_register_info_mutex);
                return NULL;
            }
            break;
        }
    }

    libstorage_process_mutex_unlock(&g_register_info_mutex);
    return ctrlName;
}

/* get the ctrlr by a pci address which is specified. */
static struct spdk_nvme_ctrlr *libstorage_get_ctrlr_by_pci_addr(const char *pci)
{
    char *pctrlrName = NULL;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    pctrlrName = libstorage_get_ctrlr_name_by_pci_addr(pci);
    if (pctrlrName == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]get nvme ctrlr name failed!\n");
        return NULL;
    }

    ctrlr = spdk_nvme_ctrlr_get_by_name(pctrlrName);
    return ctrlr;
}

static void free_rpc_pci_nsid_dev(struct rpc_pci_nsid_dev * const pci)
{
    if (pci->pci != NULL) {
        free(pci->pci);
        pci->pci = NULL;
    }

    return;
}

static int libstorage_get_smart_info(const char *pci, uint32_t nsid,
                                     struct spdk_nvme_health_information_page *smart_info)
{
    int rc;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    SPDK_NOTICELOG("[libstorage_rpc] libstorage_get_smart_info execute, pci: %s\n", pci);
    ctrlr = libstorage_get_ctrlr_by_pci_addr(pci);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] fail to get ctrlr by name\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    rc = spdk_nvme_ctrlr_get_smart_info(ctrlr, nsid, smart_info);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return rc;
}

static int check_para_and_get_pci_nsid(const struct spdk_jsonrpc_request *request,
                                       const struct spdk_json_val *params, struct rpc_pci_nsid_dev *pci)
{
    if (params == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]get SMART info requires parameters\n");
        return -1;
    }

    SPDK_NOTICELOG("[libstorage_rpc] get_smart_info_response begin execute, request: %p, param: %s\n",
                   request, (char*)params->start);
    if (spdk_json_decode_object(params, rpc_get_pci_nsid_decoders,
                                SPDK_COUNTOF(rpc_get_pci_nsid_decoders), pci)) {
        SPDK_ERRLOG("[libstorage_rpc]spdk_json_decode_object failed\n");
        return -1;
    }

    if (pci->pci == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]missing pci address param\n");
        return -1;
    }

    return 0;
}

static int get_smart_info_str_for_resp(struct spdk_jsonrpc_request *request,
                                       const struct rpc_pci_nsid_dev *pci, char *str_for_resp, uint32_t str_len)
{
    int ret;
    char *str_for_smart_info = NULL;

    str_for_smart_info = (char *)malloc(LIBSTORAGE_SMART_INFO_LEN);
    if (str_for_smart_info == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]malloc memory for string to stall SMART info failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        return -1;
    }

    ret = libstorage_get_smart_info(pci->pci, pci->nsid,
                                    (struct spdk_nvme_health_information_page *)str_for_smart_info);
    if (ret != 0) {
        SPDK_ERRLOG("[libstorage_rpc]get smart info from spdk failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to get smart info internal");
        goto free_and_exit;
    }

    if (str_len < LIBSTORAGE_SMART_INFO_LEN) {
        goto free_and_exit;
    }
    if (spdk_base64_encode(str_for_resp, str_for_smart_info, LIBSTORAGE_SMART_INFO_LEN) != 0) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to encode base64 for result");
        SPDK_ERRLOG("[libstorage_rpc] fail to encode base64\n");
        goto free_and_exit;
    }

    free(str_for_smart_info);
    return 0;

free_and_exit:
    free(str_for_smart_info);
    return -1;
}

static void free_str_for_resp(char *str_for_resp)
{
    free(str_for_resp);
}

static void get_smart_info_response(struct spdk_jsonrpc_request *request,
                                    const struct spdk_json_val *params)
{
    int ret;
    size_t count_resp;
    char *str_for_resp = NULL;
    uint32_t str_for_resp_len = LIBSTORAGE_SMART_INFO_LEN * 2; // 2: multiply 2 to make memory big enough
    struct spdk_json_write_ctx *w = NULL;
    struct rpc_pci_nsid_dev pci;

    pci.pci = NULL;
    ret = check_para_and_get_pci_nsid(request, params, &pci);
    if (ret != 0) {
        goto error_param;
    }

    str_for_resp = (char *)malloc(str_for_resp_len);
    if (str_for_resp == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]malloc memory for string to response failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        goto free_and_exit;
    }

    ret = get_smart_info_str_for_resp(request, &pci, str_for_resp, str_for_resp_len);
    if (ret != 0) {
        goto free_and_exit;
    }
    count_resp = spdk_base64_get_encoded_strlen(LIBSTORAGE_SMART_INFO_LEN);

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        goto free_and_exit;
    }

    spdk_json_write_object_begin(w);

    spdk_json_write_name(w, "smart_str");
    spdk_json_write_string(w, str_for_resp);

    spdk_json_write_name(w, "smart_len");
    spdk_json_write_uint64(w, count_resp);

    spdk_json_write_object_end(w);

    spdk_jsonrpc_end_result(request, w);
    goto free_and_exit;

error_param:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");

free_and_exit:
    free_rpc_pci_nsid_dev(&pci);
    free_str_for_resp(str_for_resp);
}
SPDK_RPC_REGISTER("get_smart", get_smart_info_response, SPDK_RPC_RUNTIME)

static void get_log_page_completion(void *cb_arg, const struct spdk_nvme_cpl *cpl)
{
    struct completion_poll_status *status = cb_arg;
    int rc;

    status->status = 0;
    rc = memcpy_s(&status->cpl, sizeof(struct spdk_nvme_cpl), cpl, sizeof(struct spdk_nvme_cpl));
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc]memory copy failed!\n");
        status->status = rc;
    }
    status->done = true;
}

static int libstorage_get_log_page(const char *pci, uint8_t log_page, uint32_t nsid,
                                   uint8_t *payload, uint32_t payload_size)
{
    int rc;
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    struct completion_poll_status status;

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    SPDK_NOTICELOG("[libstorage_rpc] get_log_page_response execute, pci: %s\n", pci);
    ctrlr = libstorage_get_ctrlr_by_pci_addr(pci);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]cannot get ctrlr by name");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    rc = spdk_nvme_ctrlr_cmd_get_log_page(ctrlr, log_page, nsid, payload, payload_size,
                                          0, get_log_page_completion, &status);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] cannot get log page from spdk\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return rc;
    }
    status.done = false;
    while (status.done == false) {
        (void)spdk_nvme_ctrlr_process_admin_completions(ctrlr);
    }
    if (spdk_nvme_cpl_is_error(&status.cpl) || status.status != 0) {
        SPDK_ERRLOG("get_log_page_completion failed! sc[%d], sct[%d], status[%d]\n",
                    status.cpl.status.sc, status.cpl.status.sct, status.status);
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return rc;
}

static int send_log_page_response(struct spdk_jsonrpc_request *request,
                                  uint8_t *payload, uint32_t payload_size)
{
    char *str_for_resp = NULL;
    struct spdk_json_write_ctx *wv = NULL;
    size_t count_resp;

    str_for_resp = (char *)malloc(JSONRPC_MAX_RESPONSE_LEN);
    if (str_for_resp == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] malloc response memory failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to malloc memory for response\n");
        return -1;
    }
    if (spdk_base64_encode(str_for_resp, payload, payload_size) != 0) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to encode base64 for result");
        SPDK_ERRLOG("[libstorage_rpc] fail to encode base64\n");
        free(str_for_resp);
        return -1;
    }

    count_resp = spdk_base64_get_encoded_strlen(payload_size);

    wv = spdk_jsonrpc_begin_result(request);
    if (wv == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        free(str_for_resp);
        return -1;
    }

    spdk_json_write_object_begin(wv);
    (void)spdk_json_write_name(wv, "log_page");
    (void)spdk_json_write_string(wv, str_for_resp);

    (void)spdk_json_write_name(wv, "log_page_len");
    (void)spdk_json_write_uint64(wv, count_resp);
    spdk_json_write_object_end(wv);

    spdk_jsonrpc_end_result(request, wv);

    free(str_for_resp);
    return 0;
}

static void get_log_page_response(struct spdk_jsonrpc_request *request,
                                  const struct spdk_json_val *params)
{
    struct rpc_pci_log_page log_page = {0};
    uint8_t *payload = NULL;
    int rc;

    if (spdk_json_decode_object(params, rpc_get_log_page_decoders,
                                SPDK_COUNTOF(rpc_get_log_page_decoders), &log_page)) {
        if (log_page.pci != NULL) {
            free(log_page.pci);
        }
        SPDK_ERRLOG("[libstorage_rpc]decode for calling to get error log failed.\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    if (log_page.pci == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]pci address param invalid.\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    payload = (uint8_t *)malloc(log_page.size);
    if (payload == NULL) {
        free(log_page.pci);
        SPDK_ERRLOG("[libstorage_rpc] malloc payload memory failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to malloc memory for payload\n");
        return;
    }

    rc = libstorage_get_log_page(log_page.pci, log_page.pageid, log_page.nsid, payload, log_page.size);
    if (rc != 0) {
        free(log_page.pci);
        free(payload);
        SPDK_ERRLOG("[libstorage_rpc] get log page fail from spdk\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to get log info from spdk\n");
        return;
    }

    rc = send_log_page_response(request, payload, log_page.size);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] send response failed!\n");
    }

    free(log_page.pci);
    free(payload);
    return;
}
SPDK_RPC_REGISTER("query_log_page", get_log_page_response, SPDK_RPC_RUNTIME)

static void get_reg_info_response(struct spdk_jsonrpc_request *request,
                                  const struct spdk_json_val *params)
{
    int ret = 0;
    struct spdk_json_write_ctx *w = NULL;

    SPDK_NOTICELOG("[libstorage_rpc] get_reg_info_response begin execute, request: %p, param: %s\n",
                   request, (char*)params->start);
    ret = libstorage_register_info_to_ublock();
    if (ret != 0) {
        SPDK_ERRLOG("[libstorage_rpc]Libstorage register pci info to ublock failed!\n");
    }

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        return;
    }

    spdk_json_write_string(w, "[libstorage_rpc]pci info rpc data recovery success");
    spdk_jsonrpc_end_result(request, w);

    return;
}
SPDK_RPC_REGISTER("get_reg", get_reg_info_response,  SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static int libstorage_fill_bdev_info(struct spdk_nvme_ctrlr *ctrlr, struct ublock_bdev *bdev)
{
    struct spdk_nvme_ns *ns = NULL;
    const struct spdk_nvme_ctrlr_data *cdata = NULL;
    struct spdk_pci_device *pci_dev = NULL;
    int rc;

    /* ublock does not occupy nvme ctrlr */
    bdev->ctrlr = NULL;

    cdata = spdk_nvme_ctrlr_get_data(ctrlr);
    ns = spdk_nvme_ctrlr_get_ns(ctrlr, 1);
    if (cdata == NULL || ns == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] failed to get ctrlr namespace\n");
        return -1;
    }
    /* skip the inactive namespace and report error */
    if (!spdk_nvme_ns_is_active(ns)) {
        SPDK_ERRLOG("[libstorage_rpc] ctrlr namespace[0x1] is inactive\n");
        return -1;
    }
    bdev->info.sector_size = spdk_nvme_ns_get_sector_size(ns);
    bdev->info.cap_size = spdk_nvme_ns_get_size(ns);
    bdev->info.md_size = spdk_nvme_ns_get_md_size(ns);

    pci_dev = spdk_nvme_ctrlr_get_pci_device(ctrlr);
    if (pci_dev == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] failed to get pci device\n");
        return -1;
    }
    bdev->info.device_id = spdk_pci_device_get_device_id(pci_dev);
    bdev->info.subsystem_device_id = spdk_pci_device_get_subdevice_id(pci_dev);
    bdev->info.vendor_id = cdata->vid;
    bdev->info.subsystem_vendor_id = cdata->ssvid;
    bdev->info.controller_id = cdata->cntlid;

    rc = memcpy_s(bdev->info.serial_number, sizeof(bdev->info.serial_number), cdata->sn, sizeof(cdata->sn));
    rc += memcpy_s(bdev->info.model_number, sizeof(bdev->info.model_number), cdata->mn, sizeof(cdata->mn));
    rc += memcpy_s(bdev->info.firmware_revision, sizeof(bdev->info.firmware_revision), cdata->fr, sizeof(cdata->fr));

    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] memcpy failed\n");
        return -1;
    }

    return 0;
}

/* remote query nvme device info through rpc */
static int _ublock_get_bdev(const char *pci, struct ublock_bdev *bdev)
{
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    int rc;

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    SPDK_NOTICELOG("[libstorage_rpc] libstorage get bdev execute, pci: %s\n", pci);
    ctrlr = libstorage_get_ctrlr_by_pci_addr(pci);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] failed to get pci ctrlr\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    rc = strncpy_s(bdev->pci, sizeof(bdev->pci), pci, strlen(pci));
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] memcpy failed\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    rc = libstorage_fill_bdev_info(ctrlr, bdev);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return rc;
}

static int libstorage_getinfo_fill_rsp(struct spdk_json_write_ctx *vw, const struct params *pci)
{
    int rc;
    struct ublock_bdev bdev = {};
    int8_t sn[NVME_SN_LEN + 1];
    int8_t mn[NVME_MN_LEN + 1];
    int8_t fr[NVME_FR_LEN + 1];

    rc = _ublock_get_bdev(pci->pci, &bdev);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] fail to get bdev info\n");
        return rc;
    }

    spdk_json_write_object_begin(vw);
    spdk_json_write_name(vw, "ctrlr");
    spdk_json_write_uint64(vw, 0);
    spdk_json_write_name(vw, "sector_size");
    spdk_json_write_uint64(vw, bdev.info.sector_size);
    spdk_json_write_name(vw, "cap_size");
    spdk_json_write_uint64(vw, bdev.info.cap_size);
    spdk_json_write_name(vw, "md_size");
    spdk_json_write_uint64(vw, bdev.info.md_size);
    spdk_json_write_name(vw, "device_id");
    spdk_json_write_int32(vw, bdev.info.device_id);
    spdk_json_write_name(vw, "subsystem_device_id");
    spdk_json_write_int32(vw, bdev.info.subsystem_device_id);
    spdk_json_write_name(vw, "vendor_id");
    spdk_json_write_int32(vw, bdev.info.vendor_id);
    spdk_json_write_name(vw, "subsystem_vendor_id");
    spdk_json_write_int32(vw, bdev.info.subsystem_vendor_id);
    spdk_json_write_name(vw, "controller_id");
    spdk_json_write_int32(vw, bdev.info.controller_id);

    rc = memcpy_s(sn, NVME_SN_LEN + 1, bdev.info.serial_number, NVME_SN_LEN);
    sn[NVME_SN_LEN] = '\0';
    rc += memcpy_s(mn, NVME_MN_LEN + 1, bdev.info.model_number, NVME_MN_LEN);
    mn[NVME_MN_LEN] = '\0';
    rc += memcpy_s(fr, NVME_FR_LEN + 1, bdev.info.firmware_revision, NVME_FR_LEN);
    fr[NVME_FR_LEN] = '\0';
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] snprintf fr failed\n");
        return rc;
    }

    spdk_json_write_name(vw, "serial_number");
    spdk_json_write_string(vw, sn);
    spdk_json_write_name(vw, "model_number");
    spdk_json_write_string(vw, mn);
    spdk_json_write_name(vw, "firmware_revision");
    spdk_json_write_string(vw, fr);
    spdk_json_write_object_end(vw);
    return 0;
}

static void getinfo_response(struct spdk_jsonrpc_request *request,
                             const struct spdk_json_val *params)
{
    struct spdk_json_write_ctx *vw = NULL;
    struct params pci;
    int rc;

    if (params == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "get_rpc requires parameters");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_PARSE_ERROR, "params error");
        return;
    }
    SPDK_NOTICELOG("[libstorage_rpc] getinfo_response begin execute, request: %p, param: %s\n",
                   request, (char*)params->start);
    pci.pci = (char *)malloc(UBLOCK_BDEV_PCI_LEN);
    if (pci.pci == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] fail to malloc pci\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "pci malloc error");
        return;
    }

    rc = spdk_json_decode_object(params, rpc_get_plogserver_decoders,
                                 SPDK_COUNTOF(rpc_get_plogserver_decoders), &pci);
    if (rc != 0) {
        free(pci.pci);
        SPDK_ERRLOG("[libstorage_rpc] spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_PARSE_ERROR, "json decode error");
        return;
    }
    vw = spdk_jsonrpc_begin_result(request);
    if (vw == NULL) {
        free(pci.pci);
        SPDK_ERRLOG("[libstorage_rpc] spdk_jsonrpc_begin_result failed\n");
        return;
    }

    rc = libstorage_getinfo_fill_rsp(vw, &pci);
    if (rc != 0) {
        free(pci.pci);
        SPDK_ERRLOG("[libstorage_rpc] fail to get bdev info\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to get nvme device info");
        return;
    }

    /* free(vw) included */
    spdk_jsonrpc_end_result(request, vw);
    free(pci.pci);
    return;
}
SPDK_RPC_REGISTER("get_info", getinfo_response, SPDK_RPC_STARTUP |SPDK_RPC_RUNTIME)

static void free_rpc_pci_dev(struct rpc_pci_dev *pci)
{
    if (pci->pci != NULL) {
        free(pci->pci);
        pci->pci = NULL;
    }
}

static int libstorage_fail_ctrlr_by_addr(char *pci)
{
    struct spdk_nvme_ctrlr    *ctrlr = NULL;
    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);
    ctrlr = spdk_nvme_bdev_ctrlr_get(pci);
    if (ctrlr == NULL) {
        SPDK_WARNLOG("[libstorage_rpc] ctrlr have been freed\n");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        /*
         * When rpc want to fail ctrlr, but the ctrlr has been removed.
         * Return -1 to send error to ublock_server for more message.
         */
        return -1;
    }

    SPDK_WARNLOG("[libstorage_rpc] libstorage_fail_ctrlr_by_addr execute, pci: %s\n", pci);
    spdk_set_thread(g_masterThread);
    spdk_bdev_fail_ctrlr(ctrlr->cb_ctx, ctrlr);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return 0;
}

static void free_nvme_ctrlr(struct spdk_jsonrpc_request *request,
                            const struct spdk_json_val *params)
{
    struct rpc_pci_dev pci = {0};
    struct spdk_json_write_ctx *w = NULL;
    char *ctrlName = NULL;

    if ((params == NULL) || (request == NULL)) {
        SPDK_ERRLOG("[libstorage_rpc]free nvme ctrlr requires parameters\n");
        goto invalid;
    }

    SPDK_WARNLOG("[libstorage_rpc] free nvme ctrlr begin execute, request: %p, param: %s\n",
                 request, (char*)params->start);
    if (spdk_json_decode_object(params, rpc_get_plogserver_decoders,
                                SPDK_COUNTOF(rpc_get_plogserver_decoders), &pci)) {
        SPDK_ERRLOG("[libstorage_rpc]spdk_json_decode_object failed\n");
        goto invalid;
    }

    if (pci.pci == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]missing pci address param\n");
        goto invalid;
    }

    ctrlName = libstorage_get_ctrlr_name_by_pci_addr(pci.pci);
    if (ctrlName == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] failed to ctrlr name by pci,  %s maybe already reset driver\n", pci.pci);
        goto invalid;
    }

    libstorage_remove_ctrlr_cap_info(ctrlName);
    libstorage_remove_rpc_register_info(ctrlName);

    if (libstorage_fail_ctrlr_by_addr(pci.pci) != 0) {
        goto invalid;
    }

    SPDK_WARNLOG("[libstorage_rpc] free_nvme_ctrlr end execute, request: %p, param: %s\n",
                 request, (char*)params->start);
    free_rpc_pci_dev(&pci);

    /* begin to send successful response message */
    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        return;
    }

    spdk_json_write_object_begin(w);

    /* return result to caller. */
    spdk_json_write_name(w, "result");
    spdk_json_write_string(w, "success");

    spdk_json_write_object_end(w);
    spdk_jsonrpc_end_result(request, w);

    return;

invalid:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
    free_rpc_pci_dev(&pci);
}
SPDK_RPC_REGISTER("free_ctrlr", free_nvme_ctrlr, SPDK_RPC_RUNTIME)

static int rpc_iostat_decode(const struct spdk_json_val *params, struct rpc_iostat_dev *iostat_dev)
{
    if (spdk_json_decode_object(params, rpc_get_iostat_decoders, SPDK_COUNTOF(rpc_get_iostat_decoders), iostat_dev)) {
        SPDK_ERRLOG("[libstorage_rpc]spdk_json_decode_object failed\n");
        return -1;
    }

    if (iostat_dev->pci == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]missing pci address param\n");
        return -1;
    }

    if (iostat_dev->iostat_enable == (int32_t)LIBSTORAGE_IOSTAT_DISABLE) {
        g_libstorage_iostat = (int32_t)LIBSTORAGE_IOSTAT_DISABLE;
    } else if (iostat_dev->iostat_enable == (int32_t)LIBSTORAGE_IOSTAT_ENABLE) {
        g_libstorage_iostat = (int32_t)LIBSTORAGE_IOSTAT_ENABLE;
    } else if (iostat_dev->iostat_enable != (int32_t)LIBSTORAGE_IOSTAT_QUERY) {
        SPDK_ERRLOG("[libstorage_rpc]error iostat param\n");
        return -1;
    }

    return 0;
}

static void send_iostat_response(struct spdk_jsonrpc_request *request, bool find_ctrl_register_info)
{
    struct spdk_json_write_ctx *w = NULL;
    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        return;
    }

    spdk_json_write_object_begin(w);

    /* return result to caller. */
    spdk_json_write_name(w, "iostat");

    if (g_libstorage_iostat) {
        if (find_ctrl_register_info) {
            spdk_json_write_string(w, "enable-pci-exist");
        } else {
            spdk_json_write_string(w, "enable-pci-invalid");
        }
    } else {
        if (find_ctrl_register_info) {
            spdk_json_write_string(w, "disable-pci-exist");
        } else {
            spdk_json_write_string(w, "disable-pci-invalid");
        }
    }

    spdk_json_write_object_end(w);
    spdk_jsonrpc_end_result(request, w);
    return;
}

static void enable_iostat_response(struct spdk_jsonrpc_request *request,
                                   const struct spdk_json_val *params)
{
    struct rpc_iostat_dev iostat_dev = {0};
    bool find_ctrl_register_info = false;

    if (params == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]iostat enable requires parameters\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    if (rpc_iostat_decode(params, &iostat_dev)) {
        if (iostat_dev.pci != NULL) {
            free(iostat_dev.pci);
        }
        SPDK_ERRLOG("[libstorage_rpc]enable_iostat_response decode iostat failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    /* query register_info_ublock_info_list */
    find_ctrl_register_info = libstorage_is_already_register_info(iostat_dev.pci);

    /* begin to send successful response message */
    send_iostat_response(request, find_ctrl_register_info);

    free(iostat_dev.pci);
    return;
}
SPDK_RPC_REGISTER("enable_iostat", enable_iostat_response, SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static void free_rpc_pci_err_dev(struct rpc_pci_errs_dev* const pci)
{
    if (pci->pci != NULL) {
        free(pci->pci);
        pci->pci = NULL;
    }
}

static int libstorage_get_error_info(const char *pci, uint32_t err_entries,
                                     struct spdk_nvme_error_information_entry *error_info)
{
    int rc;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);

    SPDK_NOTICELOG("[libstorage_rpc] get_error_info_response execute, pci: %s\n", pci);
    ctrlr = libstorage_get_ctrlr_by_pci_addr(pci);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]cannot get ctrlr by name");
        libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
        return -1;
    }

    rc = spdk_nvme_ctrlr_get_error_info(ctrlr, err_entries, error_info);
    libstorage_process_mutex_unlock(g_libstorage_admin_op_mutex);
    return rc;
}

static void libstorage_geterr_fill_rsp(struct spdk_json_write_ctx *wv, int errs,
                                       const struct spdk_nvme_error_information_entry *info)
{
    int i;
    spdk_json_write_object_begin(wv);

    /* begin of the array */
    spdk_json_write_name(wv, "error_info");
    spdk_json_write_array_begin(wv);

    /* loop for writing element of the array. */
    for (i = 0; i < errs; i++) {
        uint16_t status = 0;
        /* begin of the object which is the element of the array. */
        spdk_json_write_object_begin(wv);

        spdk_json_write_name(wv, "error_count");
        spdk_json_write_uint64(wv, info[i].error_count);
        spdk_json_write_name(wv, "sqid");
        spdk_json_write_uint32(wv, info[i].sqid);
        spdk_json_write_name(wv, "cid");
        spdk_json_write_uint32(wv, info[i].cid);
        spdk_json_write_name(wv, "status");
        if (memcpy_s(&status, sizeof(uint16_t), &(info[i].status), sizeof(info[0].status)) != 0) {
            SPDK_ERRLOG("[libstorage_rpc] memcpy failed!\n");
        }
        spdk_json_write_uint32(wv, status);
        spdk_json_write_name(wv, "error_location");
        spdk_json_write_uint32(wv, info[i].error_location);
        spdk_json_write_name(wv, "lba");
        spdk_json_write_uint64(wv, info[i].lba);
        spdk_json_write_name(wv, "nsid");
        spdk_json_write_uint32(wv, info[i].nsid);
        spdk_json_write_name(wv, "vendor_specific");
        spdk_json_write_uint32(wv, info[i].vendor_specific);

        /* end of the element object. */
        spdk_json_write_object_end(wv);
    }

    /* end of the array */
    spdk_json_write_array_end(wv);
}

static void get_error_info_response(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
    int errs;
    struct spdk_json_write_ctx *wv = NULL;
    struct spdk_nvme_error_information_entry error_info;
    struct rpc_pci_errs_dev pci = {};

    pci.pci = NULL;
    if (params == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]get error log info requires parameters.");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    SPDK_NOTICELOG("[libstorage_rpc] get_error_info_response begin execute, request: %p, param: %s\n",
                   request, (char*)params->start);
    if (spdk_json_decode_object(params, rpc_get_pci_errs_decoders,
                                SPDK_COUNTOF(rpc_get_pci_errs_decoders), &pci)) {
        free_rpc_pci_err_dev(&pci);
        SPDK_ERRLOG("[libstorage_rpc]decode for calling to get error log failed.\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    if (pci.pci == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]pci address param invalid.\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        return;
    }

    errs = libstorage_get_error_info(pci.pci, pci.err_entries, &error_info);
    if (errs < 0) {
        SPDK_ERRLOG("[libstorage_rpc]get error log info from spdk failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to get error info internal");
        free_rpc_pci_err_dev(&pci);
        return;
    }

    wv = spdk_jsonrpc_begin_result(request);
    if (wv == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        free_rpc_pci_err_dev(&pci);
        return;
    }

    libstorage_geterr_fill_rsp(wv, errs, &error_info);
    spdk_json_write_object_end(wv);

    spdk_jsonrpc_end_result(request, wv);
    free_rpc_pci_err_dev(&pci);
}
SPDK_RPC_REGISTER("get_error_log", get_error_info_response, SPDK_RPC_RUNTIME)

static void libstorage_admin_passthru_cb(void *cb_arg, const struct spdk_nvme_cpl *cpl)
{
    struct completion_poll_status *status = cb_arg;
    int rc;

    status->status = 0;
    rc = memcpy_s(&status->cpl, sizeof(struct spdk_nvme_cpl), cpl, sizeof(struct spdk_nvme_cpl));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fail to copy memory\n");
        status->status = rc;
    }
    status->done = true;
}

static void rpc_nvme_admin_passthru_resp(struct spdk_jsonrpc_request *request,
                                         void *buf, uint32_t nbytes)
{
    int rc;
    char *admin_resp = NULL;
    struct spdk_json_write_ctx *w = NULL;

    admin_resp = malloc(spdk_base64_get_encoded_strlen(nbytes) + 1);
    if (admin_resp == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] faile to malloc admin_resp\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "admin_resp malloc error");
        return;
    }

    rc = spdk_base64_encode(admin_resp, buf, nbytes);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] faile to get admin_resp\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "admin_resp encode error");
        free(admin_resp);
        return;
    }

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] spdk_jsonrpc_begin_result failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_jsonrpc_begin_result error");
        free(admin_resp);
        return;
    }
    rc += spdk_json_write_object_begin(w);

    rc += spdk_json_write_name(w, "admin_resp");
    rc += spdk_json_write_string(w, admin_resp);

    rc += spdk_json_write_object_end(w);

    spdk_jsonrpc_end_result(request, w);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] spdk_write failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_write error");
    }
    free(admin_resp);
}

static int libstorage_nvme_admin_passthru(const char *pci, void *cmd, void *buf, uint32_t nbytes)
{
    int rc;
    struct spdk_nvme_ctrlr *ctrlr = NULL;
    struct completion_poll_status status;

    if (pci == NULL || cmd == NULL || buf == NULL || nbytes > LIBSTORAGE_ADMIN_CMD_BUF_MAX_SIZE) {
        SPDK_ERRLOG("[libstorage_rpc] invalid parameters.\n");
        return -1;
    }

    (void)libstorage_process_mutex_lock(g_libstorage_admin_op_mutex);
    ctrlr = libstorage_get_ctrlr_by_pci_addr(pci);
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] fail to get ctrlr by name\n");
        rc = -1;
        goto out;
    }

    status.done = false;
    rc = spdk_nvme_ctrlr_cmd_admin_raw(ctrlr, cmd, buf, nbytes, libstorage_admin_passthru_cb, &status);
    if (rc != 0) {
        goto out;
    }
    while (status.done == false) {
        (void)spdk_nvme_ctrlr_process_admin_completions(ctrlr);
    }
    if (spdk_nvme_cpl_is_error(&status.cpl) || status.status != 0) {
        SPDK_ERRLOG("libstorage_nvme_admin_passthru failed! sc[%d], sct[%d], status[%d]\n",
                    status.cpl.status.sc, status.cpl.status.sct, status.status);
        rc = -ENXIO;
    }
out:
    (void)pthread_mutex_unlock(g_libstorage_admin_op_mutex);
    return rc;
}

static void *nvme_admin_passthru_cmd_alloc_and_parse(const void *pci_cmd)
{
    int rc;
    size_t size;
    void *cmd = NULL;

    cmd = malloc(NVME_ADMIN_CMD_SIZE);
    if (cmd == NULL) {
        SPDK_ERRLOG("fail to malloc cmd\n");
        return NULL;
    }
    rc = spdk_base64_decode(cmd, &size, pci_cmd);
    if (rc < 0 || size != NVME_ADMIN_CMD_SIZE) {
        SPDK_ERRLOG("fail to decode cmd\n");
        free(cmd);
        return NULL;
    }
    return cmd;
}

static void nvme_admin_passthru_cmd_free(void *cmd)
{
    if (cmd) {
        free(cmd);
    }
}

static void rpc_admin_passthru_free(struct rpc_admin_passthru *pci)
{
    if (!pci) {
        return;
    }

    if (pci->pci) {
        free(pci->pci);
        pci->pci = NULL;
    }
    if (pci->cmd) {
        free(pci->cmd);
        pci->cmd = NULL;
    }
}
static void nvme_admin_passthru_response(struct spdk_jsonrpc_request *request,
                                         const struct spdk_json_val *params)
{
    int rc;
    void *cmd = NULL;
    void *buf = NULL;
    struct rpc_admin_passthru pci = {0x0};

    if (params == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] admin_passthru_response requires parameters\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "params error");
        goto out;
    }

    if (spdk_json_decode_object(params, rpc_admin_passthru_decoders,
                                SPDK_COUNTOF(rpc_admin_passthru_decoders), &pci)) {
        SPDK_ERRLOG("[libstorage_rpc]spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        goto out;
    }

    cmd = nvme_admin_passthru_cmd_alloc_and_parse(pci.cmd);
    if (cmd == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "parse cmd error");
        goto out;
    }

    buf = spdk_malloc(pci.nbytes, 0, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
    if (buf == NULL) {
        SPDK_ERRLOG("[libstorage_rpc] fail to calloc buf\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "buf malloc error");
        goto out;
    }

    rc = libstorage_nvme_admin_passthru(pci.pci, cmd, buf, pci.nbytes);
    if (rc != 0) {
        SPDK_ERRLOG("[libstorage_rpc] nvme admin passthru failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "nvme admin passthru failed");
        goto out;
    }

    rpc_nvme_admin_passthru_resp(request, buf, pci.nbytes);
out:
    rpc_admin_passthru_free(&pci);
    nvme_admin_passthru_cmd_free(cmd);
    spdk_free(buf);
}
SPDK_RPC_REGISTER("admin_passthru", nvme_admin_passthru_response, SPDK_RPC_RUNTIME)

