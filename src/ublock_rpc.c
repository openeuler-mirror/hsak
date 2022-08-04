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
 * Description: ublock rpc module
 * Author: zhoupengchen
 * Create: 2018-9-1
 */

#include <stdlib.h>
#include <pthread.h>
#include <spdk/log.h>
#include <spdk/rpc.h>
#include <spdk/util.h>
#include <spdk/base64.h>

#include <sys/queue.h>
#include <sys/prctl.h>

#include "ublock.h"
#include "ublock_internal.h"

#define UNUSED_VARIABLE(x) ((void)(x))

static struct sockaddr_un g_rpc_listen_addr_unix = {0x0};
static struct spdk_jsonrpc_server *g_jsonrpc_server = NULL;
static uint8_t THREAD_EXIT = 0;
static uint8_t g_monitorExit = 0;
static pthread_t RPC_TID = 0;
static pthread_t g_monitorTid = 0;
static uint64_t g_rpcCnt = 0;
static SLIST_HEAD(, ublock_rpc_method) g_rpc_methods = SLIST_HEAD_INITIALIZER(g_rpc_methods);

static void ublock_jsonrpc_handler(struct spdk_jsonrpc_request *request,
                                   const struct spdk_json_val *method,
                                   const struct spdk_json_val *params);

static int ublock_init_shm(void)
{
    char *path = UBLOCK_RPC_SHM_FILE_NAME;
    int shm_fd = -1;
    /* init share memory */
    shm_fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 0600); /* access mode 0600 */
    if (shm_fd < 0) {
        SPDK_WARNLOG("[ublock] share memory object in %s already exist\n", path);
        shm_fd = shm_open(path, O_RDWR, 0600); /* access mode 0600 */
        if (shm_fd < 0) {
            SPDK_ERRLOG("[ublock] shm_open failed: %s\n", strerror(errno));
            (void)shm_unlink(path);
            return -1;
        }
    }
    /* specify the size of share memory */
    if (ftruncate(shm_fd, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM) == -1) {
        SPDK_ERRLOG("[ublock] frtuncate failed: %s\n", strerror(errno));
        close(shm_fd);
        (void)shm_unlink(path);
        return -1;
    }
    close(shm_fd);
    return 0;
}

int ublock_rpc_listen(const char *listen_addr)
{
    if (listen_addr == NULL) {
        SPDK_ERRLOG("[ublock] fail to listen at an empty address\n");
        return -1;
    }

    if (memset_s(&g_rpc_listen_addr_unix, sizeof(g_rpc_listen_addr_unix),
                 0, sizeof(g_rpc_listen_addr_unix)) != 0) {
        SPDK_ERRLOG("[ublock] memset failed!\n");
        return -1;
    }
    if (listen_addr[0] == '/') {
        /* listen at local socket file */
        int rc;

        g_rpc_listen_addr_unix.sun_family = AF_UNIX;
        rc = snprintf_s(g_rpc_listen_addr_unix.sun_path,
                        sizeof(g_rpc_listen_addr_unix.sun_path),
                        strlen(UBLOCK_RPC_ADDR),
                        "%s",
                        listen_addr);
        if (rc < 0 || (size_t)rc >= sizeof(g_rpc_listen_addr_unix.sun_path)) {
            SPDK_ERRLOG("[ublock] RPC Listen address Unix socket path too long\n");
            g_rpc_listen_addr_unix.sun_path[0] = '\0';
            return -1;
        }

        /* try to cleanup socket file to start up rpc service */
        if (unlink(g_rpc_listen_addr_unix.sun_path) == 0) {
            /* ublock rpc socket file has an unique name, so it */
            /* can be deleted without worrying conflict before binding */
            SPDK_WARNLOG("[ublock] RPC Unix domain socket path already exists.\n");
        }

        g_jsonrpc_server = spdk_jsonrpc_server_listen(AF_UNIX, 0,
                                                      (struct sockaddr *)&g_rpc_listen_addr_unix,
                                                      sizeof(g_rpc_listen_addr_unix),
                                                      ublock_jsonrpc_handler);
    }

    if (g_jsonrpc_server == NULL) {
        SPDK_ERRLOG("[ublock] ublock_rpc_listen() failed\n");
        /* try to delete the socket file for failing to listen */
        (void)unlink(g_rpc_listen_addr_unix.sun_path);
        return -1;
    }

    return 0;
}

static int ublock_rpc_thread_close(pthread_t thread)
{
    THREAD_EXIT = 1;
    /* wait util the thread has already exit */
    if (pthread_join(thread, NULL) != 0) {
        return -1;
    }

    SPDK_NOTICELOG("[ublock] RPC server thread has been killed\n");
    return 0;
}

static int ublock_monitor_thread_close(pthread_t thread)
{
    g_monitorExit = 1;
    (void)pthread_cancel(thread);
    if (pthread_join(thread, NULL) != 0) {
        return -1;
    }

    SPDK_NOTICELOG("[ublock] RPC monitor thread has been killed\n");
    return 0;
}

static void ublock_jsonrpc_server_shutdown(struct spdk_jsonrpc_server *server)
{
    struct spdk_jsonrpc_server_conn *conn = NULL;
    if (server == NULL) {
        return;
    }

    close(server->sockfd);

    TAILQ_FOREACH(conn, &server->conns, link) {
        close(conn->sockfd);
    }

    free(server);
}

static void ublock_rpc_close_print_status(int rpc_is_started)
{
    /* stop sharing registered info when stop RPC service */
    switch (rpc_is_started) {
        case 0: /* 0 means rpc thread and g_jsonrpc_server are all NULL */
            SPDK_NOTICELOG("[ublock] rpc close with rpc thread and g_jsonrpc_server all NULL\n");
            break;
        case 1: /* 1 means rpc thread is started, g_jsonrpc_server is NULL */
            SPDK_NOTICELOG("[ublock] rpc close with rpc thread started and g_jsonrpc_server NULL\n");
            break;
        case 2: /* 2 means rpc service is started */
            SPDK_NOTICELOG("[ublock] rpc close with rpc service started\n");
            break;
        default:
            SPDK_ERRLOG("[ublock] rpc close, wrong status\n");
            break;
    }
    if (rpc_is_started == 2) { /* 2 means rpc service is started */
        if (shm_unlink(UBLOCK_RPC_SHM_FILE_NAME) == -1) {
            SPDK_WARNLOG("[ublock] shm_unlink failed: %s\n", strerror(errno));
        }
    }
    return;
}

void ublock_rpc_close(void)
{
    /* in ublock, rpc service is started in RPC thread */
    /* and the RPC thread provides service in g_jsonrpc_server */
    int rpc_is_started = 0;
    int rpcStatus;

    if (g_monitorTid != 0) {
        if (ublock_monitor_thread_close(g_monitorTid) == -1) {
            rpcStatus = pthread_kill(g_monitorTid, 0);
            if (rpcStatus != ESRCH) {
                return;
            }
        }
        /* rpc monitor pthread has already been killed */
        g_monitorTid = 0;
    }

    if (RPC_TID != 0) {
        if (ublock_rpc_thread_close(RPC_TID) == -1) {
            rpcStatus = pthread_kill(RPC_TID, 0);
            if (rpcStatus != ESRCH) {
                /* RPC_TID is still alive, do not free g_jsonrpc_server */
                return;
            }
        }
        /* pthread has already been killed */
        RPC_TID = 0;

        rpc_is_started++;
    }

    if (g_jsonrpc_server != NULL) {
        if (g_rpc_listen_addr_unix.sun_path[0] != '\0') {
            /* Delete the Unix socket file */
            (void)unlink(g_rpc_listen_addr_unix.sun_path);
        }

        ublock_jsonrpc_server_shutdown(g_jsonrpc_server);
        g_jsonrpc_server = NULL;

        rpc_is_started++;
    }
    ublock_rpc_close_print_status(rpc_is_started);
}

static void *ublock_rpc_block_accept(void *arg)
{
    /* start server */
    SPDK_NOTICELOG("[ublock] ublock RPC server running\n");

    /* set ublock rpc server thread name as 'ublock_server'
     * for debug purpose.
     */
    prctl(PR_SET_NAME, "ublock_server");

    while (1) {
        if (THREAD_EXIT == 1) {
#ifdef DEBUG
            SPDK_NOTICELOG("[ublock] THREAD_EXIT trigger\n");
#endif
            break;
        }

        /* if the socket file is deleted, restart the socket listen */
        if (access(g_rpc_listen_addr_unix.sun_path, F_OK) == -1) {
            ublock_jsonrpc_server_shutdown(g_jsonrpc_server);
            g_jsonrpc_server = NULL;
            ublock_rpc_listen(UBLOCK_RPC_ADDR);
        }

        ublock_rpc_accept();
        usleep(100000); /* pending 100000 us */

        if (g_rpcCnt == UINT_MAX) {
            g_rpcCnt = 0;
        }
        g_rpcCnt++;
    }

    return ((void *)0);
}

static void *ublock_rpc_monitor(void *arg)
{
    uint64_t lastCnt;

    UNUSED_VARIABLE(arg);

    /* start monitor */
    SPDK_NOTICELOG("[ublock] ublock RPC monitor running\n");

    /* set ublock rpc monitor thread name as 'ublock_monitor'
     * for debug purpose.
     */
    (void)prctl(PR_SET_NAME, "ublock_monitor");

    while (1) {
        if (g_monitorExit == 1) {
            break;
        }

        lastCnt = g_rpcCnt;

        (void)sleep(60); /* pending 60s: 64 conns * 1s */

        if (lastCnt == g_rpcCnt) {
            SPDK_ERRLOG("[ublock] ublock server hangs and exit\n");
            ublock_fini();
            exit(0);
        }
    }

    return ((void *)0);
}

void ublock_rpc_accept(void)
{
    spdk_jsonrpc_server_poll(g_jsonrpc_server);
}

static int ublock_pth_start_rpc(void)
{
    int err;
    int retry_create = 0;
    int retryMonitor = 0;

create:
    /* create rpc thread */
    THREAD_EXIT = 0;
    err = pthread_create(&RPC_TID,
                         NULL,
                         ublock_rpc_block_accept,
                         UBLOCK_RPC_ADDR);
    if (err != 0) {
        if (err == EAGAIN && retry_create == 0) {
            retry_create = 1;
            goto create;
        }
        SPDK_ERRLOG("[ublock] fail to create thread, error code: %d\n", err);
        return -1;
    }

monitor:
    g_monitorExit = 0;
    /* create rpc monitor thread */
    err = pthread_create(&g_monitorTid,
                         NULL,
                         ublock_rpc_monitor,
                         NULL);
    if (err != 0) {
        if (err == EAGAIN && retryMonitor == 0) {
            retryMonitor = 1;
            goto monitor;
        }
        SPDK_ERRLOG("[ublock] fail to create monitor thread, error code: %d\n", err);
        return -1;
    }

    return 0;
}

int ublock_start_rpc(const char *listen_addr)
{
    int rc;

    if (ublock_init_shm() != 0) {
        SPDK_ERRLOG("[ublock] init share memory failed\n");
        return -1;
    }

    if (listen_addr == NULL) {
        SPDK_ERRLOG("[ublock] fail to start rpc server at empty listen address\n");
        return -1;
    }

    rc = ublock_rpc_listen(listen_addr);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fail to start rpc server socket at %s\n", listen_addr);
        return rc;
    }

    rc = ublock_pth_start_rpc();
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fail to start rpc server socket at a new thread\n");
        /* restore the values set by calling ublock_rpc_listen(listen_addr) */
        ublock_jsonrpc_server_shutdown(g_jsonrpc_server);
        g_jsonrpc_server = NULL;

        /* try to delete socket file if it exists */
        (void)unlink(g_rpc_listen_addr_unix.sun_path);

        /* reset g_rpc_listen_addr_unix as initialization: */
        if (memset_s(&g_rpc_listen_addr_unix,
                     sizeof(g_rpc_listen_addr_unix),
                     0,
                     sizeof(g_rpc_listen_addr_unix)) != 0) {
            SPDK_ERRLOG("[ublock] memset failed!\n");
        }
        return rc;
    }
    SPDK_NOTICELOG("[ublock] rpc at %s started\n", listen_addr);

    return rc;
}

/* RPC server handler to process json request */
static void ublock_jsonrpc_handler(struct spdk_jsonrpc_request *request,
                                   const struct spdk_json_val *method,
                                   const struct spdk_json_val *params)
{
    struct ublock_rpc_method *m = NULL;

    if (method == NULL) {
        SPDK_ERRLOG("[ublock] method is empty\n");
        spdk_jsonrpc_send_error_response(request,
                                         -1,
                                         "method is empty");
        return;
    }

    SPDK_NOTICELOG("[ublock] ublock_jsonrpc_handler request: %p, handling method: %s\n",
                   request, (char *)method->start);

    SLIST_FOREACH(m, &g_rpc_methods, slist) {
        if (spdk_json_strequal(method, m->name)) {
            m->func(request, params);
            return;
        }
    }

    spdk_jsonrpc_send_error_response(request,
                                     SPDK_JSONRPC_ERROR_METHOD_NOT_FOUND,
                                     "Method not found");
}

void ublock_rpc_register_method(const char *method,
                                ublock_rpc_method_handler func)
{
    struct ublock_rpc_method *m;

    m = calloc(1, sizeof(struct ublock_rpc_method));
    if (m == NULL) {
        SPDK_ERRLOG("[ublock] fail to calloc m\n");
        return;
    }

    m->name = strdup(method);
    if (m->name == NULL) {
        SPDK_ERRLOG("[ublock] fail to strdup method name\n");
        free(m);
        return;
    }

    m->func = func;

    SLIST_INSERT_HEAD(&g_rpc_methods, m, slist);
}

/* plog_server register socket address into ublock for establishing connection */
struct ublock_plog_server {
    char *pci;
    char *plg_sock_addr;
    char *ctrlr_name;
    SLIST_ENTRY(ublock_plog_server)
    slist;
};

static SLIST_HEAD(, ublock_plog_server) g_plog_server = SLIST_HEAD_INITIALIZER(g_plog_server);

#define SLIST_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = SLIST_FIRST((head));                     \
            (var) && ((tvar) = SLIST_NEXT((var), field), 1); \
            (var) = (tvar))

void ublock_stop_rpc(void)
{
    struct ublock_rpc_method *m = NULL;
    struct ublock_rpc_method *tmp = NULL;

    ublock_rpc_close();

    SLIST_FOREACH_SAFE(m, &g_rpc_methods, slist, tmp) {
        SLIST_REMOVE(&g_rpc_methods, m, ublock_rpc_method, slist);
        if (m->name) {
            free(m->name);
        }
        free(m);
    }
}

static int ublock_share_reginfo(void)
{
    int rc;
    int shm_fd = -1;
    int reg_plg_counter;
    char *path = UBLOCK_RPC_SHM_FILE_NAME;
    plog_server_sh *plg_map = NULL;
    struct ublock_plog_server *each_plgs = NULL;
    struct stat statbuf;

    shm_fd = shm_open(path, O_RDWR, 0600); /* access mode 0600 */
    if (shm_fd < 0) {
        SPDK_ERRLOG("[ublock] shm_open share memory failed\n");
        return -1;
    }

    rc = fstat(shm_fd, &statbuf);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fstat failed: %s\n", strerror(errno));
        close(shm_fd);
        return -1;
    }
    if (statbuf.st_size != sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM) {
        SPDK_ERRLOG("[ublock] share memory is broken\n");
        close(shm_fd);
        return -1;
    }

    plg_map = (plog_server_sh *)mmap(NULL,
                                     sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM,
                                     PROT_WRITE,
                                     MAP_SHARED,
                                     shm_fd,
                                     0);
    if (plg_map == (void *)-1) {
        SPDK_ERRLOG("[ublock] mmap failed: %s\n", strerror(errno));
        close(shm_fd);
        plg_map = NULL;
        return -1;
    }
    close(shm_fd);

    reg_plg_counter = 0;
    rc = 0;
    SLIST_FOREACH(each_plgs, &g_plog_server, slist) {
        if (reg_plg_counter < UBLOCK_PLG_DEVICE_MAX_NUM) {
            rc += memcpy_s(plg_map[reg_plg_counter].pci,
                           sizeof(plg_map[reg_plg_counter].pci),
                           each_plgs->pci,
                           strlen(each_plgs->pci) + 1);
            rc += memcpy_s(plg_map[reg_plg_counter].plg_sock_addr,
                           sizeof(plg_map[reg_plg_counter].plg_sock_addr),
                           each_plgs->plg_sock_addr,
                           strlen(each_plgs->plg_sock_addr) + 1);
            rc += memcpy_s(plg_map[reg_plg_counter].ctrlr_name,
                           sizeof(plg_map[reg_plg_counter].ctrlr_name),
                           each_plgs->ctrlr_name,
                           strlen(each_plgs->ctrlr_name) + 1);
            if (rc != 0) {
                SPDK_ERRLOG("[ublock] memcpy failed!\n");
                (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
                return -1;
            }
            SPDK_NOTICELOG("[ublock] share plog_server: %d\n", reg_plg_counter);
            SPDK_NOTICELOG("[ublock] share plog_server->pci: %s\n",
                           plg_map[reg_plg_counter].pci);
            SPDK_NOTICELOG("[ublock] share plog_server->plg_sock_addr: %s\n",
                           plg_map[reg_plg_counter].plg_sock_addr);
            SPDK_NOTICELOG("[ublock] share plog_server->ctrlr_name: %s\n",
                           plg_map[reg_plg_counter].ctrlr_name);
            reg_plg_counter++;
        } else {
            /* share memory initialization seems ok, and do not shm_unlink */
            SPDK_ERRLOG("[ublock] too many plog_server registered\n");
            (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
            return -1;
        }
    }

    (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
    return 0;
}

static const struct spdk_json_object_decoder rpc_plogserver_decoders[] = {
    {
        "pci",
        offsetof(struct ublock_plog_server, pci),
        spdk_json_decode_string,
    },
    {
        "plg_sock_addr",
        offsetof(struct ublock_plog_server, plg_sock_addr),
        spdk_json_decode_string,
    },
    {
        "ctrlr_name",
        offsetof(struct ublock_plog_server, ctrlr_name),
        spdk_json_decode_string,
    },
};

static int ublock_rpc_regresponse(struct spdk_jsonrpc_request *request)
{
    struct spdk_json_write_ctx *w;

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        return -1;
    }
    spdk_json_write_string(w, "register ok");
    spdk_jsonrpc_end_result(request, w);

    return 0;
}

static void ublock_plog_server_free(struct ublock_plog_server *plog_server)
{
    if (plog_server == NULL) {
        return;
    }

    free(plog_server->ctrlr_name);
    plog_server->ctrlr_name = NULL;

    free(plog_server->plg_sock_addr);
    plog_server->plg_sock_addr = NULL;

    free(plog_server->pci);
    plog_server->pci = NULL;

    free(plog_server);
}

static void ublock_rpc_register_plogserver(struct spdk_jsonrpc_request *request,
    const struct spdk_json_val *params)
{
    SPDK_NOTICELOG("rpc calling reg_plogserver\n");
    struct ublock_plog_server *plog_server = NULL;
    struct ublock_plog_server *each_plgs = NULL;

    plog_server = (struct ublock_plog_server *)calloc(1, sizeof(struct ublock_plog_server));
    if (plog_server == NULL) {
        SPDK_ERRLOG("[ublock] fail to calloc plog_server\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "calloc error");
        return;
    }

    if (spdk_json_decode_object(params, rpc_plogserver_decoders,
                                SPDK_COUNTOF(rpc_plogserver_decoders), plog_server) < 0) {
        ublock_plog_server_free(plog_server);
        SPDK_ERRLOG("[ublock] spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_json_decode_object error");
        return;
    }

    /* check for updating plog_server */
    SLIST_FOREACH(each_plgs, &g_plog_server, slist) {
        if (strcmp(each_plgs->pci, plog_server->pci) != 0) {
            continue;
        }
        if (strcmp(each_plgs->plg_sock_addr, plog_server->plg_sock_addr) != 0 ||
            strcmp(each_plgs->ctrlr_name, plog_server->ctrlr_name) != 0) {
            /* socket address update */
            SLIST_REMOVE(&g_plog_server, each_plgs, ublock_plog_server, slist);
            /* free malloced item of removed node */
            ublock_plog_server_free(each_plgs);
            SLIST_INSERT_HEAD(&g_plog_server, plog_server, slist);
            SPDK_NOTICELOG("[ublock] plog_server %s update registered, sock_addr %s, ctrl_name %s\n",
                           plog_server->pci, plog_server->plg_sock_addr, plog_server->ctrlr_name);
            goto end;
        }
        ublock_plog_server_free(plog_server);
        SPDK_NOTICELOG("[ublock] plog_server %s already registered, sock_addr %s, ctrl_name %s\n",
                       each_plgs->pci, each_plgs->plg_sock_addr, each_plgs->ctrlr_name);
        goto end;
    }

    /* register new plog_server */
    SLIST_INSERT_HEAD(&g_plog_server, plog_server, slist);
    SPDK_NOTICELOG("[ublock] plog_server %s new registered, sock_addr %s, ctrl_name %s\n",
                   plog_server->pci, plog_server->plg_sock_addr, plog_server->ctrlr_name);

end:
    if (ublock_share_reginfo() != 0) {
        SPDK_ERRLOG("[ublock] fail to share registered plog_server\n");
    }
    if (ublock_rpc_regresponse(request) != 0) {
        SPDK_ERRLOG("[ublock] fail to response plog_server register\n");
    }
}
UBLOCK_RPC_REGISTER("reg_plogserver", ublock_rpc_register_plogserver)

struct ublock_rpc_bdev_pci {
    char *pci;
};

static const struct spdk_json_object_decoder rpc_bdev_pci_decoders[] = {
    {
        "pci",
        offsetof(struct ublock_rpc_bdev_pci, pci),
        spdk_json_decode_string,
    },
};

static void ublock_rpc_get_bdev_info_resp(struct spdk_jsonrpc_request *request,
                                          struct ublock_bdev *bdev)
{
    struct spdk_json_write_ctx *w = NULL;

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[ublock] spdk_jsonrpc_begin_result failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_jsonrpc_begin_result error");
        return;
    }

    spdk_json_write_object_begin(w);

    spdk_json_write_name(w, "ctrlr");
    spdk_json_write_uint64(w, (uintptr_t)bdev->ctrlr);

    spdk_json_write_name(w, "sector_size");
    spdk_json_write_uint64(w, bdev->info.sector_size);

    spdk_json_write_name(w, "cap_size");
    spdk_json_write_uint64(w, bdev->info.cap_size);

    spdk_json_write_name(w, "md_size");
    spdk_json_write_uint32(w, bdev->info.md_size);

    spdk_json_write_name(w, "device_id");
    spdk_json_write_int32(w, bdev->info.device_id);

    spdk_json_write_name(w, "subsystem_device_id");
    spdk_json_write_int32(w, bdev->info.subsystem_device_id);

    spdk_json_write_name(w, "vendor_id");
    spdk_json_write_int32(w, bdev->info.vendor_id);

    spdk_json_write_name(w, "subsystem_vendor_id");
    spdk_json_write_int32(w, bdev->info.subsystem_vendor_id);

    spdk_json_write_name(w, "controller_id");
    spdk_json_write_int32(w, bdev->info.controller_id);

    spdk_json_write_name(w, "serial_number");
    char *sn = (char *)malloc(sizeof(bdev->info.serial_number) + 1);
    if (sn == NULL) {
        free(w);
        SPDK_ERRLOG("[ublock] fail to malloc sn\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to malloc sn");
        return;
    }
    if (memcpy_s(sn,
                 sizeof(bdev->info.serial_number) + 1,
                 bdev->info.serial_number,
                 sizeof(bdev->info.serial_number))) {
        free(w);
        free(sn);
        SPDK_ERRLOG("[ublock] snprintf sn failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to snprintf sn");
        return;
    }
    sn[sizeof(bdev->info.serial_number)] = '\0';
    spdk_json_write_string(w, sn);

    spdk_json_write_name(w, "model_number");
    char *mn = (char *)malloc(sizeof(bdev->info.model_number) + 1);
    if (mn == NULL) {
        free(w);
        free(sn);
        SPDK_ERRLOG("[ublock] fail to malloc mn\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to malloc mn");
        return;
    }
    if (memcpy_s(mn,
                 sizeof(bdev->info.model_number) + 1,
                 bdev->info.model_number,
                 sizeof(bdev->info.model_number)) != 0) {
        free(w);
        free(sn);
        free(mn);
        SPDK_ERRLOG("[ublock] snprintf mn failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to snprintf mn");
        return;
    }
    mn[sizeof(bdev->info.model_number)] = '\0';
    spdk_json_write_string(w, mn);

    spdk_json_write_name(w, "firmware_revision");
    char *fr = (char *)malloc(sizeof(bdev->info.firmware_revision) + 1);
    if (fr == NULL) {
        free(w);
        free(sn);
        free(mn);
        SPDK_ERRLOG("[ublock] fail to malloc fr\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to malloc fr");
        return;
    }
    if (memcpy_s(fr,
                 sizeof(bdev->info.firmware_revision) + 1,
                 bdev->info.firmware_revision,
                 sizeof(bdev->info.firmware_revision)) != 0) {
        free(w);
        free(sn);
        free(mn);
        free(fr);
        SPDK_ERRLOG("[ublock] snprintf fr failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to snprintf fr");
        return;
    }
    fr[sizeof(bdev->info.firmware_revision)] = '\0';
    spdk_json_write_string(w, fr);

    spdk_json_write_object_end(w);

    /* free(w) included */
    spdk_jsonrpc_end_result(request, w);

    free(sn);
    free(mn);
    free(fr);
    return;
}

static void ublock_rpc_get_bdev_info(struct spdk_jsonrpc_request *request,
                                     const struct spdk_json_val *params)
{
    struct ublock_rpc_bdev_pci bdev_pci = {0x0};
    struct ublock_bdev bdev = {{0x0}};

    if (params == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "get_rpc requires parameters");
        return;
    }

    if (spdk_json_decode_object(params, rpc_bdev_pci_decoders,
                                SPDK_COUNTOF(rpc_bdev_pci_decoders), &bdev_pci)) {
        free(bdev_pci.pci);
        SPDK_ERRLOG("[ublock] spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "json decode error");
        return;
    }

    int rc = _ublock_get_bdev(bdev_pci.pci, &bdev);
    if (rc == -1) {
        free(bdev_pci.pci);
        SPDK_ERRLOG("[ublock] fail to get bdev info\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to get nvme device info");
        return;
    }

    ublock_rpc_get_bdev_info_resp(request, &bdev);

    free(bdev_pci.pci);
}
UBLOCK_RPC_REGISTER("get_bdev_info", ublock_rpc_get_bdev_info)

struct ublock_rpc_pci_nsid_dev {
    char *pci;
    uint32_t nsid;
};

static const struct spdk_json_object_decoder rpc_get_pci_nsid_decoders[] = {
    { "pci", offsetof(struct ublock_rpc_pci_nsid_dev, pci), spdk_json_decode_string },
    { "nsid", offsetof(struct ublock_rpc_pci_nsid_dev, nsid), spdk_json_decode_uint32 },
};

static void ublock_rpc_send_smart_info(struct spdk_jsonrpc_request *request,
                                       const char *str_for_resp, size_t count_resp)
{
    struct spdk_json_write_ctx *w = NULL;
    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[ublock] spdk_jsonrpc_begin_result failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_jsonrpc_begin_result error");
        return;
    }
    spdk_json_write_object_begin(w);

    spdk_json_write_name(w, "smart_str");
    spdk_json_write_string(w, str_for_resp);

    spdk_json_write_name(w, "smart_len");
    spdk_json_write_uint64(w, count_resp);

    spdk_json_write_object_end(w);

    spdk_jsonrpc_end_result(request, w);
}

static void ublock_rpc_get_smart_info(struct spdk_jsonrpc_request *request,
                                      const struct spdk_json_val *params)
{
    size_t count_resp;
    char *str_for_smart_info = NULL;
    char *str_for_resp = NULL;
    struct ublock_rpc_pci_nsid_dev pci = {0x0};
    struct ublock_SMART_info smart_info = {0x0};

    if (params == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "get_smart_info requires parameters");
        return;
    }

    if (spdk_json_decode_object(params, rpc_get_pci_nsid_decoders,
                                SPDK_COUNTOF(rpc_get_pci_nsid_decoders), &pci) < 0) {
        SPDK_ERRLOG("[ublock]spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_json_decode_object error");
        goto exit;
    }

    str_for_smart_info = (char *)malloc(sizeof(char) * (UBLOCK_SMART_INFO_LEN));
    if (str_for_smart_info == NULL) {
        SPDK_ERRLOG("[ublock]malloc memory for string to stall SMART info failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        goto exit;
    }

    str_for_resp = (char *)malloc(sizeof(char) * (UBLOCK_SMART_INFO_LEN * 2)); /* multiply 2 to hold str safely */
    if (str_for_resp == NULL) {
        SPDK_ERRLOG("[ublock]malloc memory for string to response failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        goto exit;
    }

    if (_ublock_get_SMART_info(pci.pci, pci.nsid, &smart_info) != 0) {
        SPDK_ERRLOG("[ublcok]get smart info from spdk failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to get smart info internal");
        goto exit;
    }

    if (memcpy_s(str_for_smart_info, UBLOCK_SMART_INFO_LEN, &smart_info, UBLOCK_SMART_INFO_LEN) != 0) {
        SPDK_ERRLOG("[ublcok] memcpy failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to memory copy\n");
        goto exit;
    }
    if (spdk_base64_encode(str_for_resp, str_for_smart_info, UBLOCK_SMART_INFO_LEN) != 0) {
        SPDK_ERRLOG("[ublock] fail to encode string\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to encode string\n");
        goto exit;
    }
    count_resp = spdk_base64_get_encoded_strlen(UBLOCK_SMART_INFO_LEN);
    ublock_rpc_send_smart_info(request, str_for_resp, count_resp);

exit:
    free(pci.pci);
    free(str_for_smart_info);
    free(str_for_resp);
}
UBLOCK_RPC_REGISTER("get_smart_info", ublock_rpc_get_smart_info)

static void ublock_rpc_shutdown_nvme_ctrlr(struct spdk_jsonrpc_request *request,
                                const struct spdk_json_val *params)
{
    int rc;
    struct ublock_rpc_bdev_pci pci = {0};
    struct spdk_json_write_ctx *w = NULL;

    if (params == NULL) {
        SPDK_ERRLOG("[ublock] ublock_rpc_shutdown_nvme_ctrlr requires parameters\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "params error");
        return;
    }

    if (spdk_json_decode_object(params, rpc_bdev_pci_decoders,
                                SPDK_COUNTOF(rpc_bdev_pci_decoders), &pci)) {
        SPDK_ERRLOG("[libstorage_rpc]spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        free(pci.pci);
        return;
    }

    rc = _ublock_nvme_ctrlr_shutdown_reset(pci.pci, false);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock_server]fail to shutdown the ctrlr:%s!\n", pci.pci);
        free(pci.pci);
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to shut down the ctrlr internal");
        return;
    }

    free(pci.pci);
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
}
UBLOCK_RPC_REGISTER("shutdown_ctrlr_local", ublock_rpc_shutdown_nvme_ctrlr)

static void ublock_rpc_reset_nvme_ctrlr(struct spdk_jsonrpc_request *request,
                                const struct spdk_json_val *params)
{
    int rc;
    struct ublock_rpc_bdev_pci pci = {0};
    struct spdk_json_write_ctx *w = NULL;

    if (params == NULL) {
        SPDK_ERRLOG("[ublock] ublock_rpc_shutdown_nvme_ctrlr requires parameters\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "params error");
        return;
    }

    if (spdk_json_decode_object(params, rpc_bdev_pci_decoders,
                                SPDK_COUNTOF(rpc_bdev_pci_decoders), &pci)) {
        SPDK_ERRLOG("[libstorage_rpc]spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        free(pci.pci);
        return;
    }

    rc = _ublock_nvme_ctrlr_shutdown_reset(pci.pci, true);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock_server]fail to reset the ctrlr:%s!\n", pci.pci);
        free(pci.pci);
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to reset the ctrlr internal");
        return;
    }

    free(pci.pci);
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
}
UBLOCK_RPC_REGISTER("reset_ctrlr_local", ublock_rpc_reset_nvme_ctrlr)

struct ublock_rpc_pci_errs_dev {
    char *pci;
    uint32_t err_entries;
};

static const struct spdk_json_object_decoder rpc_get_pci_errs_decoders[] = {
    { "pci", offsetof(struct ublock_rpc_pci_errs_dev, pci), spdk_json_decode_string },
    { "err_entries", offsetof(struct ublock_rpc_pci_errs_dev, err_entries), spdk_json_decode_uint32 },
};

static int ublock_rpc_get_error_log_entries(const struct spdk_json_val *params,
                                            struct ublock_rpc_pci_errs_dev *pci)
{
    pci->pci = NULL;
    if (spdk_json_decode_object(params, rpc_get_pci_errs_decoders,
                                SPDK_COUNTOF(rpc_get_pci_errs_decoders), pci)) {
        SPDK_ERRLOG("[ublock]decode for calling to get error log failed.\n");
        return -1;
    }

    if (pci->pci == NULL) {
        SPDK_ERRLOG("[ublock]pci address param invalid.\n");
        return -1;
    }

    if (pci->err_entries == 0) {
        SPDK_ERRLOG("[ublock]pci error log entry invalid.\n");
        return -1;
    }

    if (pci->err_entries > UBLOCK_RPC_ERROR_LOG_MAX_COUNT) {
        SPDK_ERRLOG("[ublock] count of error log pages"
                    " should not larger than %d.\n", UBLOCK_RPC_ERROR_LOG_MAX_COUNT);
        return -1;
    }

    return 0;
}

static void ublock_rpc_get_error_log_resp(struct spdk_jsonrpc_request *request, int errs,
                                          struct ublock_nvme_error_info *error_info)
{
    int i;
    struct spdk_json_write_ctx *w = NULL;

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[libstorage_rpc]start to response rpc call failed!\n");
        return;
    }

    spdk_json_write_object_begin(w);

    /* begin of the array */
    spdk_json_write_name(w, "error_info");
    spdk_json_write_array_begin(w);

    /* loop for writing element of the array. */
    for (i = 0; i < errs; i++) {
        uint16_t status = 0;
        int rc = 0;
        /* begin of the object which is the element of the array. */
        spdk_json_write_object_begin(w);

        spdk_json_write_name(w, "error_count");
        spdk_json_write_uint64(w, error_info[i].error_count);
        spdk_json_write_name(w, "sqid");
        spdk_json_write_uint32(w, error_info[i].sqid);
        spdk_json_write_name(w, "cid");
        spdk_json_write_uint32(w, error_info[i].cid);
        spdk_json_write_name(w, "status");
        rc = memcpy_s(&status, sizeof(uint16_t), &(error_info[i].status), sizeof(error_info[0].status));
        if (rc != 0) {
            SPDK_ERRLOG("[ublcok] memcpy failed!\n");
        }
        spdk_json_write_uint32(w, status);
        spdk_json_write_name(w, "error_location");
        spdk_json_write_uint32(w, error_info[i].error_location);
        spdk_json_write_name(w, "lba");
        spdk_json_write_uint64(w, error_info[i].lba);
        spdk_json_write_name(w, "nsid");
        spdk_json_write_uint32(w, error_info[i].nsid);
        spdk_json_write_name(w, "vendor_specific");
        spdk_json_write_uint32(w, error_info[i].vendor_specific);

        /* end of the element object. */
        spdk_json_write_object_end(w);
    }

    /* end of the array */
    spdk_json_write_array_end(w);

    spdk_json_write_object_end(w);

    spdk_jsonrpc_end_result(request, w);
    return;
}

static void ublock_rpc_get_error_log_info(struct spdk_jsonrpc_request *request,
    const struct spdk_json_val *params)
{
    int errs;
    struct ublock_nvme_error_info *error_info = NULL;
    struct ublock_rpc_pci_errs_dev pci = {};

    if (params == NULL) {
        SPDK_ERRLOG("[ublock]get error log info requires parameters.\n");
        goto invalid;
    }

    if (ublock_rpc_get_error_log_entries(params, &pci) != 0) {
        SPDK_ERRLOG("[ublock] get entries of error log failed.\n");
        goto invalid;
    }

    error_info = (struct ublock_nvme_error_info *)malloc(pci.err_entries *
                 sizeof(struct ublock_nvme_error_info));
    if (error_info == NULL) {
        SPDK_ERRLOG("[ublock]allocate memory for error log page fail!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to allocate mem internal");
        goto free_and_exit;
    }

    errs = _ublock_get_error_log_info(pci.pci, pci.err_entries, error_info);
    if (errs < 0) {
        SPDK_ERRLOG("[ublock]get error log info from spdk failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to get error info internal");
        goto free_and_exit;
    }
    ublock_rpc_get_error_log_resp(request, errs, error_info);
    goto free_and_exit;

invalid:
    spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");

free_and_exit:
    if (error_info != NULL) {
        free(error_info);
    }
    if (pci.pci != NULL) {
        free(pci.pci);
    }
}
UBLOCK_RPC_REGISTER("get_error_log_info", ublock_rpc_get_error_log_info)

struct ublock_rpc_admin_passthru {
    char *pci;
    uint32_t nbytes;
    char *cmd;
};

static const struct spdk_json_object_decoder rpc_admin_passthru_decoders[] = {
    { "pci", offsetof(struct ublock_rpc_admin_passthru, pci), spdk_json_decode_string },
    { "nbytes", offsetof(struct ublock_rpc_admin_passthru, nbytes), spdk_json_decode_uint32 },
    { "cmd", offsetof(struct ublock_rpc_admin_passthru, cmd), spdk_json_decode_string },
};

static void ublock_rpc_nvme_admin_passthru_resp(struct spdk_jsonrpc_request *request,
                                                void *buf, uint32_t nbytes)
{
    int rc;
    char *admin_resp = NULL;
    struct spdk_json_write_ctx *w = NULL;

    admin_resp = malloc(spdk_base64_get_encoded_strlen(nbytes) + 1);
    if (admin_resp == NULL) {
        SPDK_ERRLOG("[ublock] faile to malloc admin_resp\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "admin_resp malloc error");
        return;
    }

    rc = spdk_base64_encode(admin_resp, buf, nbytes);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] faile to get admin_resp\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "admin_resp encode error");
        free(admin_resp);
        return;
    }

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        SPDK_ERRLOG("[ublock] spdk_jsonrpc_begin_result failed\n");
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
        SPDK_ERRLOG("[ublock] spdk_write failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "spdk_write error");
    }
    free(admin_resp);
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

static void ublock_rpc_admin_passthru_free(struct ublock_rpc_admin_passthru *pci)
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

static void ublock_rpc_nvme_admin_passthru(struct spdk_jsonrpc_request *request,
                                           const struct spdk_json_val *params)
{
    int rc;
    void *cmd = NULL;
    void *buf = NULL;
    struct ublock_rpc_admin_passthru pci = {0x0};

    if (params == NULL) {
        SPDK_ERRLOG("[ublock] ublock_rpc_admin_passthru requires parameters\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "params error");
        goto out;
    }

    if (spdk_json_decode_object(params, rpc_admin_passthru_decoders,
                                SPDK_COUNTOF(rpc_admin_passthru_decoders), &pci)) {
        SPDK_ERRLOG("[ublock]spdk_json_decode_object failed\n");
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
        SPDK_ERRLOG("[ublock] fail to malloc buf\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "buf malloc error");
        goto out;
    }

    rc = _ublock_nvme_admin_passthru(pci.pci, cmd, buf, pci.nbytes);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] nvme admin passthru failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "nvme admin passthru failed");
        goto out;
    }

    ublock_rpc_nvme_admin_passthru_resp(request, buf, pci.nbytes);
out:
    ublock_rpc_admin_passthru_free(&pci);
    nvme_admin_passthru_cmd_free(cmd);
    spdk_free(buf);
}
UBLOCK_RPC_REGISTER("admin_passthru_local", ublock_rpc_nvme_admin_passthru)

static char *ublock_get_sockaddr_shm_by_pci(const char *pci,
                                            char *ctrl_name,
                                            size_t ctrl_name_size,
                                            const plog_server_sh *plg_map)
{
    int i;
    char *sockaddr = NULL;

    for (i = 0; i < UBLOCK_PLG_DEVICE_MAX_NUM; i++) {
        if (strlen(plg_map[i].pci) == 0) {
            continue;
        }
        if (strcmp(plg_map[i].pci, pci) != 0) {
            continue;
        }
        if (strlen(plg_map[i].plg_sock_addr) > 0 && strlen(plg_map[i].plg_sock_addr) < UBLOCK_PLG_SOCK_ADDR_MAX_LEN) {
            sockaddr = (char *)malloc(strlen(plg_map[i].plg_sock_addr) + 1);
            if (sockaddr == NULL) {
                SPDK_ERRLOG("[ublock] fail to malloc sockaddr\n");
                return NULL;
            }
            if ((strcpy_s(sockaddr, strlen(plg_map[i].plg_sock_addr) + 1, plg_map[i].plg_sock_addr) != 0) ||
                (strcpy_s(ctrl_name, ctrl_name_size, plg_map[i].ctrlr_name) != 0)) {
                SPDK_ERRLOG("[ublock] strcpy failed!\n");
                free(sockaddr);
                sockaddr = NULL;
            }
            return sockaddr;
        }
    }

    return NULL;
}

char *ublock_get_sockaddr_shm(const char *pci, char *ctrl_name, size_t ctrl_name_size)
{
    int rc;
    int shm_fd = -1;
    char *path = UBLOCK_RPC_SHM_FILE_NAME;
    char *sockaddr = NULL;
    struct stat statbuf;
    plog_server_sh *plg_map = NULL;

    if ((pci == NULL) || (ctrl_name == NULL)) {
        SPDK_ERRLOG("[ublock] ublock_get_sockaddr_shm failed for pci or ctrl_name is NULL\n");
        return NULL;
    }

    if (ctrl_name_size > UBLOCK_CTRLR_NAME_MAX_LEN) {
        SPDK_ERRLOG("[ublock] len of ctrl_name is out of range\n");
        return NULL;
    }

    shm_fd = shm_open(path, O_RDONLY, 0600); /* 0600 means only root can read and write this file */
    if (shm_fd < 0) {
        SPDK_ERRLOG("[ublock] shm_open failed: %s\n", strerror(errno));
        return NULL;
    }

    rc = fstat(shm_fd, &statbuf);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fstat is failed: %s\n", strerror(errno));
        close(shm_fd);
        return NULL;
    }
    if (statbuf.st_size != sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM) {
        SPDK_ERRLOG("[ublock] share memory is broken\n");
        close(shm_fd);
        return NULL;
    }

    plg_map = (plog_server_sh *)mmap(NULL,
                                     sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM,
                                     PROT_READ,
                                     MAP_SHARED,
                                     shm_fd,
                                     0);
    if (plg_map == (void *)MAP_FAILED) {
        SPDK_ERRLOG("[ublock] mmap failed: %s\n", strerror(errno));
        close(shm_fd);
        return NULL;
    }
    close(shm_fd);

    sockaddr = ublock_get_sockaddr_shm_by_pci(pci, ctrl_name, ctrl_name_size, plg_map);
    (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
    return sockaddr;
}

char *ublock_get_sockaddr(const char *pci)
{
    struct ublock_plog_server *each_plgs = NULL;
    char *sockaddr = NULL;
    char ctrlr_name[UBLOCK_CTRLR_NAME_MAX_LEN];

    if (pci == NULL) {
        SPDK_ERRLOG("[ublock] ublock_get_sockaddr failed for pci is NULL\n");
        return NULL;
    }

    /* no register info, find it from share memory */
    if (SLIST_EMPTY(&g_plog_server)) {
        sockaddr = ublock_get_sockaddr_shm(pci, ctrlr_name, UBLOCK_CTRLR_NAME_MAX_LEN);
        return sockaddr;
    }

    SLIST_FOREACH(each_plgs, &g_plog_server, slist) {
        if (strcmp(each_plgs->pci, pci) == 0) {
            size_t addr_len;
            int rc = 0;

            addr_len = strlen(each_plgs->plg_sock_addr);
            sockaddr = (char *)malloc(addr_len + 1);
            if (sockaddr == NULL) {
                SPDK_ERRLOG("[ublock] fail to malloc sockaddr\n");
                return NULL;
            }
            rc = memcpy_s(sockaddr, addr_len, each_plgs->plg_sock_addr, addr_len);
            if (rc != 0) {
                free(sockaddr);
                SPDK_ERRLOG("[ublock] memcpy failed\n");
                return NULL;
            }
            sockaddr[addr_len] = '\0';
            return sockaddr;
        }
    }

    return NULL;
}

/* plog_server check if it is registered */
struct plogserver_name {
    char *pci;
};

static const struct spdk_json_object_decoder rpc_get_plogserver_decoders[] = {
    {
        "pci",
        offsetof(struct plogserver_name, pci),
        spdk_json_decode_string,
    },
};

static int ublock_rpc_getresponse(struct spdk_jsonrpc_request *request,
                                  const char *addr)
{
    struct spdk_json_write_ctx *w;

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        return -1;
    }
    spdk_json_write_string_fmt(w, "%s", addr);
    spdk_jsonrpc_end_result(request, w);

    return 0;
}

static void ublock_rpc_get_plogserver(struct spdk_jsonrpc_request *request,
                                      const struct spdk_json_val *params)
{
#ifdef DEBUG
    printf("rpc calling get_plogserver\n");
#endif
    struct plogserver_name *pci = NULL;
    char *sock_addr = NULL;

    pci = (struct plogserver_name *)calloc(1, sizeof(struct plogserver_name));
    if (pci == NULL) {
        SPDK_ERRLOG("[ublock] fail to malloc pci\n");
        return;
    }

    if (spdk_json_decode_object(params, rpc_get_plogserver_decoders,
                                SPDK_COUNTOF(rpc_get_plogserver_decoders), pci)) {
        free(pci->pci);
        free(pci);
        SPDK_ERRLOG("[ublock] spdk_json_decode_object failed\n");
        return;
    }

    sock_addr = ublock_get_sockaddr(pci->pci);
    if (sock_addr == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "no pci socket adress found");
    } else {
        if (ublock_rpc_getresponse(request, sock_addr) != 0) {
            SPDK_ERRLOG("[ublock] fail to response plog_server getting\n");
            spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "fail to response");
        }
    }
    free(pci->pci);
    free(pci);
    free(sock_addr);
}
UBLOCK_RPC_REGISTER("get_plogserver", ublock_rpc_get_plogserver)

struct ublock_rpc_pci_log_page {
    char *pci;
    uint8_t pageid;
    uint32_t nsid;
    uint32_t size;

};

static const struct spdk_json_object_decoder rpc_get_log_page_decoders[] = {
    { "pci", offsetof(struct ublock_rpc_pci_log_page, pci), spdk_json_decode_string },
    { "nsid", offsetof(struct ublock_rpc_pci_log_page, nsid), spdk_json_decode_uint32 },
    { "pageid", offsetof(struct ublock_rpc_pci_log_page, pageid), spdk_json_decode_uint32 },
    { "size", offsetof(struct ublock_rpc_pci_log_page, size), spdk_json_decode_uint32 },
};

static int ublock_rpc_send_log_page(struct spdk_jsonrpc_request *request,
                                    uint8_t *payload, uint32_t payload_size)
{
    struct spdk_json_write_ctx *w = NULL;
    char *str_for_resp = NULL;
    size_t count_resp;

    str_for_resp = (char *)malloc(sizeof(char) * (SPDK_JSONRPC_MAX_VALUES));
    if (str_for_resp == NULL) {
        SPDK_ERRLOG("[ublock]malloc memory for response failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        return -1;
    }

    if (spdk_base64_encode(str_for_resp, payload, payload_size) != 0) {
        free(str_for_resp);
        SPDK_ERRLOG("[ublock] fail to encode string\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to encode string\n");
        return -1;
    }

    count_resp = spdk_base64_get_encoded_strlen(payload_size);

    w = spdk_jsonrpc_begin_result(request);
    if (w == NULL) {
        free(str_for_resp);
        SPDK_ERRLOG("[ublock] spdk_jsonrpc_begin_result failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "spdk_jsonrpc_begin_result error");
        return -1;
    }

    spdk_json_write_object_begin(w);

    (void)spdk_json_write_name(w, "log_page");
    (void)spdk_json_write_string(w, str_for_resp);

    (void)spdk_json_write_name(w, "log_page_len");
    (void)spdk_json_write_uint64(w, count_resp);

    spdk_json_write_object_end(w);

    spdk_jsonrpc_end_result(request, w);

    free(str_for_resp);
    return 0;
}

static void ublock_rpc_get_log_page(struct spdk_jsonrpc_request *request,
                                    const struct spdk_json_val *params)
{
    int ret;
    struct ublock_rpc_pci_log_page pci = {0};
    void *payload = NULL;

    if (params == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "get_log_page requires parameters");
        return;
    }

    if (spdk_json_decode_object(params, rpc_get_log_page_decoders,
                                SPDK_COUNTOF(rpc_get_log_page_decoders), &pci)) {
        free(pci.pci);
        SPDK_ERRLOG("[ublock]spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "spdk_json_decode_object error");
        return;
    }

    payload = (char *)malloc(sizeof(char) * pci.size);
    if (payload == NULL) {
        SPDK_ERRLOG("[ublock]malloc memory for payload failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Fail to alloc mem");
        free(pci.pci);
        return;
    }

    ret = _ublock_get_log_page(pci.pci, pci.pageid, pci.nsid, payload, pci.size);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock]get log page from spdk failed!\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
                                         "Fail to get log page internal");
        goto exit;
    }

    ret = ublock_rpc_send_log_page(request, payload, pci.size);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock]send response failed!\n");
    }

exit:
    free(payload);
    free(pci.pci);
    return;
}
UBLOCK_RPC_REGISTER("query_log_page", ublock_rpc_get_log_page);

#ifdef SPDK_CONFIG_ERR_INJC
#define UBLOCK_RPC_ERROR_CMD_MAX_LEN 512
int ublock_send_request_err_injc(char *sockaddr, char *request_line)
{
    int fd;
    int buf_len;
    char *buf = NULL;
    int rc;

    if (sockaddr == NULL || request_line == NULL) {
        SPDK_ERRLOG("invalide parameters to send request\n");
        return -1;
    }

    fd = ublock_client_conn(sockaddr);
    if (fd == -1) {
        SPDK_ERRLOG("fail to connect socket address: %s\n", sockaddr);
        return -1;
    }

    buf = (uint8_t *)malloc(SPDK_JSONRPC_RECV_BUF_SIZE);
    if (buf == NULL) {
        SPDK_ERRLOG("malloc for buffer to recive response failed!\n");
        close(fd);
        return -1;
    }
    rc = memset_s(buf, SPDK_JSONRPC_RECV_BUF_SIZE, 0, SPDK_JSONRPC_RECV_BUF_SIZE);
    if (rc != 0) {
        SPDK_ERRLOG("memset failed!\n");
        free(buf);
        close(fd);
        return -1;
    }
    buf_len = ublock_client_send(fd, request_line, strlen(request_line), buf);
    close(fd);
    if (buf_len < 0) {
        SPDK_ERRLOG("fail to send request to sockaddr %s\n", sockaddr);
        free(buf);
        return -1;
    }
    // if ublock has error internal, it will response message except "success".
    if (strstr(buf, "success") == NULL) {
        SPDK_ERRLOG("error occurs in ublock to handle error injection.\n");
        SPDK_ERRLOG("error response is %s\n", buf);
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}
#endif
