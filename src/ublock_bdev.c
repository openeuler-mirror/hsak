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
 * Description: ublock module
 * Author: zhoupengchen
 * Create: 2018-9-1
 */

#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <regex.h>
#include <rte_eal.h>
#include <rte_bus_pci.h>
#include <spdk/env.h>
#include <spdk/event.h>
#include <spdk/nvme.h>
#include <spdk/pci_ids.h>
#include <spdk/stdinc.h>

#include <sys/file.h>
#include <sys/types.h>

#include "ublock.h"
#include "ublock_internal.h"
#include <spdk_internal/nvme_internal.h>

#define UBLOCK_ENV_DPDK_DEFAULT_NAME "LibStorage-ublock"
/* 1. sizeof(struct spdk_nvme_ctrlr) = 5920 B */
/* 2. max ctrlr is 512 */
/* 3. spdk init nvme level and bdev level */
/* 4. spdk init dpdk primary ctlrlr tailq and attached tailq */
/* finaylly, we set env-dpdk min-memory as 20M(round(5920*512*2*2/1024/1024)) */
#define UBLOCK_ENV_DPDK_MEM_MIN 20

/* the size of buf to save return value of admin cmd */
#define UBLOCK_ADMIN_CMD_BUF_MAX_SIZE 4096
#define UBLOCK_ADMIN_CMD_IDENTIFY_SIZE 4096

#define UBLOCK_CLIENT_GET_REG "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\
\"get_reg\",\"params\":{}}"

static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_probe_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_esn_lock = PTHREAD_MUTEX_INITIALIZER;

#define UBLOCK_FLAG_CLIENT 1 /* flag 1 means init as client */
#define UBLOCK_FLAG_SERVER 2 /* flag 2 means init as server */
static int g_init_flg = 0;

/* atomic lock for uio and ublock */
uint32_t *g_ublock_uio_lock = NULL;

#define UBLOCK_UIO_SHARE_LOCK           "share_lock.shm.\
e9b10e0e1010dadeefcb70a19bbe61d0352ec43fd02979ee0c925be1"
#define  LOCK_INIT    0x00000000U

struct completion_poll_status {
    struct spdk_nvme_cpl    cpl;
    bool                    done;
    int                     status;
};

static void completion_poll_status_set_done(void *cb_arg, const struct spdk_nvme_cpl *cpl)
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

static int ublock_uio_lock_init(void)
{
    int shm_fd = shm_open(UBLOCK_UIO_SHARE_LOCK, O_CREAT | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR);
    if (shm_fd < 0) {
        if (errno != EEXIST) {
            SPDK_ERRLOG("create share memory failed: %d\n", errno);
            return -1;
        }
        shm_fd = shm_open(UBLOCK_UIO_SHARE_LOCK, O_RDWR, S_IRUSR | S_IWUSR);
        if (shm_fd < 0) {
            SPDK_ERRLOG("share memory is already exist, open failed: %d\n", errno);
            return -1;
        }
    }
    if (ftruncate(shm_fd, sizeof(uint32_t)) == -1) {
        SPDK_ERRLOG("ftruncate share memory failed %d\n", errno);
        close(shm_fd);
        shm_unlink(UBLOCK_UIO_SHARE_LOCK);
        return -1;
    }

    g_ublock_uio_lock = (uint32_t *)mmap(NULL, sizeof(uint32_t), PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (g_ublock_uio_lock == MAP_FAILED) {
        SPDK_ERRLOG("mmap failed: %d\n", errno);
        close(shm_fd);
        return -1;
    }

    if (*g_ublock_uio_lock > 0) {
        if (kill(*(pid_t *)g_ublock_uio_lock, 0) < 0) {
            *g_ublock_uio_lock = LOCK_INIT;
        }
    }

    close(shm_fd);
    return 0;
}

static long ublock_read_file(int fd)
{
    char buf[UBLOCK_BUFFER_SIZE] = {0};
    char *ep = NULL;
    long pid;
    int ret;

    ret = read(fd, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        return -1;
    }

    pid = strtol(buf, &ep, 0);
    if (pid == 0 || pid == LONG_MAX || ep == buf || *ep != '\n') {
        return -1;
    }

    return pid;
}

static int ublock_write_file(int fd, pid_t pid)
{
    char buf[UBLOCK_BUFFER_SIZE] = {0};
    int ret;

    ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%ld\n", (long)pid);
    if (ret <= 0) {
        SPDK_ERRLOG("[ublock] snprintf_s failed!\n");
        return -1;
    } else {
        ssize_t num;
        (void)lseek(fd, (off_t)0, SEEK_SET);
        num = write(fd, buf, strlen(buf));
        if (num > 0) {
            if (ftruncate(fd, num) == -1) {
                SPDK_ERRLOG("[ublock] fail to truncate file.\n");
                return -1;
            }
        } else {
            SPDK_ERRLOG("[ublock] fail to write file.\n");
            return -1;
        }
    }

    return 0;
}

/*
 * try to lock ublock server lockfile to check server process(ex. /var/run/ublock_server.pid)
 *
 * return:
 *  true, server exist
 *  false, server not exist
 */
bool ublock_query_server_exist(const char *pidfile, bool update, pid_t pid)
{
    static int fd = -1;
    long otherpid;
    char err_buf[UBLOCK_BUFFER_SIZE] = {0};
    char *error = NULL;
    int flags = O_RDWR | O_CLOEXEC;
    int rc;

    if (update) {
        flags |= O_CREAT;
    }

    /* Initial mode is 0600 to prevent flock() race/DoS. */
    fd = open(pidfile, flags, 0600); /* mode 0600 */
    if (fd == -1) {
        error = strerror_r(errno, err_buf, sizeof(err_buf));
        SPDK_ERRLOG("[ublock] can't open or create %s: %s\n",
                    pidfile, error);
        (void)unlink(pidfile);
        exit(EXIT_FAILURE);
    }

    /* ublock server has already init */
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        int save_errno = errno;

        if (g_init_flg != UBLOCK_FLAG_SERVER) {
            close(fd);
            return true;
        }

        otherpid = ublock_read_file(fd);
        if (otherpid >= 0) {
            /* log the file lock status in ublock server.
             * ublock client just call to test if the ublock server
             * process is existing, so we do not log it.
             */
            error = strerror_r(save_errno, err_buf, sizeof(err_buf));
            SPDK_ERRLOG("[ublock] can't lock %s, otherpid may be %ld: %s\n", pidfile, otherpid, error);
        } else {
            error = strerror_r(save_errno, err_buf, sizeof(err_buf));
            SPDK_ERRLOG("[ublock] can't lock %s, otherpid unknown: %s\n",
                        pidfile, error);
        }

        close(fd);
        return true;
    }

    if (update) {
        /* pre embeded for ublock working as daemon */
        (void)fchmod(fd, 0644); /* mode 0644 */
        (void)fcntl(fd, F_SETFD, 1); /* set close-on-exec 1 */

        rc = ublock_write_file(fd, pid);
        if (rc < 0) {
            SPDK_ERRLOG("[ublock] fail to write %s\n", pidfile);
            goto FAILURE;
        }
        return false;
    }

    close(fd); /* free flock when client lock success */
    return false;

FAILURE:
    close(fd);
    (void)unlink(pidfile);
    exit(EXIT_FAILURE);
}

static void ublock_uio_lock(void)
{
    if (g_ublock_uio_lock != NULL) {
        while (!__sync_bool_compare_and_swap(g_ublock_uio_lock, LOCK_INIT, getpid())) {
            usleep(1);
        }
    }
}

static void ublock_uio_unlock(void)
{
    if (g_ublock_uio_lock != NULL) {
        __sync_bool_compare_and_swap(g_ublock_uio_lock, getpid(), LOCK_INIT);
    }
}
/**
 * IN:
 * @id   PID or TID
 * @path /proc or /proc/PID/
 *
 * RETURN:
 * 0, not found given `id' in `path'
 * 1, found given `id' in `path'
 */
static int ublock_searchID(const char *id, const char *path)
{
    if (id == NULL || path == NULL) {
        return 0;
    }

    DIR *dir = NULL;
    struct dirent *dirent = NULL;

    dir = opendir(path);
    if (dir == NULL) {
        SPDK_ERRLOG("unable to open directory: %s\n", path);
        return 0;
    }

    dirent = readdir(dir);
    while (dirent != NULL) {
        if (0 == strcmp(id, dirent->d_name)) {
#ifdef DEBUG
            SPDK_NOTICELOG("found pid(tid) in %s/%s\n", path, dirent->d_name);
#endif
            closedir(dir);
            return 1;
        }
        dirent = readdir(dir);
    }

    closedir(dir);
    return 0;
}

/**
 * filename is number(ex: directory '1209' in /proc/1209/)
 */
static bool ublock_is_number_str(const char *pid)
{
    if (pid == NULL) {
        return false;
    }
    char *pattern = "^[0-9]\\{1,\\}$";

    int ret;
    int cflags = 0;
    const size_t nmatch = 10; /* 10 bytes for reg matching */
    regmatch_t pm[10]; /* 10 bytes buf for reg matching */
    regex_t reg;

    ret = regcomp(&reg, pattern, cflags);
    if (ret == 0) {
        ret = regexec(&reg, pid, nmatch, pm, cflags);
    }
    regfree(&reg);

    return (ret == 0);
}

/**
 * test if the given `filename' is a directory
 */
static bool ublock_is_dir(const char *filename)
{
    if (filename == NULL) {
        return false;
    }

    struct stat statbuf;

    (void)lstat(filename, &statbuf);

    return S_ISDIR(statbuf.st_mode);
}

/**
 * search PID or TID in system to
 * make sure the given `pid' is still running or not
 */
static int ublock_searchTID(const char *pid)
{
    DIR *dir = NULL;
    struct dirent *dirent = NULL;
    char *filename = NULL;
    char *tidpath = NULL;
    int rc = 0;

    dir = opendir("/proc/");
    if (dir == NULL) {
        SPDK_ERRLOG("fail to open directory: /proc/\n");
        return 0;
    }

    filename = (char *)calloc(FILENAME_MAX, sizeof(char));
    if (filename == NULL) {
        SPDK_ERRLOG("fail to init filename\n");
        goto out;
    }

    tidpath = (char *)calloc(FILENAME_MAX, sizeof(char));
    if (tidpath == NULL) {
        SPDK_ERRLOG("fail to init tidpath\n");
        goto out;
    }

    for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
        if (snprintf_s(filename, FILENAME_MAX, FILENAME_MAX - 1,
                       "/proc/%s", dirent->d_name) < 0) {
            continue;
        }

        if (ublock_is_dir(filename) && ublock_is_number_str(dirent->d_name)) {
            if (snprintf_s(tidpath, FILENAME_MAX, FILENAME_MAX - 1,
                           "%s/task/", filename) < 0) {
                continue;
            }

            if (ublock_searchID(pid, tidpath) == 1) {
                rc = 1;
                goto out;
            }
        }
    }

out:
    closedir(dir);
    free(filename);
    free(tidpath);
    return rc;
}

/**
 *  * search TID in system to
 *   * make sure the given `pid' is still running or not
 *    */
static int ublock_searchPTID(const char *pid)
{
    if (pid == NULL) {
        return 0;
    }

    /* find if match with pid in /proc/ */
    if (ublock_searchID(pid, "/proc/") == 1) {
        return 1;
    }

    /* find if match with tid in /proc/pid/task */
    return ublock_searchTID(pid);
}

static void ublock_get_plog_info(const struct dirent *dirent,
                                 const char *pid_buffer,
                                 char *filename_buffer,
                                 char *buf)
{
    int fd = -1;
    int buf_len = 0;
    int ret = 0;

    /* the tid(pid) of matched socket is running in system */
    if (ublock_searchPTID(pid_buffer) == 1) {
        /* exclude libstorage_rpc_pid.sock.lock in spdk-18.10 */
        if (strstr(dirent->d_name, "lock")) {
            return;
        }

        /* the pid of libstorage rpc server is still running,
         * but it is not sure that the pid is not occupied by
         * another new process which is not libstorage rpc
         * server
         */
        if (snprintf_s(filename_buffer,
                       FILENAME_MAX,
                       FILENAME_MAX - 1,
                       "/var/run/%s",
                       dirent->d_name) < 0) {
            SPDK_WARNLOG("[ublock] fail to snprintf\n");
            return;
        }
        fd = ublock_client_conn(filename_buffer);
        if (fd < 0) {
            SPDK_ERRLOG("[ublock] fail to connect %s\n",
                        filename_buffer);
            return;
        }
        ret = memset_s(buf, SPDK_JSONRPC_RECV_BUF_SIZE, 0, SPDK_JSONRPC_RECV_BUF_SIZE);
        if (ret != 0) {
            SPDK_WARNLOG("memset failed!\n");
            close(fd);
            return;
        }
        buf_len = ublock_client_send(fd, UBLOCK_CLIENT_GET_REG, strlen(UBLOCK_CLIENT_GET_REG), buf);

        /* close the connect after send */
        close(fd);
        if (buf_len < 0) {
            SPDK_ERRLOG("fail to send rpc recovery request to sockaddr %s\n", filename_buffer);
            return;
        }
        // if uio recv revocery rpc req success, it will response message "success".
        if (strstr(buf, "success") == NULL) {
            SPDK_ERRLOG("error occurs in ublock to recovery rpc data request, response is %s\n", buf);
            return;
        }
    }
    return;
}

static void ublock_recover_rpcdata(void)
{
    DIR *dir = NULL;
    struct dirent *dirent = NULL;
    char *tmp = NULL;
    char *pid_buffer = NULL;
    char *filename_buffer = NULL;
    char *buf = NULL;
    int idx = 0;

    dir = opendir("/var/run");
    if (dir == NULL) {
        SPDK_ERRLOG("unable to open directory\n");
        return;
    }

    buf = (uint8_t *)calloc(SPDK_JSONRPC_RECV_BUF_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        SPDK_ERRLOG("calloc for buffer to recive response failed!\n");
        goto out;
    }

    pid_buffer = (char *)calloc(FILENAME_MAX, sizeof(char));
    if (pid_buffer == NULL) {
        SPDK_ERRLOG("fail to init pid_buffer\n");
        goto out;
    }

    filename_buffer = (char *)calloc(FILENAME_MAX, sizeof(char));
    if (filename_buffer == NULL) {
        SPDK_ERRLOG("fail to init filename_buffer\n");
        goto out;
    }

    for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
        /* found the matched socket */
        if (strncmp(dirent->d_name, "libstorage_rpc_", 15) != 0) { /* 15 is len of libstorage_rpc_ */
            continue;
        }
        idx = 0;
        tmp = dirent->d_name + 15; /* 15 is len of libstorage_rpc_ */

        /* fix endless loop when file name is "libstorage_rpc_xxxxxxxxx" */
        while ((*tmp) != '.' && (*tmp) != '\0' && idx < FILENAME_MAX - 1) {
            pid_buffer[idx++] = *tmp++;
        }
        pid_buffer[idx] = '\0';

        ublock_get_plog_info(dirent, pid_buffer, filename_buffer, buf);
    }

out:
    free(buf);
    free(pid_buffer);
    free(filename_buffer);
    closedir(dir);
}

static void ublock_ignore_sig(int sig)
{
    if (sig == SIGPIPE) {
        /* ignore SIGPIPE for send to a exit socket connection, */
        /* or it will lead to process exit */
        signal(SIGPIPE, SIG_IGN);
    }
}

static int enable_rpc_server(void)
{
    /* init ublock as server */
    g_init_flg = UBLOCK_FLAG_SERVER;

    /* make sure there is no ublock server initialized */
    if (!ublock_query_server_exist(UBLOCK_SERVER_LOCKFILE, true, getpid())) {
        /* rpc server initialize */
        if (ublock_start_rpc(UBLOCK_RPC_ADDR) != 0) {
            SPDK_ERRLOG("[ublock] ublock init failed"
                        " to start rpc server\n");
            g_init_flg = 0;
            return -1;
        }
        /* try to recover register data */
        ublock_recover_rpcdata();
    } else {
        SPDK_ERRLOG("[ublock] ublock server has exist\n");
        g_init_flg = 0;
        return -1;
    }

    return 0;
}

int init_ublock(const char *name, enum ublock_rpc_server_status flg)
{
    const char *tmpName = name;
    /*
     * ublock module might initialize in server process or client process,
     * which UBLOCK_RPC_SERVER_ENABLE is uesd in server process and
     * UBLOCK_RPC_SERVER_DISABLE is uesd in server process.
     * .--------------------------------------------------------------------.
     * |                             |   dpdk     |    rpc     |   monitor  |
     * |--------------------------------------------------------------------|
     * |  UBLOCK_RPC_SERVER_ENABLE   |    yes     |   yes      |   yes      |
     * |--------------------------------------------------------------------|
     * |  UBLOCK_RPC_SERVER_DISABLE  |    yes     |            |            |
     * .--------------------------------------------------------------------.
     */
    struct spdk_env_opts env_opts = {0x0};

    (void)pthread_mutex_lock(&g_init_lock);

    if (g_init_flg > 0) {
        SPDK_NOTICELOG("[ublock] ublock can only be initialized once\n");
        (void)pthread_mutex_unlock(&g_init_lock);
        return -1;
    }

    /* init ublock as client */
    g_init_flg = UBLOCK_FLAG_CLIENT;

    if (tmpName == NULL) {
        tmpName = UBLOCK_ENV_DPDK_DEFAULT_NAME;
    }

    /* ignore SIGPIPE for sending an exited socket connection */
    /* which will lead to procee exit */
    (void)signal(SIGPIPE, ublock_ignore_sig);

    /* env_dpdk initialize */
    spdk_env_opts_init(&env_opts);
    env_opts.name = tmpName;
    env_opts.mem_size = UBLOCK_ENV_DPDK_MEM_MIN;
    if (spdk_env_init(&env_opts) < 0) {
        SPDK_ERRLOG("Failed to initialize SPDK env\n");
        goto FAILURE;
    }

    /* start rpc server including rpc service and monitor service */
    if (flg == UBLOCK_RPC_SERVER_ENABLE) {
        if (enable_rpc_server() != 0) {
            SPDK_ERRLOG("[ublock] enable ublock server fail\n");
            goto FAILURE;
        }
    }

    if (ublock_uio_lock_init() != 0) {
        SPDK_ERRLOG("Can't create share memory for lock!\n");
        goto FAILURE;
    }

    ublock_init_iostat();

    (void)pthread_mutex_unlock(&g_init_lock);

#ifdef DEBUG
    SPDK_NOTICELOG("[ublock] ublock initialization done\n");
#endif

    return 0;

FAILURE:
    (void)pthread_mutex_unlock(&g_init_lock);
    exit(EXIT_FAILURE);
}

void ublock_fini(void)
{
    (void)pthread_mutex_lock(&g_init_lock);

    /* ublock is not initialized */
    if (g_init_flg == 0) {
        SPDK_NOTICELOG("[ublock] ublock is not initialized\n");
        (void)pthread_mutex_unlock(&g_init_lock);
        return;
    }

    /* ublock is initialized as client */
    if (g_init_flg == UBLOCK_FLAG_CLIENT) {
        SPDK_NOTICELOG("[ublock] finalize ublock client\n");
        (void)pthread_mutex_unlock(&g_init_lock);
        return;
    }

    SPDK_NOTICELOG("[ublock] finalize ublock server\n");
    g_init_flg = 0;

    if (g_ublock_uio_lock != NULL) {
        ublock_uio_unlock();
        (void)munmap(g_ublock_uio_lock, sizeof(uint32_t));
    }
    g_ublock_uio_lock = NULL;

    /* ublock is initialized as server */
    ublock_stop_rpc();
    (void)pthread_mutex_unlock(&g_init_lock);
}

static void ublock_get_device_addr(struct spdk_pci_addr *addr, const struct rte_pci_device *pci_dev)
{
    addr->domain = pci_dev->addr.domain;
    addr->bus = pci_dev->addr.bus;
    addr->dev = pci_dev->addr.devid;
    addr->func = pci_dev->addr.function;
}

/* add new node of nvme device which including its pci address into bdev list */
static int _add_ublock_bdev(struct ublock_bdev_mgr *bdev_list,
                            const struct rte_pci_device *pci_dev)
{
    int rc;
    struct spdk_pci_addr pci_addr;
    struct ublock_bdev *bdev = NULL;

    if (bdev_list == NULL || pci_dev == NULL) {
        SPDK_ERRLOG("[ublock] parameter bdev_list or pci_dev is NULL\n");
        return -1;
    }

    bdev = calloc(1, sizeof(struct ublock_bdev));
    if (bdev == NULL) {
        SPDK_ERRLOG("[ublock] fail to calloc memory\n");
        return -ENOMEM;
    }

    ublock_get_device_addr(&pci_addr, pci_dev);

    rc = spdk_pci_addr_fmt(bdev->pci, sizeof(bdev->pci), &pci_addr);
    if (rc != 0) {
        free(bdev);
        SPDK_ERRLOG("[ublock] pci addr format fail\n");
        return rc;
    }

    TAILQ_INSERT_TAIL(&bdev_list->bdevs, bdev, link);
    return 0;
}

static bool ublock_is_device_path(const struct rte_pci_device *dev)
{
    if (dev == NULL) {
        return false;
    }

    int rc;
    char pci[UBLOCK_PCI_ADDR_MAX_LEN];
    char *dirname = NULL;
    const char *sys_path = NULL;
    struct stat statbuf;
    struct spdk_pci_addr pci_addr;

    ublock_get_device_addr(&pci_addr, dev);
    rc = spdk_pci_addr_fmt(pci, sizeof(pci), &pci_addr);
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] fail to format pci addr\n");
        return false;
    }

    dirname = (char *)calloc(PATH_MAX, sizeof(char));
    if (dirname == NULL) {
        SPDK_ERRLOG("fail to init dirname\n");
        return false;
    }

    sys_path = rte_pci_get_sysfs_path();
    rc = snprintf_s(dirname, PATH_MAX,
                    strlen(sys_path) + strlen(pci) + 1,
                    "%s/%s", sys_path, pci);
    if (rc <= 0) {
        SPDK_ERRLOG("[ublock] snprintf failed!\n");
        free(dirname);
        return false;
    }

    rc = lstat(dirname, &statbuf);
    if (rc < 0) {
#ifdef DEBUG
        SPDK_NOTICELOG("[ublock] lstat(%s) failed, %s\n",
                       dirname, strerror(errno));
#endif
        free(dirname);
        return false;
    }

    free(dirname);
    return S_ISLNK(statbuf.st_mode) || S_ISDIR(statbuf.st_mode);
}

static struct rte_pci_bus *ublock_get_pci_bus(void)
{
    struct rte_bus *bus = NULL;

    (void)pthread_mutex_lock(&g_probe_lock);
    /* rescan the NVMe device list in case of spdk_nvme_detach remove */
    /* the device node from pci_device_list */
    if (rte_bus_scan() < 0) {
        (void)pthread_mutex_unlock(&g_probe_lock);
        SPDK_ERRLOG("[ublock] %s: Cannot scan PCI bus\n", __func__);
        return NULL;
    }
    (void)pthread_mutex_unlock(&g_probe_lock);

    bus = rte_bus_find_by_name("pci");
    if (bus == NULL) {
        SPDK_ERRLOG("[ublock] get bus list failed\n");
        return NULL;
    }

    return (struct rte_pci_bus *)bus;
}

/* get all nvme device pci address */
int ublock_get_bdevs(struct ublock_bdev_mgr *bdev_list)
{
    int rc = -2; /* -2 means there is no nvme device in environment */
    struct rte_pci_device *tmp = NULL;
    struct rte_pci_device *dev = NULL;
    struct rte_pci_bus *pci_bus = NULL;

    if (bdev_list == NULL) {
        SPDK_ERRLOG("[ublock] parameter bdev_list is NULL\n");
        return -1;
    }

    TAILQ_INIT(&bdev_list->bdevs);

    /*
     * spdk_nvme_probe & spdk_nvme_detach will update pci_device_list
     */
    pci_bus = ublock_get_pci_bus();
    if (pci_bus == NULL) {
        return -1;
    }

    TAILQ_FOREACH_SAFE(dev, &(pci_bus->device_list), next, tmp) {
        if (dev->id.class_id != SPDK_PCI_CLASS_NVME) {
            continue;
        }
        /* when echo 1 > /sys/bus/pci/devices/${PCI_ADDR}/remove to remove device,
         * the directory /sys/bus/pci/devices/${PCI_ADDR} will be removed. If so,
         * do not add the device into bdev_list.
         */
        if (!ublock_is_device_path(dev)) {
            continue;
        }

        rc = _add_ublock_bdev(bdev_list, dev);
        if (rc != 0) {
            ublock_free_bdevs(bdev_list);
            return rc;
        }
    }

    if (rc == -2) { /* -2 means there is no nvme device in environment */
        SPDK_ERRLOG("[ublock] there is no NVMe device in environment\n");
    }

    return rc;
}

void ublock_free_bdevs(struct ublock_bdev_mgr *bdev_list)
{
    struct ublock_bdev *bdev = NULL, *tmp = NULL;

    if (bdev_list == NULL) {
        SPDK_ERRLOG("[ublock] parameter bdev_list is NULL\n");
        return;
    }

    TAILQ_FOREACH_SAFE(bdev, &bdev_list->bdevs, link, tmp) {
        TAILQ_REMOVE(&bdev_list->bdevs, bdev, link);
        free(bdev);
    }
}

static bool probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
                     struct spdk_nvme_ctrlr_opts *opts)
{
#ifdef DEBUG
    SPDK_NOTICELOG("[ublock] Attaching to %s\n", trid->traddr);
#endif

    return true;
}

static void timeout_cb(void *cb_arg, struct spdk_nvme_ctrlr *ctrlr,
                       struct spdk_nvme_qpair *qpair, uint16_t cid)
{
    SPDK_ERRLOG("Warning: Detected a timeout. ctrlr=%p qpair=%p cb_arg=%p cid=%u\n", ctrlr, qpair, cb_arg, cid);
    ctrlr->is_failed = true;
}

static void attach_cb(void *cb_ctx,
                      const struct spdk_nvme_transport_id *trid,
                      struct spdk_nvme_ctrlr *ctrlr,
                      const struct spdk_nvme_ctrlr_opts *opts)
{
    if (cb_ctx == NULL) {
        SPDK_WARNLOG("[ublock] wrong input when spdk_nvme_probe attach\n");
        return;
    }
    struct ublock_bdev *bdev = cb_ctx;
#ifdef DEBUG
    SPDK_NOTICELOG("[ublock] Attached to %s\n", trid->traddr);
#endif
    spdk_nvme_ctrlr_register_timeout_callback(ctrlr, 150000000, timeout_cb, NULL); /* 150000000 is 150s timeout */
    bdev->ctrlr = ctrlr;
}

static int ublock_claim_nvme_for_local_query(struct spdk_nvme_transport_id *trid,
                                             struct ublock_bdev *bdev,
                                             const char *pci)
{
    int ret;
    struct spdk_pci_addr pci_addr;
    struct spdk_pci_device *pci_dev = NULL;

    if (trid == NULL || bdev == NULL || pci == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters\n");
        return -1;
    }

    if (strlen(pci) > sizeof(bdev->pci) - 1) {
        SPDK_ERRLOG("[ublock] pci name is too long\n");
        return -1;
    }
    ret = strncpy_s(bdev->pci, sizeof(bdev->pci), pci, strlen(pci));
    if (ret != 0) {
        SPDK_ERRLOG("[ublock] strncpy failed!\n");
        return -1;
    }

    if (spdk_pci_addr_parse(&pci_addr, pci)) {
        SPDK_ERRLOG("[ublock] could not parse pci address\n");
        return -1;
    }

    /* when pci claim by other, probe will return 0 */
    bdev->ctrlr = NULL;
    trid->trtype = SPDK_NVME_TRANSPORT_PCIE;
    spdk_pci_addr_fmt(trid->traddr, sizeof(trid->traddr), &pci_addr);

    pci_dev = (struct spdk_pci_device *)calloc(1, sizeof(struct spdk_pci_device));
    if (pci_dev == NULL) {
        return -1;
    }

    pci_dev->addr = pci_addr;
    ret = spdk_pci_device_claim(pci_dev);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock] other process claim the NVMe device\n");
        free(pci_dev);
        return -1;
    }
    close(pci_dev->internal.claim_fd);
    free(pci_dev);
    return 0;
}

static int ublock_probe_nvme_for_local_query(struct spdk_nvme_transport_id *trid,
                                             struct ublock_bdev *bdev)
{
    int fd = 0;
    int ret;

    ret = spdk_nvme_probe(trid, bdev, probe_cb, attach_cb, NULL);
    if (ret != 0 || bdev->ctrlr == NULL) {
        SPDK_ERRLOG("[ublock] Failed to probe pci, %d\n", ret);
        fd = -1;
    }

    return fd;
}

static void ublock_detach_nvme_for_local_query(struct spdk_nvme_ctrlr *ctrlr)
{
    if (ctrlr == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameter\n");
        return;
    } else {
        (void)spdk_nvme_detach_ublock(ctrlr);
    }
}

static int ublock_reset_nvme_for_local_query(char *pci, struct spdk_nvme_ctrlr *ctrlr)
{
    int ret;

    if ((ctrlr == NULL) || (pci == NULL)) {
        SPDK_ERRLOG("[ublock] invalid parameter\n");
        ublock_uio_unlock();
        return -1;
    } else {
        (void)spdk_nvme_detach_ublock(ctrlr);
    }

    ret = spdk_rebind_driver(pci, "nvme");

    ublock_uio_unlock();
    if (ret < 0) {
        SPDK_ERRLOG("failed to reset pci address %s driver to nvme\n", pci);
        /* reset driver fail */
        return -EBUSY;
    }

    return ret;
}

/* parse nvme bdev device info from the nvme device controller */
static int ublock_parse_bdev_ctrlr_info(struct ublock_bdev *bdev)
{
    int ret;
    uint32_t nsid;
    struct spdk_pci_device *pci_dev = NULL;

    pci_dev = spdk_nvme_ctrlr_get_pci_device(bdev->ctrlr);
    if (pci_dev == NULL) {
        SPDK_ERRLOG("[ublock] failed to get pci device\n");
        return -1;
    }
    nsid = spdk_nvme_ctrlr_get_first_active_ns(bdev->ctrlr);
    if (nsid == 0) {
        SPDK_ERRLOG("[ublock] failed to get active nsid\n");
        return -1;
    }
    bdev->info.sector_size = spdk_nvme_ns_get_sector_size(&bdev->ctrlr->ns[nsid - 1]);
    if (bdev->ctrlr->cdata.oacs.ns_manage == 0) {
        /* nvme not support ns management */
        bdev->info.cap_size = spdk_nvme_ns_get_size(&bdev->ctrlr->ns[nsid - 1]);
    } else {
        /* nvme support ns management */
        bdev->info.cap_size = bdev->ctrlr->cdata.tnvmcap[0];
    }
    bdev->info.md_size = spdk_nvme_ns_get_md_size(&bdev->ctrlr->ns[nsid - 1]);
    bdev->info.device_id = spdk_pci_device_get_device_id(pci_dev);
    bdev->info.subsystem_device_id = spdk_pci_device_get_subdevice_id(pci_dev);
    bdev->info.vendor_id = bdev->ctrlr->cdata.vid;
    bdev->info.subsystem_vendor_id = bdev->ctrlr->cdata.ssvid;
    bdev->info.controller_id = bdev->ctrlr->cdata.cntlid;
    ret = memcpy_s(bdev->info.serial_number,
                   sizeof(bdev->info.serial_number),
                   bdev->ctrlr->cdata.sn,
                   sizeof(bdev->ctrlr->cdata.sn));

    ret += memcpy_s(bdev->info.model_number,
                    sizeof(bdev->info.model_number),
                    bdev->ctrlr->cdata.mn,
                    sizeof(bdev->info.model_number));

    ret += memcpy_s(bdev->info.firmware_revision,
                    sizeof(bdev->info.firmware_revision),
                    bdev->ctrlr->cdata.fr,
                    sizeof(bdev->ctrlr->cdata.fr));
    if (ret != 0) {
        SPDK_ERRLOG("[ublock] memcpy failed!\n");
        return ret;
    }

    return 0;
}

/* get nvme bdev info from local nvme device which is not occupied by others */
static int _ublock_get_bdev_from_local(const char *pci,
                                       struct ublock_bdev *bdev)
{
    int ret;
    int fd = -1;
    struct spdk_nvme_transport_id trid = {0x0};

    if (pci == NULL || bdev == NULL) {
        SPDK_ERRLOG("[ublock] parameter pci or bdev is NULL\n");
        return -1;
    }

    if (ublock_claim_nvme_for_local_query(&trid, bdev, pci) != 0) {
        return -1;
    }

    /* spdk_nvme_probe is not thread safe */
    (void)pthread_mutex_lock(&g_probe_lock);
    ublock_uio_lock();
    fd = ublock_probe_nvme_for_local_query(&trid, bdev);
    if (fd < 0) {
        ublock_uio_unlock();
        (void)pthread_mutex_unlock(&g_probe_lock);
        return -1;
    }

    /* parse nvme bdev device info */
    ret = ublock_parse_bdev_ctrlr_info(bdev);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock] parse nvme bdev device info failed!\n");
        goto out_func;
    }

    ret = 0;
out_func:
    /*
     * SPDK bind admin queue with process, and the admin
     * queue is malloced from dpdk reserverd memzone
     * who is freed by process terminated. For ublock,
     * it whill lead to dpdk memory leakage, so we free
     * it manually.
     */
    ublock_detach_nvme_for_local_query(bdev->ctrlr);
    ublock_uio_unlock();
    bdev->ctrlr = NULL;
    (void)pthread_mutex_unlock(&g_probe_lock);
    return ret;
}

int ublock_get_bdev(const char *pci, struct ublock_bdev *bdev)
{
    int rc;

    if (pci == NULL || bdev == NULL) {
        SPDK_ERRLOG("[ublock] parameter pci or bdev is NULL\n");
        return -1;
    }

    if (strlen(pci) > sizeof(bdev->pci) - 1) {
        SPDK_ERRLOG("[ublock] pci name is too long\n");
        return -1;
    }
    /* get bdev info from ublock rpc server */
    rc = ublock_client_queryinfo(LOCAL_RPC_QUERY, pci, bdev);
    if (rc == -1) {
        SPDK_ERRLOG("[ublock-client] can't get info from ublock server jsonrpc\n");
        return -EAGAIN;
    } else if (rc != 0) {
        SPDK_ERRLOG("[ublock-client] query info local failed\n");
        return -1;
    }
    rc = strncpy_s(bdev->pci, sizeof(bdev->pci), pci, strlen(pci));
    if (rc != 0) {
        SPDK_ERRLOG("[ublock] strncpy failed!\n");
        return -1;
    }

    return 0;
}

/* basic function of querying nvme bdev info */
int _ublock_get_bdev(const char *pci, struct ublock_bdev *bdev)
{
    int ret;

    if (pci == NULL || bdev == NULL) {
        SPDK_ERRLOG("[ublock] parameter pci or bdev is NULL\n");
        return -1;
    }

    /* first try local app */
    ret = _ublock_get_bdev_from_local(pci, bdev);
    if (ret == 0) {
        SPDK_NOTICELOG("[ublock-server] get bdev from local success\n");
        return 0;
    }

    /* try get cdata from jsonrpc */
    /* remote query info of pci device */
    SPDK_NOTICELOG("[ublock-server] get bdev from remote\n");
    if (strlen(pci) > sizeof(bdev->pci) - 1) {
        SPDK_ERRLOG("[ublock] pci name is too long\n");
        return -1;
    }
    ret = ublock_client_queryinfo(REMOTE_RPC_QUERY, pci, bdev);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock-server] fail get info from remote jsonrpc\n");
        return -1;
    }
    ret = strncpy_s(bdev->pci, sizeof(bdev->pci), pci, strlen(pci));
    if (ret != 0) {
        SPDK_ERRLOG("[ublock] strncpy failed!\n");
        return -1;
    }

    return 0;
}

void ublock_free_bdev(struct ublock_bdev *bdev)
{
    if (bdev == NULL) {
        return;
    }

    if (bdev->ctrlr) {
        (void)spdk_nvme_detach_ublock(bdev->ctrlr);
    }

    (void)pthread_mutex_lock(&g_probe_lock);
    if (rte_bus_scan() < 0) {
        SPDK_ERRLOG("[ublock] %s: Cannot scan PCI bus\n", __func__);
    }
    (void)pthread_mutex_unlock(&g_probe_lock);
}

static int ublock_copy_bdev(struct ublock_bdev *bdev_dest,
                            const struct ublock_bdev *bdev_src)
{
    int rc;

    bdev_dest->info.sector_size = bdev_src->info.sector_size;
    bdev_dest->info.cap_size = bdev_src->info.cap_size;
    bdev_dest->info.md_size = bdev_src->info.md_size;
    bdev_dest->info.device_id = bdev_src->info.device_id;
    bdev_dest->info.subsystem_device_id = bdev_src->info.subsystem_device_id;
    bdev_dest->info.vendor_id = bdev_src->info.vendor_id;
    bdev_dest->info.subsystem_vendor_id = bdev_src->info.subsystem_vendor_id;
    bdev_dest->info.controller_id = bdev_src->info.controller_id;
    rc = memcpy_s(bdev_dest->info.serial_number,
                  sizeof(bdev_dest->info.serial_number),
                  bdev_src->info.serial_number,
                  sizeof(bdev_src->info.serial_number));
    if (rc != 0) {
        return -1;
    }
    rc = memcpy_s(bdev_dest->info.model_number,
                  sizeof(bdev_dest->info.model_number),
                  bdev_src->info.model_number,
                  sizeof(bdev_src->info.model_number));
    if (rc != 0) {
        return -1;
    }
    rc = memcpy_s(bdev_dest->info.firmware_revision,
                  sizeof(bdev_dest->info.firmware_revision),
                  bdev_src->info.firmware_revision,
                  sizeof(bdev_src->info.firmware_revision));
    if (rc != 0) {
        return -1;
    }
    /* if bdev query by local probe, bdev_info.ctrlr is not NULL. otherwise the bdev_info.ctrlr is NULL */
    bdev_dest->ctrlr = bdev_src->ctrlr;
    return 0;
}

int ublock_get_bdev_by_esn(const char *esn, struct ublock_bdev *bdev)
{
    char buff[21] = {0x0}; /* 21 bytes buf for esn store */
    struct ublock_bdev *bdev_tmp = NULL;
    struct ublock_bdev *tmp = NULL;
    struct ublock_bdev bdev_info = {{0x0}};
    struct ublock_bdev_mgr bdev_list = {{0x0}};

    if (esn == NULL || bdev == NULL) {
        SPDK_ERRLOG("[ublock] parameter esn or bdev is NULL\n");
        return -1;
    }
    /* according to struct ublock_bdev_info, the length of ESN string is less than 20 */
    if (strlen(esn) > 20) { /* esn not longger then 20 bytes */
        SPDK_ERRLOG("[ublock] error serial number string: %s\n", esn);
        return -1;
    }

    /* get all NVMe devices */
    if (ublock_get_bdevs(&bdev_list) != 0) {
        SPDK_ERRLOG("[ublock] fail to get nvme device list\n");
        return -1;
    }

    /* go through device list to check if esn is matched */
    TAILQ_FOREACH_SAFE(bdev_tmp, &bdev_list.bdevs, link, tmp) {
        if (ublock_get_bdev(bdev_tmp->pci, &bdev_info) != 0) {
            SPDK_ERRLOG("[ublock-client] fail to get nvme info of %s\n", bdev_tmp->pci);
            continue;
        }

        /* copy serial number in device controller into a string buffer */
        if (memset_s(buff, sizeof(buff), 0, sizeof(buff)) != 0) {
            goto error_return;
        }

        if (memcpy_s(buff, sizeof(buff),
                      bdev_info.info.serial_number,
                      sizeof(bdev_info.info.serial_number)) != 0) {
            goto error_return;
        }
#ifdef DEBUG
        SPDK_NOTICELOG("[ublock] serial number: '%s'\n", buff);
#endif
        if (strcmp(buff, esn) != 0) {
            /* if not query bdev matched with esn argu, detach the bdev  */
            ublock_free_bdev(&bdev_info);
            continue;
        }

        /* get bdev info by esn */
        if (memcpy_s(bdev->pci, sizeof(bdev->pci), bdev_tmp->pci, sizeof(bdev_tmp->pci)) != 0) {
            goto error_return;
        }

        if (ublock_copy_bdev(bdev, &bdev_info) != 0) {
            goto error_return;
        }

        /* if query bdev matched with esn argu, the bdev need detached by outer layer caller */
        ublock_free_bdevs(&bdev_list);
        return 0;
    }

    SPDK_WARNLOG("[ublock] cannot find the device whose esn='%s'\n", esn);
    ublock_free_bdevs(&bdev_list);
    return -EAGAIN; /* -EAGAIN means that did not find any bdev matched to the esn, need application retry */

error_return:
    SPDK_ERRLOG("[ublock] memory operation failed!\n");
    ublock_free_bdev(&bdev_info);
    ublock_free_bdevs(&bdev_list);
    return -1;
}

/* get nvme SMART info from local nvme device which is not occupied by others */
static int _ublock_get_SMART_info_from_local(const char *pci, uint32_t nsid,
    struct ublock_SMART_info *smart_info)
{
    int ret;
    int fd = -1;
    struct spdk_nvme_transport_id trid;
    struct ublock_bdev bdev;
    struct spdk_nvme_health_information_page *all_smart_info = (struct spdk_nvme_health_information_page *)smart_info;

    if (pci == NULL || smart_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters\n");
        return -1;
    }

    if (ublock_claim_nvme_for_local_query(&trid, &bdev, pci) != 0) {
        return -1;
    }

    /* spdk_nvme_probe is not thread safe */
    (void)pthread_mutex_lock(&g_probe_lock);
    ublock_uio_lock();
    fd = ublock_probe_nvme_for_local_query(&trid, &bdev);
    if (fd < 0) {
        ublock_uio_unlock();
        (void)pthread_mutex_unlock(&g_probe_lock);
        return -1;
    }

    /* after nvme probe, start to get SMART info */
    ret = spdk_nvme_ctrlr_get_smart_info(bdev.ctrlr, nsid, all_smart_info);
    if (ret != 0) {
        SPDK_NOTICELOG("[ublock-server] Get SMART info from local failed!\n");
        ret = -1;
    }

    ublock_detach_nvme_for_local_query(bdev.ctrlr);
    ublock_uio_unlock();
    (void)pthread_mutex_unlock(&g_probe_lock);
    return ret;
}

int ublock_get_SMART_info(const char *pci, uint32_t nsid, struct ublock_SMART_info *smart_info)
{
    int ret;

    if (pci == NULL || smart_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters\n");
        return -1;
    }

    ret = ublock_client_querySMARTinfo(LOCAL_RPC_QUERY, pci, nsid, smart_info);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock-client] fail to get smart info from ublock server\n");
        return -EAGAIN;
    }

    return ret;
}

/* basic function of querying nvme SMART info */
int _ublock_get_SMART_info(const char *pci, uint32_t nsid, struct ublock_SMART_info *smart_info)
{
    int ret;

    if (pci == NULL || smart_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters\n");
        return -1;
    }

    /* first try local app */
    ret = _ublock_get_SMART_info_from_local(pci, nsid, smart_info);
    if (ret == 0) {
        SPDK_NOTICELOG("[ublock-server] get SMART info from local success\n");
        goto end;
    }

    /* try get SMART info from jsonrpc */
    /* remote query smart info of pci device */
    SPDK_NOTICELOG("[ublock-server] get SMART info from remote\n");
    ret = ublock_client_querySMARTinfo(REMOTE_RPC_QUERY, pci, nsid, smart_info);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock-server] can't get info from remote jsonrpc\n");
        return -1;
    }

end:
#ifdef SPDK_CONFIG_ERR_INJC
    ublock_error_inject_smart_info(pci, smart_info);
    ublock_error_inject_print_smart_info(smart_info);
#endif

    return 0;
}

int ublock_get_SMART_info_by_esn(const char *esn, uint32_t nsid, struct ublock_SMART_info *smart_info)
{
    if (esn == NULL || smart_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters\n");
        return -1;
    }
    /* according to struct ublock_bdev_info, the length of ESN string is less than 20 */
    if (strlen(esn) > 20) { /* esn not longger then 20 bytes */
        SPDK_ERRLOG("[ublock] error serial number string: %s\n", esn);
        return -1;
    }

    int rc;
    char pci[UBLOCK_PCI_ADDR_MAX_LEN] = {0x0};
    struct ublock_bdev bdev = {{0x0}};

    (void)pthread_mutex_lock(&g_esn_lock);
    /* get PCI address of NVMe device by esn */
    rc = ublock_get_bdev_by_esn(esn, &bdev);
    if (rc != 0) {
        (void)pthread_mutex_unlock(&g_esn_lock);
        SPDK_ERRLOG("[ublock-client] fail to find esn='%s' related NVMe device\n", esn);
        return rc;
    }

    if (bdev.pci == NULL || strlen(bdev.pci) > UBLOCK_PCI_ADDR_MAX_LEN - 1) {
        ublock_free_bdev(&bdev);
        (void)pthread_mutex_unlock(&g_esn_lock);
        SPDK_ERRLOG("[ublock] error PCI address string: %s\n", bdev.pci);
        return -1;
    }

    if (strcpy_s(pci, UBLOCK_PCI_ADDR_MAX_LEN, bdev.pci)) {
        ublock_free_bdev(&bdev);
        (void)pthread_mutex_unlock(&g_esn_lock);
        SPDK_ERRLOG("[ublock] fail to copy PCI address string\n");
        return -1;
    }
    /* free bdev to release NVMe device controller */
    ublock_free_bdev(&bdev);
    (void)pthread_mutex_unlock(&g_esn_lock);

    /* get SMART info according related pci by esn */
    return ublock_get_SMART_info(pci, nsid, smart_info);
}

/* get nvme error log info from local nvme device which is not occupied by others */
static int _ublock_get_error_log_info_from_local(const char *pci, uint32_t err_entries,
    struct ublock_nvme_error_info *errlog_info)
{
    int ret;
    int fd = -1;
    struct spdk_nvme_transport_id trid;
    struct ublock_bdev bdev;

    if (pci == NULL || errlog_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    if (ublock_claim_nvme_for_local_query(&trid, &bdev, pci) != 0) {
        return -1;
    }

    /* spdk_nvme_probe is not thread safe */
    (void)pthread_mutex_lock(&g_probe_lock);
    ublock_uio_lock();
    fd = ublock_probe_nvme_for_local_query(&trid, &bdev);
    if (fd < 0) {
        ublock_uio_unlock();
        (void)pthread_mutex_unlock(&g_probe_lock);
        return -1;
    }

    /* after nvme probe, start to get error log info */
    ret = spdk_nvme_ctrlr_get_error_info(bdev.ctrlr, err_entries,
                                         (struct spdk_nvme_error_information_entry *)errlog_info);
    if (ret < 0) {
        SPDK_WARNLOG("[ublock-server] get error log info from local failed.\n");
    }

    /* detach the nvme ctrlr for the next operation. */
    ublock_detach_nvme_for_local_query(bdev.ctrlr);
    ublock_uio_unlock();
    (void)pthread_mutex_unlock(&g_probe_lock);
    /* return the actual count of error log entries. */
    return ret;
}

int ublock_get_error_log_info(const char *pci, uint32_t err_entries, struct ublock_nvme_error_info *errlog_info)
{
    int ret;

    if (pci == NULL || errlog_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    if (err_entries > UBLOCK_RPC_ERROR_LOG_MAX_COUNT) {
        SPDK_ERRLOG("[ublock] count of error log pages"
                    " should not larger than %d.\n", UBLOCK_RPC_ERROR_LOG_MAX_COUNT);
        return -1;
    }

    ret = ublock_client_query_err_log_info(LOCAL_RPC_QUERY, pci, err_entries, errlog_info);
    if (ret <= 0) {
        SPDK_ERRLOG("[ublock-client] cannot get error log info from ublock server.\n");
        return -EAGAIN;
    }

    if (ret < (int)err_entries) {
        SPDK_NOTICELOG("[ublock] this nvme controller supports %d error log entries.\n", ret);
    }
    return ret;
}

int _ublock_get_error_log_info(const char *pci, uint32_t err_entries, struct ublock_nvme_error_info *errlog_info)
{
    int ret;

    if (pci == NULL || errlog_info == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    if (err_entries > UBLOCK_RPC_ERROR_LOG_MAX_COUNT) {
        SPDK_ERRLOG("[ublock] count of error log pages should not larger than 256.\n");
    }

    /* try to get information from local app firstly. */
    ret = _ublock_get_error_log_info_from_local(pci, err_entries, errlog_info);
    if (ret > 0) {
        SPDK_NOTICELOG("[ublock-server] get error log info from local success.\n");
        goto exit;
    }

    /* try to get information from rpc. */
    /* remote query error log info of pci device. */
    SPDK_NOTICELOG("[ublock-server] get error log info from remote call.\n");
    ret = ublock_client_query_err_log_info(REMOTE_RPC_QUERY, pci, err_entries, errlog_info);
    if (ret <= 0) {
        SPDK_ERRLOG("[ublock-server] cannot get info from rpc.\n");
        return -1;
    }

exit:
    if (ret < (int)err_entries) {
        SPDK_NOTICELOG("[ublock] this nvme controller supports %d error log entries.\n", ret);
    }
    return ret;
}

static int _ublock_nvme_ctrlr_shutdown_reset_from_local(const char *pci, bool reset_flag)
{
    int fd = -1;
    struct spdk_nvme_transport_id trid;
    struct ublock_bdev bdev;
    int ret = 0;

    if (pci == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    if (ublock_claim_nvme_for_local_query(&trid, &bdev, pci) != 0) {
        return -1;
    }

    /* spdk_nvme_probe is not thread safe */
    (void)pthread_mutex_lock(&g_probe_lock);
    ublock_uio_lock();
    fd = ublock_probe_nvme_for_local_query(&trid, &bdev);
    if (fd < 0) {
        ublock_uio_unlock();
        (void)pthread_mutex_unlock(&g_probe_lock);
        return -1;
    }

    /* if probe is successful, it means no one is using that device to read or write. */
    if (reset_flag) {
        /* this function contains safely reset nvme driver operation , detach and rebind the nvme. */
        ret = ublock_reset_nvme_for_local_query(trid.traddr, bdev.ctrlr);
    } else {
        /* this function contains safely shutdown operation ,so detach the nvme directly here. */
        ublock_detach_nvme_for_local_query(bdev.ctrlr);
        ublock_uio_unlock();
    }

    (void)pthread_mutex_unlock(&g_probe_lock);
    return ret;
}

int ublock_shutdown_disk(const char *pci, bool reset_flag)
{
    int ret;
    char *op_name[2] = { "shutdown", "reset driver" }; // 2 kinds of operations

    if (pci == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    ret = _ublock_nvme_ctrlr_shutdown_reset(pci, reset_flag);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock-client] %s %s nvme fail. ret is %d\n", op_name[reset_flag ? 1 : 0], pci, ret);
        return -1;
    }

    SPDK_NOTICELOG("[ublock-client] %s %s nvme successfully.\n", op_name[reset_flag ? 1 : 0], pci);
    return ret;
}

int _ublock_nvme_ctrlr_shutdown_reset(const char *pci, bool reset_flag)
{
    int ret;
    char *op_name[2] = { "shutdown", "reset driver" }; // 2 kinds of operations

    if (pci == NULL) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    /* try to probe the nvme device from local app firstly. */
    /* if it is successful to probe, it means LibStorage is not start and it is safe to shutdown. */
    ret = _ublock_nvme_ctrlr_shutdown_reset_from_local(pci, reset_flag);
    if (ret == 0) {
        SPDK_NOTICELOG("[ublock-server] probe %s nvme local, it is safe to shutdown.\n", pci);
        goto exit;
    } else if (ret == -EBUSY) {
        SPDK_ERRLOG("[ublock-server] rebind %s nvme driver fail from local.\n", pci);
        return ret;
    }

exit:
    SPDK_NOTICELOG("[ublock] %s %s nvme successfully.\n", op_name[reset_flag ? 1 : 0], pci);

    return ret;
}

int ublock_string_to_int(const char *str, int *result)
{
    long ret;
    char *endptr = NULL;

    ret = strtol(str, &endptr, 0);
    if (errno || endptr[0] != '\0') {
        return -1;
    }

#if __WORDSIZE == 64
    if ((ret > INT_MAX) || (ret < INT_MIN)) {
        return -1;
    }
#endif

    *result = (int)ret;
    return 0;
}

static void get_log_page_completion(void *cb_arg, const struct spdk_nvme_cpl *cpl)
{
    completion_poll_status_set_done(cb_arg, cpl);
}

static int _ublock_get_log_page_from_local(const char *pci, uint8_t log_page, uint32_t nsid,
                                           uint8_t *payload, uint32_t payload_size)
{
    int rc;
    struct ublock_bdev bdev;
    struct spdk_nvme_transport_id trid;
    int fd = -1;
    struct completion_poll_status status;

    if (ublock_claim_nvme_for_local_query(&trid, &bdev, pci) != 0) {
        return -1;
    }

    (void)pthread_mutex_lock(&g_probe_lock);
    ublock_uio_lock();
    fd = ublock_probe_nvme_for_local_query(&trid, &bdev);
    if (fd < 0) {
        ublock_uio_unlock();
        (void)pthread_mutex_unlock(&g_probe_lock);
        return -1;
    }
    status.done = false;
    rc = spdk_nvme_ctrlr_cmd_get_log_page(bdev.ctrlr, log_page, nsid, payload, payload_size,
                                          0, get_log_page_completion, &status);
    if (rc != 0) {
        goto free_and_out;
    }
    while (status.done == false) {
        (void)spdk_nvme_ctrlr_process_admin_completions(bdev.ctrlr);
    }
    if (spdk_nvme_cpl_is_error(&status.cpl) || status.status != 0) {
        SPDK_ERRLOG("get_log_page_completion failed! sc[%d], sct[%d], status[%d]\n",
                    status.cpl.status.sc, status.cpl.status.sct, status.status);
        rc = -ENXIO;
    }

free_and_out:
    ublock_detach_nvme_for_local_query(bdev.ctrlr);
    ublock_uio_unlock();
    (void)pthread_mutex_unlock(&g_probe_lock);
    return rc;
}

int _ublock_get_log_page(const char *pci, uint8_t log_page, uint32_t nsid,
                         uint8_t *payload, uint32_t payload_size)
{
    int ret;
    struct rpc_log_page rpc_param = {0};

    if (pci == NULL || payload == NULL || payload_size == 0) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    ret = _ublock_get_log_page_from_local(pci, log_page, nsid, payload, payload_size);
    if (ret >= 0) {
        SPDK_NOTICELOG("[ublock] get log page from local success.\n");
        return 0;
    }

    rpc_param.pci = pci;
    rpc_param.nsid = nsid;
    rpc_param.log_page = log_page;
    rpc_param.payload = payload;
    rpc_param.payload_size = payload_size;
    ret = ublock_client_query_log_page_info(REMOTE_RPC_QUERY, &rpc_param);
    if (ret < 0) {
        SPDK_ERRLOG("[ublock] cannot get log page from remote.\n");
        return -1;
    }

    return ret;
}

int ublock_get_log_page(const char *pci, uint8_t log_page, uint32_t nsid,
                        void *payload, uint32_t payload_size)
{
    int ret;
    struct rpc_log_page rpc_param = {0};

    if (pci == NULL || payload == NULL || payload_size == 0 || payload_size > UBLOCK_RPC_MAX_LOG_PAGE_SIZE) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    rpc_param.pci = pci;
    rpc_param.nsid = nsid;
    rpc_param.log_page = log_page;
    rpc_param.payload = payload;
    rpc_param.payload_size = payload_size;
    ret = ublock_client_query_log_page_info(LOCAL_RPC_QUERY, &rpc_param);
    if (ret < 0) {
        SPDK_ERRLOG("[ublock] cannot get info rpc from local\n");
        return -1;
    }
    return ret;
}

static void admin_passthru_cb(void *cb_arg, const struct spdk_nvme_cpl *cpl)
{
    completion_poll_status_set_done(cb_arg, cpl);
}

static int _ublock_nvme_admin_passthru_local(const char *pci, void *cmd, void *buf, uint32_t nbytes)
{
    int rc;
    struct ublock_bdev bdev;
    struct spdk_nvme_transport_id trid;
    struct completion_poll_status status;

    if (pci == NULL || cmd == NULL || buf == NULL || nbytes > UBLOCK_ADMIN_CMD_BUF_MAX_SIZE) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    if (ublock_claim_nvme_for_local_query(&trid, &bdev, pci) != 0) {
        return -1;
    }

    (void)pthread_mutex_lock(&g_probe_lock);
    ublock_uio_lock();
    rc = ublock_probe_nvme_for_local_query(&trid, &bdev);
    if (rc < 0) {
        ublock_uio_unlock();
        (void)pthread_mutex_unlock(&g_probe_lock);
        return -1;
    }
    status.done = false;
    rc = spdk_nvme_ctrlr_cmd_admin_raw(bdev.ctrlr, cmd, buf, nbytes, admin_passthru_cb, &status);
    if (rc != 0) {
        goto out;
    }
    while (status.done == false) {
        (void)spdk_nvme_ctrlr_process_admin_completions(bdev.ctrlr);
    }
    if (spdk_nvme_cpl_is_error(&status.cpl) || status.status != 0) {
        SPDK_ERRLOG("nvme_admin_passthru failed! sc[%d], sct[%d], status[%d]\n",
                    status.cpl.status.sc, status.cpl.status.sct, status.status);
        rc = -ENXIO;
    }
out:
    ublock_detach_nvme_for_local_query(bdev.ctrlr);
    ublock_uio_unlock();
    (void)pthread_mutex_unlock(&g_probe_lock);
    return rc;
}

int32_t ublock_nvme_admin_passthru(const char *pci, void *cmd, void *buf, size_t nbytes)
{
    uint16_t opc;

    if (pci == NULL || cmd == NULL || buf == NULL || nbytes > UBLOCK_ADMIN_CMD_IDENTIFY_SIZE) {
        SPDK_ERRLOG("[ublock] invalid parameters, pci: %p, cmd: %p, buf: %p, nbytes: %lu.\n", pci, cmd, buf, nbytes);
        return -1;
    }

    opc = ((struct spdk_nvme_cmd *)cmd)->opc;
    switch (opc) {
        case SPDK_NVME_OPC_IDENTIFY:
            if (nbytes != UBLOCK_ADMIN_CMD_IDENTIFY_SIZE) {
                SPDK_ERRLOG("[ublock] The command(%d) has invalid buf size(%lu)\n", (int)opc, nbytes);
                return -1;
            }
            break;
        default:
            SPDK_ERRLOG("The command(%d) is not supported.\n", (int)opc);
            return -1;
    }

    return ublock_client_nvme_admin_passthru(LOCAL_RPC_QUERY, pci, cmd, buf, nbytes);
}

int32_t _ublock_nvme_admin_passthru(const char *pci, void *cmd, void *buf, uint32_t nbytes)
{
    int ret = -1;

    if (pci == NULL || cmd == NULL || buf == NULL || nbytes > UBLOCK_ADMIN_CMD_BUF_MAX_SIZE) {
        SPDK_ERRLOG("[ublock] invalid parameters.\n");
        return -1;
    }

    /* first try local */
    ret = _ublock_nvme_admin_passthru_local(pci, cmd, buf, nbytes);
    if (ret == 0) {
        SPDK_NOTICELOG("[ublock-server] nvme admin passthru from local success\n");
        return 0;
    }

    /* remote nvme admin passthru to pci */
    SPDK_NOTICELOG("[ublock-server] nvme admin passthru remote\n");
    ret = ublock_client_nvme_admin_passthru(REMOTE_RPC_QUERY, pci, cmd, buf, nbytes);
    if (ret != 0) {
        SPDK_ERRLOG("[ublock-server] remote jsonrpc can't nvme admin passthru\n");
        return -1;
    }

    return 0;
}

