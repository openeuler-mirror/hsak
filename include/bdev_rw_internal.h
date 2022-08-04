/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: this is a header file for the data structure defined internally by libstorage.
 * Author: xiehuiming@huawei.com
 * Create: 2018-09-01
 */

#ifndef BDEV_RW_INTERNAL_H
#define BDEV_RW_INTERNAL_H

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <regex.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_eal_memconfig.h>
#include <securec.h>
#include <string.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include "bdev_rw_common.h"
#include "spdk/bdev_rw.h"
#include "spdk/conf.h"
#include "spdk/event.h"
#include "spdk/trace.h"
#include "spdk/util.h"
#include "spdk/thread.h"

enum disktype_E {
    NVME_DISK = 1,
    INVALID_DISK
};

enum diskstate_E {
    DISK_REUSE = -3,
    DISK_RELEASE = -2,
    DISK_DELETE = -1,
    DISK_CLOSE = 0,
};

enum OPCODE_TYPE {
    OP_READ = 1,
    OP_WRITE,
    OP_READV,
    OP_WRITEV,
    OP_DEALLOCATE,
    OP_NOP = 7
};

#define NS_CANNOT_SHARE 0
#define NS_CAN_SHARE 1
#define NS_ID_INVALID 0
#define NBYTES_TO_MAX_MDSIZE(nbytes) (((((nbytes) - 1) & 512) + 1) * 8)
#define PI_SIZE 8
#define DISK_TYPE_SHIFT1_FOR_FD 30
#define DISK_TYPE_SHIFT2_FOR_FD 29
#define SPDK_THREAD_NAME_LENGTH 64
#define SPDK_MAX_BDEV_NAME_LEN 10

/* refer to SPDK_BDEV_IO_POOL_SIZE, keep the same limitation */
#define LIBSTORAGE_IO_T_POOL_SIZE (64 * 1024)

/* the shm file for probe operation */
#define LIBSTORAGE_UBLOCK_LOCKFILE          "/var/run/ublock_uio.pid"

#define LIBSTORAGE_LOAD_MAX_CONTROLLERS 36
#define LIBSTORAGE_CONFIG_MAX_CONTROLLERS 72
#define LIBSTORAGE_LOAD_FINISH 0
#define LIBSTORAGE_LOAD_SUCCESS 1
#define LIBSTORAGE_LOAD_NEW 1

/* max socket cmd size */
#define MAX_SOCKET_CMD_SIZE 512

extern bool g_bSameBdevMultiQ;
extern bool g_bUseReactor;
extern struct spdk_conf *g_libstorage_config;
extern uint8_t g_ucE2EDif;
extern bool g_bSpdkInitcomplete;
extern void *g_alloc_io_t[];
extern struct spdk_mempool *g_libstorage_io_t_mempool;
extern pthread_mutex_t *g_libstorage_admin_op_mutex;
extern struct spdk_thread  *g_masterThread;
extern bool g_useCUSE;

struct pi_struct {
    uint16_t guard_tag;
    uint16_t app_tag;
    uint32_t ref_tag;
};

typedef struct libstorage_device_fd {
    char devname[MAX_BDEV_NAME_LEN];
    int32_t fd;
    int32_t disktype;
    volatile int32_t ref;
    volatile bool inCompletionCtx; /* In completion context or not. Use in nopoll model */
    int8_t pad[3];                 /* 3 means the length of reserved text */
    void *ctrlr;
    void *bdev_desc;
    void *channel;
    void *thread;
    void *data;
    SLIST_ENTRY(libstorage_device_fd)
    slist;
} LIBSTORAGE_DEVICE_FD_T;

typedef SLIST_HEAD(, libstorage_device_fd) LibstorageDevFdListHead;

/* caller of this function needs to hold the pthread_mutex_lock which protects the list to find */
static inline LIBSTORAGE_DEVICE_FD_T *LibstorageFindDevfd(const LibstorageDevFdListHead *fdList, int32_t fd)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    SLIST_FOREACH(devfd, fdList, slist) {
        if (fd == devfd->fd) {
            break;
        }
    }
    return devfd;
}

static inline LIBSTORAGE_DEVICE_FD_T* LibstorageGetDeviceFd(const LibstorageDevFdListHead *fdList, int32_t fd)
{
    LIBSTORAGE_DEVICE_FD_T *devfd = NULL;
    SLIST_FOREACH(devfd, fdList, slist) {
        if (fd == devfd->fd) {
            if (spdk_unlikely(devfd->ref <= (int32_t)DISK_CLOSE)) {
                return NULL;
            }
            break;
        }
    }
    return devfd;
}

struct rw_completion_status {
    int32_t result;
    volatile bool done;
};

struct ctrlr_capability_info {
    char ctrlrName[MAX_CTRL_NAME_LEN];
    struct {
        /** metadata size */
        uint32_t ms : 16; /* Ԫ�����ֽ�������СΪ8�ֽ� */

        /** lba data size */
        uint32_t lbads : 8; /* ָʾLBA��СΪ2^lbads,lbads��С��9 */

        /** relative performance */
        uint32_t rp : 2;

        uint32_t reserved : 6;
    } lbaf[LBA_FORMAT_NUM];
    uint16_t max_num_ns;
    uint8_t nlbaf;
    uint8_t pad;
    uint32_t cur_format : 4;
    uint32_t cur_extended : 1;
    uint32_t cur_pi : 3;
    uint32_t cur_pil : 1;
    uint32_t cur_can_share : 1;
    uint32_t mc_extented : 1;
    uint32_t mc_pointer : 1;
    uint32_t pi_type1 : 1;
    uint32_t pi_type2 : 1;
    uint32_t pi_type3 : 1;
    uint32_t md_start : 1;
    uint32_t md_end : 1;
    uint32_t ns_manage : 1;
    uint32_t directives : 1;
    uint32_t reserved : 1;
    uint32_t dsm : 1;
    uint32_t reserved1 : 11;
    SLIST_ENTRY(ctrlr_capability_info)
    slist;
};

enum nvme_reload_state {
    RELOAD_NULL = 0, /* state is not initialized */
    RELOAD_REMAIN,
    RELOAD_DELETE,
    RELOAD_CREATE,
};

struct libstorage_nvme_config {
    char ctrlName[MAX_CTRL_NAME_LEN];
    char pciAddr[MAX_PCI_ADDR_LEN];
    enum nvme_reload_state state;
};

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

typedef struct {
    volatile int val;
} libstorage_atomic32_t;

#define LIBSTORAGE_ATOMIC32_INIT(i)    { (i) }

static __always_inline int libstorage_atomic32_read(libstorage_atomic32_t *v)
{
    return (int)v->val;
}

static __always_inline void libstorage_atomic32_set(libstorage_atomic32_t *v, int i)
{
    v->val = i;
}

/* Return: new value */
static __always_inline int libstorage_atomic32_add_return(libstorage_atomic32_t *v, int i)
{
    return __sync_add_and_fetch(&v->val, i);
}

/* Return: new value */
static __always_inline int libstorage_atomic32_sub_return(libstorage_atomic32_t *v, int i)
{
    return __sync_sub_and_fetch(&v->val, i);
}

/* Return: new value */
static __always_inline int libstorage_atomic32_inc_return(libstorage_atomic32_t *v)
{
    return __sync_add_and_fetch(&v->val, 1);
}

/* Return: new value */
static __always_inline int libstorage_atomic32_dec_return(libstorage_atomic32_t *v)
{
    return __sync_sub_and_fetch(&v->val, 1);
}

static __always_inline void libstorage_atomic32_inc(libstorage_atomic32_t *v)
{
    __sync_add_and_fetch(&v->val, 1);
}

static __always_inline void libstorage_atomic32_dec(libstorage_atomic32_t *v)
{
    __sync_sub_and_fetch(&v->val, 1);
}

/* Return: old value */
static __always_inline int libstorage_atomic32_return_add(libstorage_atomic32_t *v, int i)
{
    return __sync_fetch_and_add(&v->val, i);
}

/* Return: old value */
static __always_inline int libstorage_atomic32_return_sub(libstorage_atomic32_t *v, int i)
{
    return __sync_fetch_and_sub(&v->val, i);
}

/* Return: old value */
static __always_inline int libstorage_atomic32_return_inc(libstorage_atomic32_t *v)
{
    return __sync_fetch_and_add(&v->val, 1);
}

/* Return: old value */
static __always_inline int libstorage_atomic32_return_dec(libstorage_atomic32_t *v)
{
    return __sync_fetch_and_sub(&v->val, 1);
}

static __always_inline int libstorage_atomic32_cmp_and_swap(libstorage_atomic32_t *v, int oldVal, int newVal)
{
    return __sync_val_compare_and_swap(&v->val, oldVal, newVal);
}

static __always_inline bool libstorage_atomic32_test_and_set(libstorage_atomic32_t *v, int val)
{
    return __sync_bool_compare_and_swap(&v->val, 0, val);
}

static inline int libstorage_thread_cb(struct spdk_thread *thread)
{
    return 0;
}

int32_t libstorage_io_t_mempool_initialize(void);
void libstorage_io_t_mempool_free(void);
void *libstorage_io_t_alloc_buf(void);
void libstorage_io_t_free_buf(LIBSTORAGE_IO_T *buf);

void async_io_completion_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
bool libstorage_dif_verify_crc(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *io);
bool libstorage_dif_verify_crc_v(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *io);
int32_t libstorage_dif_generate(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *io);
int32_t libstorage_dif_generate_v(const struct spdk_bdev *bdev, const LIBSTORAGE_IO_T *io);
int32_t libstorage_open_shm_set_size(const char *shm_name, off_t length, bool *is_create);
struct spdk_nvme_ns *libstorage_get_ns_by_devname(const char *devname);
int LibstorageDeallocateNvme(const LIBSTORAGE_DEVICE_FD_T *devfd, LIBSTORAGE_IO_T *io, spdk_bdev_io_completion_cb cb);
int LibstorageLaunchIoToNvme(const LIBSTORAGE_DEVICE_FD_T *devfd, LIBSTORAGE_IO_T *io, spdk_bdev_io_completion_cb cb);
void LibstoragePollExitCheckResource(void);

int32_t libstorage_process_bdev_rsp_nopoll(int fd);
int32_t libstorage_open_nopoll(const char *devfullname);
int32_t libstorage_close_nopoll(int32_t fd);
int32_t libstorage_submit_io_nopoll(LIBSTORAGE_IO_T *submitio);
int32_t libstorage_init_without_reactor(void);
int32_t libstorage_exit_without_reactor(void);

int32_t libstorage_open_poll(const char *devfullname);
int32_t libstorage_close_poll(int32_t fd);
int32_t libstorage_submit_io_poll(LIBSTORAGE_IO_T *submitio);
int32_t libstorage_init_with_reactor(void);
int32_t libstorage_exit_with_reactor(void);
void libstorage_notify_dpdk_init(void);
struct spdk_thread *libstorage_create_spdk_thread(void);

int32_t libstorage_get_print_level_from_conf(struct spdk_conf_section *sp);
void libstorage_get_dif_from_conf(struct spdk_conf_section *sp);
int32_t libstorage_init_nvme_conf(struct libstorage_nvme_config *p_nvmes_config, size_t nvmes_config_size);
int32_t libstorage_insert_nvme_conf(struct libstorage_nvme_config *p_nvmes_config, int32_t *config_nvme_tail,
                                    const struct libstorage_nvme_config *nvme_config);
int32_t libstorage_update_nvme_conf(struct libstorage_nvme_config *p_nvmes_config, int32_t config_nvme_num,
                                    const struct libstorage_nvme_config *nvme_config);
int32_t libstorage_get_one_nvme_from_conf(struct spdk_conf_section *sp,
                                          int32_t index, struct libstorage_nvme_config *nvme_config);
int32_t libstorage_get_nvme_from_conf(const char *cfgfile,
                                      struct libstorage_nvme_config *p_nvmes_config, int32_t config_nvme_num);
int32_t libstorage_init_global_conf(const char *cfgfile);
int32_t libstorage_parse_conf_item(const char *cfgfile);
int build_socket_cmd(char *cmd_str, size_t size, const char *socket_mem,
                     const char *socket_limit);

#endif
