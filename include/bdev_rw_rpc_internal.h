/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: this is a header file for interaction function between LibStorage and ublock.
 * Author: louhongxiang@huawei.com
 * Create: 2018-09-01
 */

#ifndef LIBSTORAGE_RPC_INTERNAL_H
#define LIBSTORAGE_RPC_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <sys/queue.h>
#include "bdev_rw_internal.h"

extern bool g_bRpcServer;

/* internal interface of removing cap info specified by ctrlName from list. */
void libstorage_remove_ctrlr_cap_info(const char *ctrlName);
/* internal interface of removing register info specified by ctrlrName from list. */
int libstorage_remove_rpc_register_info(const char *ctrlrName);

/* robust mutex lock init function */
int libstorage_robust_mutex_init_recursive_shared(pthread_mutex_t *mtx);
/* robust mutex lock function */
int libstorage_process_mutex_lock(pthread_mutex_t *mutex);
/* robust mutex unlock function */
int libstorage_process_mutex_unlock(pthread_mutex_t *mutex);

/* This struct contains pci address and socket address for libstroage register to ublock. */
struct libstorage_rpc_register_ublock_info {
    char *plg_sock_addr;
    char pci[MAX_PCI_ADDR_LEN];
    char ctrlName[MAX_CTRL_NAME_LEN];
    SLIST_ENTRY(libstorage_rpc_register_ublock_info)
    slist;
};

/* part of nvme SMART info */
struct ublock_SMART_info {
    uint8_t critical_warning;
    uint16_t temperature;
    uint8_t available_spare;
    uint8_t available_spare_threshold;
    uint8_t percentage_used;
};

struct rpc_pci_dev {
    char *pci;
};

struct rpc_iostat_dev {
    char *pci;
    int32_t iostat_enable;
};

struct rpc_pci_nsid_dev {
    char *pci;
    uint32_t nsid;
};

struct rpc_pci_errs_dev {
    char *pci;
    uint32_t err_entries;
};

struct rpc_pci_log_page {
    char *pci;
    uint32_t nsid;
    uint8_t pageid;
    uint32_t size;
};

struct rpc_admin_passthru {
    char *pci;
    uint32_t nbytes;
    char *cmd;
};

#define JSONRPC_MAX_RESPONSE_LEN    8192    /* the max length of jsonrpc response */

#define NVME_SN_LEN  20    /* the max length of the device serial number */
#define NVME_MN_LEN  40    /* the max length of the device model */
#define NVME_FR_LEN  8     /* the max length of the firmware version */
/* nvme info-querying */
struct ublock_bdev_info {
    uint64_t sector_size;
    uint64_t cap_size;           /* cap_size */
    uint32_t md_size;            /* metadata size */
    uint16_t device_id;
    uint16_t subsystem_device_id;
    uint16_t vendor_id;
    uint16_t subsystem_vendor_id;
    uint16_t controller_id;
    int8_t serial_number[NVME_SN_LEN];
    int8_t model_number[NVME_MN_LEN];
    int8_t firmware_revision[NVME_FR_LEN];
};

#define UBLOCK_BDEV_PCI_LEN 256
struct ublock_bdev {
    /* Unique name for this block device. */
    char pci[UBLOCK_BDEV_PCI_LEN];
    struct ublock_bdev_info info;
    struct spdk_nvme_ctrlr *ctrlr;
    TAILQ_ENTRY(ublock_bdev)
    link;
};

struct params {
    char *pci;
};

void libstorage_start_rpc_server(void);
void libstorage_stop_rpc_server(void);
int libstorage_register_one_info_to_ublock(const char *pci, const char *name);

#endif /* endif LIBSTORAGE_RPC_INTERNAL_H */
