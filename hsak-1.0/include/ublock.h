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
 * Description: ublock API head file
 * Author: zhoupengchen
 * Create: 2018-9-1
 */

#ifndef UBLOCK_H_
#define UBLOCK_H_

#include <stdint.h> /* for uint64_t */

#include <sys/queue.h> /* for TAILQ_xxx */
#include <sys/types.h> /* for ssize_t */
#include <stdbool.h>

#define UBLOCK_NVME_UEVENT_SUBSYSTEM_UIO 1

#define UBLOCK_TRADDR_MAX_LEN 256

#define UBLOCK_PCI_ADDR_MAX_LEN 256

/* ublock initialization */
enum ublock_rpc_server_status {
    /* start ublock without rpc server */
    UBLOCK_RPC_SERVER_DISABLE = 0,
    /* start ublock with rpc server */
    UBLOCK_RPC_SERVER_ENABLE = 1,
};

/**
 * Initialize ublock resources when startup.
 * Ublock must be init prior to using any other ublock functions.
 *
 * IN:
 * @name dpdk env name.
 * @flg  flag to tell if start rpc service
 *
 * RETURNS:
 * 0 for success, -1 for fail. If rpc thread or monitor thread fail to start,
 * ublock will exit(EXIT_FAILURE);
 */
int init_ublock(const char *name, enum ublock_rpc_server_status flg);

/* init ublock with starting rpc server */
#define ublock_init(name) init_ublock(name, UBLOCK_RPC_SERVER_ENABLE)

/* init ublock without start rpc server */
#define ublock_init_norpc(name) init_ublock(name, UBLOCK_RPC_SERVER_DISABLE)

/**
 * Finalize ublock managed resources
 */
void ublock_fini(void);

/**
 * Structures for I/O stat info base iostat shm.
 */
struct ublock_ctrl_iostat_info {
    uint64_t num_read_ops;
    uint64_t num_write_ops;
    uint64_t read_latency_ms;
    uint64_t write_latency_ms;
    uint64_t io_outstanding;
    uint64_t num_poll_timeout;
    uint64_t io_ticks_ms;
};

int ublock_get_ctrl_iostat(const char* pci, struct ublock_ctrl_iostat_info *ctrl_iostat);

/* nvme info-querying */
struct ublock_bdev_info {
    uint64_t sector_size;         /* nvme sector size (ex. 512) */
    uint64_t cap_size;            /* nvme capability size */
    uint32_t md_size;             /* nvme metadata size */
    uint16_t device_id;           /* device id of nvme control */
    uint16_t subsystem_device_id; /* subsystem device id of nvme control */
    uint16_t vendor_id;           /* vendor id of nvme control */
    uint16_t subsystem_vendor_id; /* subsystem vendor id of nvme control */
    uint16_t controller_id;       /* control id */
    int8_t serial_number[20];     /* 20 bytes serail number of nvme */
    int8_t model_number[40];      /* 40 bytes model number of nvme */
    int8_t firmware_revision[8];  /* 8 bytes firmware revision of nvme */
};

struct ublock_bdev {
    char pci[UBLOCK_PCI_ADDR_MAX_LEN]; /* pci address, unique name for nvme device */
    struct ublock_bdev_info info;      /* information struct of nvme device */
    struct spdk_nvme_ctrlr *ctrlr;     /* pointer of nvme control(used only inside) */
    TAILQ_ENTRY(ublock_bdev)
    link;
};

struct ublock_bdev_mgr {
    TAILQ_HEAD(, ublock_bdev)
    bdevs; /* nvme device list */
};

/**
 * scan the list of nvme pci device to get its pci address
 *
 * OUT:
 * @bdev_list store nvme device pci address into each element of device list
 *
 * RETURN:
 * 0, success to scan device list
 * -1, fail to scan device list
 * -2, no NVMe device in environment
 *
 * NOTE:
 * 1.the parameter `bdev_list' is managed outside
 * 2.the element in `bdev_list' is malloced, should call ublock_free_bdevs to free
 */
int ublock_get_bdevs(struct ublock_bdev_mgr *bdev_list);
/* the list of nvme pci device has to be freed, when it is not used. */
void ublock_free_bdevs(struct ublock_bdev_mgr *bdev_list);

/**
 * get nvme device information according to its pci address
 *
 * IN:
 * @pci  pci address of nvme device
 *
 * OUT:
 * @bdev information structure `bdev' of nvme device
 *
 * RETURN:
 * 0, success to get information of given pci address
 * -1, fail to get information of given pci address
 * -EAGAIN, need application retry
 *
 * NOTE:
 * 1.the parameter `bdev' is managed outside
 * 2.when finish to get information, call ublock_free_bdev to release controller of nvme device
 */
int ublock_get_bdev(const char *pci, struct ublock_bdev *bdev);
/* bdev has to be freed when you get the info */
void ublock_free_bdev(struct ublock_bdev *bdev);

/**
 * TAILQ operation to go through the queue
 */
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
            (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
            (var) = (tvar))

/**
 * get nvme device information according to its serial number(ESN)
 *
 * IN:
 * @esn  serial number of nvme device
 *
 * OUT:
 * @bdev information structure `bdev' of nvme device
 *
 * RETURN:
 * 0, success to get information of given esn number
 * -1, fail to get information of given esn number
 * -EAGAIN, need application retry
 *
 * NOTE:
 * 1.the parameter `bdev' is managed outside
 * 2.when finish to get information, call ublock_free_bdev to release controller of nvme device
 */
int ublock_get_bdev_by_esn(const char *esn, struct ublock_bdev *bdev);

/* nvme SMART-querying */
/* the total length of SMART information is 512 bytes. */
#define UBLOCK_SMART_INFO_LEN 512

struct __attribute__((packed)) __attribute__((aligned)) ublock_SMART_info {
    uint8_t critical_warning;
    uint16_t temperature;
    uint8_t available_spare;
    uint8_t available_spare_threshold;
    uint8_t percentage_used;
    uint8_t reserved[26]; /* reserved 26 bytes, it's standard struction */

    /*
     * Note that the following are 128-bit values, but are
     *  defined as an array of 2 64-bit values.
     */
    /* Data Units Read is always in 512-byte units. */
    uint64_t data_units_read[2]; /* 2 uint64 for read */
    /* Data Units Written is always in 512-byte units. */
    uint64_t data_units_written[2]; /* 2 uint64 for write */
    /* For NVM command set, this includes Compare commands. */
    uint64_t host_read_commands[2]; /* 2 uint64 for read commands */
    uint64_t host_write_commands[2]; /* 2 uint64 for write commands */
    /* Controller Busy Time is reported in minutes. */
    uint64_t controller_busy_time[2]; /* 2 uint64 for busy time */
    uint64_t power_cycles[2]; /* 2 uint64 for power cycles */
    uint64_t power_on_hours[2]; /* 2 uint64 for hours */
    uint64_t unsafe_shutdowns[2]; /* 2 uint64 for shutdowns */
    uint64_t media_errors[2]; /* 2 uint64 for errors */
    uint64_t num_error_info_log_entries[2]; /* 2 uint64 for log */
    /* Controller temperature related. */
    uint32_t warning_temp_time;
    uint32_t critical_temp_time;
    uint16_t temp_sensor[8]; /* 8 short for sensor */

    uint8_t reserved2[296]; /* reserved 296 bytes, it's standard struction */
};

/**
 * query SMART health information according pci address and namespace id,
 * the SMART health information will be stored in `smart_info'.
 *
 * IN:
 * @pci  nvme device pci address
 * @nsid nvme device namespace id, either legal namespace id or 0xFFFFFFFF is allowed
 *
 * OUT:
 * @smart_info structure to store smart information of nvme device
 *
 * RETURN:
 * 0, success to query smart information of nvme device
 * -1, fail to query smart information of nvme device
 * -EAGAIN, need application retry
 */
int ublock_get_SMART_info(const char *pci, uint32_t nsid,
                          struct ublock_SMART_info *smart_info);

/**
 * query SMART health information according serail number and namespace id,
 * the SMART health information will be stored in `smart_info'.
 *
 * IN:
 * @esn  nvme device serial number
 * @nsid nvme device namespace id, either legal namespace id or 0xFFFFFFFF is allowed
 *
 * OUT:
 * @smart_info structure to store smart information of nvme device
 *
 * RETURN:
 * 0, success to query smart information of nvme device
 * -1, fail to query smart information of nvme device
 * -2, fail to query smart information for no matched esn number
 */
int ublock_get_SMART_info_by_esn(const char *esn, uint32_t nsid, struct ublock_SMART_info *smart_info);

/* nvme error log querying */
struct ublock_nvme_error_info {
    uint64_t error_count;
    uint16_t sqid;
    uint16_t cid;
    uint16_t status;
    uint16_t error_location;
    uint64_t lba;
    uint32_t nsid;
    uint8_t vendor_specific;
    uint8_t         trtype;
    uint8_t         reserved30[2]; /* reseived 2 bytes */
    uint64_t        command_specific;
    uint16_t        trtype_specific;
    uint8_t         reserved42[22]; /* reseived 22 bytes */
};

/**
 * query error log page information according pci address.
 * how many error log entries that wanted should be specified by parameter err_entries.
 * the error log information will be stored in parameter errlog_info.
 * return value is the actual count of error log entries that we can get, because the count
 * of error log entries we want may larger than the count that the nvme controller supports.
 *
 * IN:
 * @pci         pci address of nvme device
 * @err_entries number of error log entries
 *
 * OUT:
 * @errlog_info error log information structure to store the result
 *
 * RETURN:
 * -1, fail to get error log information of nvme device
 * -EAGAIN, need application retry
 * number of error log entries, success to get error log information of nvme device
 */
int ublock_get_error_log_info(const char *pci, uint32_t err_entries,
                              struct ublock_nvme_error_info *errlog_info);

/**
 * query log page information according pci address, namespace id and page id,
 * the log page information will be stored in `payload'.
 *
 * IN:
 * @pci             nvme device pci address
 * @log_page        nvme device log page id
 * @nsid            nvme device namespace id, either legal namespace id or
 *                  0xFFFFFFFF is allowed
 * @payload_size    the size of payload
 *
 * OUT:
 * @payload         store log page of nvme device, caller should malloc and free
 *                  the buffer when call the interface
 *
 * RETURN:
 * 0, success to query log page information of nvme device
 * -1, fail to query log page information of nvme device
 */
int ublock_get_log_page(const char* pci, uint8_t log_page, uint32_t nsid,
                        void* payload, uint32_t payload_size);
/**
 * Passthru admin cmd to get identify
 *
 * IN:
 * @pci             nvme device pci address
 * @cmd             admin cmd, the size must be 64 bytes
 * @nbytes          the size of buf, can't more than 4096
 *
 * OUT:
 * @buf             store information user want from nvme
 *
 * RETURN:
 * 0, success to passthru admin cmd to nvme device
 * -1, fail to passthru admin cmd to nvme device
 */
int32_t ublock_nvme_admin_passthru(const char *pci, void *cmd, void *buf, size_t nbytes);
#endif /* UBLOCK_H_ */
