/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * Description: this is a header file of LibStorage IO interface for external users.
 * Author: xiehuiming@huawei.com
 * Create: 2018-09-01
 */

#ifndef LIBSTORAGE_BDEV_RW_H
#define LIBSTORAGE_BDEV_RW_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/uio.h>
#include <sys/queue.h>
#define MAX_BDEV_NAME_LEN 24
#define MAX_CTRL_NAME_LEN 16
#define MAX_PCI_ADDR_LEN  24

struct libstorage_dpdk_contig_mem {
    uint64_t virtAddr;  /* Virtual memory start address */
    uint64_t memLen;    /* The memory lengh of virtual memory */
    uint64_t allocLen;  /* The memory lengh for application alloc */
};

struct libstorage_dpdk_init_notify_arg {
    uint64_t baseAddr;     /* Virtual memory base address */
    uint16_t memsegCount;  /* Number of valid members of below 'memseg' */
    /*
     * Array of memory segment. The front and back
     * two segments of memory are not contiguous
     */
    struct libstorage_dpdk_contig_mem *memseg;
};

struct libstorage_dpdk_init_notify {
    const char *name;
    void (*notifyFunc)(const struct libstorage_dpdk_init_notify_arg *arg);
    TAILQ_ENTRY(libstorage_dpdk_init_notify) tailq;
};

void libstorage_add_notify_func(struct libstorage_dpdk_init_notify *notification);

/**
 * \brief Register a new notification function
 */
#define LIBSTORAGE_REGISTER_DPDK_INIT_NOTIFY(_name, _notify) \
    struct libstorage_dpdk_init_notify __libstorage_init_notify_ ## _name = \
    {   \
        .name = #_name, \
        .notifyFunc = _notify, \
    };  \
    __attribute__((constructor)) static void __libstorage_##_name ## _notify_register(void) \
    {   \
        libstorage_add_notify_func(&__libstorage_init_notify_ ## _name);    \
    }

enum libstorage_ns_lba_size {
    LIBSTORAGE_NVME_NS_LBA_SIZE_512 = 0x9,
    LIBSTORAGE_NVME_NS_LBA_SIZE_4K = 0xc
};

enum libstorage_ns_md_size {
    LIBSTORAGE_METADATA_SIZE_0 = 0,
    LIBSTORAGE_METADATA_SIZE_8 = 8,
    LIBSTORAGE_METADATA_SIZE_64 = 64
};

enum libstorage_ns_pi_type {
    LIBSTORAGE_FMT_NVM_PROTECTION_DISABLE = 0x0,
    LIBSTORAGE_FMT_NVM_PROTECTION_TYPE1 = 0x1,
    LIBSTORAGE_FMT_NVM_PROTECTION_TYPE2 = 0x2,
    LIBSTORAGE_FMT_NVM_PROTECTION_TYPE3 = 0x3,
};

enum libstorage_crc_and_prchk {
    /* application calculate crc and disable ctrl check guard */
    LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK = 0x0,
    /* application calculate crc and enable ctrl check guard */
    LIBSTORAGE_APP_CRC_AND_ENABLE_PRCHK = 0x1,
    /* libstorage calculate crc and disable ctrl check guard */
    LIBSTORAGE_LIB_CRC_AND_DISABLE_PRCHK = 0x2,
    /* libstorage calculate crc and enable ctrl check guard */
    LIBSTORAGE_LIB_CRC_AND_ENABLE_PRCHK = 0x3,
#define NVME_NO_REF 0x4
    /* application calculate crc and disable ctrl check guard and disable ctrl ref tag */
    LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK_NO_REF = LIBSTORAGE_APP_CRC_AND_DISABLE_PRCHK | NVME_NO_REF,
    /* application calculate crc and enable ctrl check guard and disable ctrl ref tag */
    LIBSTORAGE_APP_CRC_AND_ENABLE_PRCHK_NO_REF = LIBSTORAGE_APP_CRC_AND_ENABLE_PRCHK | NVME_NO_REF,
};

enum libstorage_print_log_level {
    LIBSTORAGE_PRINT_LOG_ERROR,
    LIBSTORAGE_PRINT_LOG_WARN,
    LIBSTORAGE_PRINT_LOG_NOTICE,
    LIBSTORAGE_PRINT_LOG_INFO,
    LIBSTORAGE_PRINT_LOG_DEBUG,
};

struct libstorage_namespace_info {
    char name[MAX_BDEV_NAME_LEN];
    uint64_t size;             /** namespace size in bytes */
    uint64_t sectors;          /** number of sectors */
    uint32_t sector_size;      /** sector size in bytes */
    uint32_t md_size;          /** metadata size in bytes */
    uint32_t max_io_xfer_size; /** maximum i/o size in bytes */
    uint16_t id;               /** namespace id */
    uint8_t pi_type;           /** end-to-end data protection information type */
    uint8_t is_active : 1;     /** namespace is active or not */
    uint8_t ext_lba : 1;       /** namespace support extending LBA size or not */
    uint8_t dsm : 1;           /** namespace supports Dataset Management or not */
    uint8_t pad : 3;
    uint64_t reserved;
};

#define LBA_FORMAT_NUM 16
struct libstorage_nvme_ctrlr_info {
    char name[MAX_CTRL_NAME_LEN];
    char address[MAX_PCI_ADDR_LEN];
    struct {
        uint32_t domain;
        uint8_t bus;
        uint8_t dev;
        uint8_t func;
    } pci_addr;
    uint64_t totalcap;      /* Total NVM Capacity in bytes */
    uint64_t unusecap;      /* Unallocated NVM Capacity in bytes */
    int8_t sn[20];          /* Serial number, length is 20 */
    uint8_t fr[8];          /* Firmware revision, length is 8 */
    uint32_t max_num_ns;    /* Number of namespaces */
    /*
     * Version of the NVM Express specification that
     * the controller implementation supports
     */
    uint32_t version;
    uint16_t num_io_queues; /* num of io queues */
    uint16_t io_queue_size; /* io queue size */
    uint16_t ctrlid;        /* Controller id */
    uint16_t pad1;
    struct {
        struct {
            /** metadata size */
            uint32_t ms : 16; /* Ԫ�����ֽ�������СΪ8�ֽ� */

            /** lba data size */
            uint32_t lbads : 8; /* ָʾLBA��СΪ2^lbads,lbads��С��9 */

            uint32_t reserved : 8;
        } lbaf[LBA_FORMAT_NUM];
        uint8_t nlbaf;
        uint8_t pad2[3];    /* length of pad2 is 3 */
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
        uint32_t ns_manage : 1;  /* Supports the Namespace Management and Namespace Attachment commands */
        uint32_t directives : 1; /* Controller support Directives or not */
        uint32_t reserved : 1;
        uint32_t dsm : 1;        /* Controller support Dataset Management or not */
        uint32_t reserved1 : 11;
    } cap_info;
};

struct libstorage_mgr_info {
    char pci[MAX_PCI_ADDR_LEN];
    char ctrlName[MAX_CTRL_NAME_LEN];
    uint64_t sector_size;
    uint64_t cap_size;
    uint16_t device_id;
    uint16_t subsystem_device_id;
    uint16_t vendor_id;
    uint16_t subsystem_vendor_id;
    uint16_t controller_id;
    int8_t serial_number[20];       /* length of sn is 20 */
    int8_t model_number[40];        /* length of mn is 40 */
    uint8_t firmware_revision[8];   /* length of fr is 8 */
};

/* same with struct spdk_nvme_health_information_page in nvme_spec.h */
struct __attribute__((packed)) __attribute__((aligned)) libstorage_smart_info {
    /* details of uint8_t critical_warning
     * union spdk_nvme_critical_warning_state {
     *      uint8_t     raw;
     *
     *      struct {
     *          uint8_t available_spare     : 1;
     *          uint8_t temperature     : 1;
     *          uint8_t device_reliability  : 1;
     *          uint8_t read_only       : 1;
     *          uint8_t volatile_memory_backup  : 1;
     *          uint8_t reserved        : 3;
     *      } bits;
     * };
     */
    uint8_t critical_warning;
    uint16_t temperature;
    uint8_t available_spare;
    uint8_t available_spare_threshold;
    uint8_t percentage_used;
    uint8_t reserved[26];               /* reserve 26 bytes */

    /*
     * Note that the following are 128-bit values, but are
     *  defined as an array of 2 64-bit values.
     */
    /* Data Units Read is always in 512-byte units. */
    uint64_t data_units_read[2];        /* 2 64-bit values to hold a 128-bit value */

    /* Data Units Written is always in 512-byte units. */
    uint64_t data_units_written[2];     /* 2 64-bit values to hold a 128-bit value */

    /* For NVM command set, this includes Compare commands. */
    uint64_t host_read_commands[2];     /* 2 64-bit values to hold a 128-bit value */
    uint64_t host_write_commands[2];    /* 2 64-bit values to hold a 128-bit value */

    /* Controller Busy Time is reported in minutes. */
    uint64_t controller_busy_time[2];   /* 2 64-bit values to hold a 128-bit value */
    uint64_t power_cycles[2];           /* 2 64-bit values to hold a 128-bit value */
    uint64_t power_on_hours[2];         /* 2 64-bit values to hold a 128-bit value */
    uint64_t unsafe_shutdowns[2];       /* 2 64-bit values to hold a 128-bit value */
    uint64_t media_errors[2];           /* 2 64-bit values to hold a 128-bit value */
    uint64_t num_error_info_log_entries[2]; /* 2 64-bit values to hold a 128-bit value */

    /* Controller temperature related. */
    uint32_t warning_temp_time;
    uint32_t critical_temp_time;
    uint16_t temp_sensor[8];            /* 8 16-bit values to hold a 128-bit value */

    uint8_t reserved2[296];             /* reserve 296 bytes here */
};
#define LIBSTORAGE_MAX_DSM_RANGE_DESC_COUNT 256

/* Dataset Management - Range Definition */
struct libstorage_dsm_range_desc {
    /* RESERVED */
    uint32_t reserved;

    /* NUMBER OF LOGICAL BLOCKS */
    uint32_t block_count;

    /* UNMAP LOGICAL BLOCK ADDRESS */
    uint64_t lba;
};

/**
 * Get all nvme information in current system.
 *
 * \param ppCtrlrInfo Output parameter for the array of nvme information.
 * \return a positive integer to indicate the number of nvme,
 *  return 0 if no any nvme information obtained from the current system.
 *
 * Attention: After the 'ppctrlrinfo' is used up, the caller must free the memory for 'ppctrlrinfo'.
 */
uint32_t libstorage_get_nvme_ctrlr_info(struct libstorage_nvme_ctrlr_info **ppCtrlrInfo);

/**
 * Get the nvme management information by ESN.
 *
 * \param esn ESN of nvme.
 * \param mgr_info Output parameter for the nvme management information.
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_get_mgr_info_by_esn(const char *esn, struct libstorage_mgr_info *mgr_info);

/**
 * Get the nvme SMART information by ESN.
 *
 * \param esn ESN of nvme
 * \param nsid The specified namespace identifier
 * \param mgr_smart_info Output parameter for the nvme SMART information
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_get_mgr_smart_by_esn(const char *esn, uint32_t nsid, struct libstorage_smart_info *mgr_smart_info);

/**
 * Get namespace information for the specified block device.
 *
 * \param bdevName The name of the specified block device
 * \param ppNsInfo Output parameter for the namespace information
 * \return 1 if operation is successful or 0 if the specified block device does not exist
 *
 * Attention: After the 'ppNsInfo' is used up, the caller must free the memory for 'ppNsInfo'
 */
uint32_t libstorage_get_bdev_ns_info(const char *bdevName, struct libstorage_namespace_info **ppNsInfo);

/**
 * Get all namespace information for the specified nvme.
 *
 * \param ctrlName The name of the specified nvme.
 * \param ppNsInfo Output parameter for all namespace information in the specified nvme
 * \return a positive integer to indicate the number of namespace,
 *  return 0 if no any namespace information obtained from the specified nvme.
 *
 * Attention: After the 'ppNsInfo' is used up, the caller must free the memory for 'ppNsInfo'
 */
uint32_t libstorage_get_ctrl_ns_info(const char *ctrlName, struct libstorage_namespace_info **ppNsInfo);

/**
 * Create one namespace in the specified nvme.
 *
 * \param ctrlName The name of the specified nvme.
 * \param ns_size The size of namespace in sectors.
 * \param outputName Output parameter for the name of the new namespace
 * \return a positive integer for new namespce identifier if operation is successful,
    return a negative interger if an error occurred
 *
 * Attention: After the 'outputName' is used up, the caller must free the memory for 'outputName'
 */
int32_t libstorage_create_namespace(const char *ctrlName, uint64_t ns_size, char **outputName);

/**
 * Delete one namespace from the specified nvme.
 *
 * \param ctrlName The name of the specified nvme.
 * \param ns_id The specified namespace identifier.
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_delete_namespace(const char *ctrlName, uint32_t ns_id);

/**
 * Delete all namespaces from the specified nvme.
 *
 * \param ctrlName The name of the specified nvme
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_delete_all_namespace(const char *ctrlName);

/**
 * Plug the specified nvme to current system.
 *
 * \param pci_addr The PCI address for the specified nvme
 * \param ctrlr_name The name of the specified nvme
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_nvme_create_ctrlr(const char *pci_addr, const char *ctrlr_name);

/**
 * Unplug the specified nvme from current system.
 *
 * \param ctrlr_name The name of the specified nvme
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_nvme_delete_ctrlr(const char *ctrlr_name);

/**
 * Reload the nvme configuration file for plugging/unplugging NVMes into/from current process.
 *
 * \param cfgfile The configuration file of Libstorage. It must be accessible.
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_nvme_reload_ctrlr(const char *cfgfile);

/**
 * Low level format the NVM media.
 * This is used when the user wants to change the LBA data size and/or metadata size.
 *
 * Attention: A low level format may destroy all data and metadata associated with all namespaces
              or only the specific namespace associated with the command (refer to the Format NVM
              Attributes field in the Identify Controller data structure). After the Format NVM command
              successfully completes, the controller shall not return any user data that was previously
              contained in an affected namespace
 *
 * \param ctrlName The name of the specified nvme.
 * \param lbaf The LBA format to apply to the NVM media.
 * \param piType Specifies whether end-to-end data protection is enabled and the type of protection information.
 * \param pil_start Protection information is transferred as the first or the last eight bytes of metadata
 * \param ms_extented The metadata is transferred as part of an extended data LBA or not
 * \param ses Not used in current.
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int8_t libstorage_low_level_format_nvm(const char *ctrlName, uint8_t lbaf,
                                       enum libstorage_ns_pi_type piType,
                                       bool pil_start, bool ms_extented, uint8_t ses);

/**
 * Callback function prototype.
 *
 * \param cb_status The result of the operation. 0 if operation is successful, a negative integer
 *        if an error occured in software system, a positive integer if an error occured in NVM system.
 * \param sct_code A status code type. It is 0 if 'cb_status' is Less than or equal to 0,
 *        If an error occured in NVM system, this field indicate a status code type.
 * \param cb_arg The argument of Callback function. It is provided by the caller.
 * \return No return
 */
typedef void (*LIBSTORAGE_CALLBACK_FUNC)(int32_t cb_status, int32_t sct_code, void *cb_arg);

/**
 * Notice the NVM subsystem to deallocate all provided ranges.
 *
 * \param fd Block device descriptor to deallocate.
 * \param range All provided ranges
 * \param range_count The count of range array.
 * \param cb param Callback function.
 * \param cb_arg The argument of Callback function. It is provided by the caller
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_deallocate_block(int32_t fd, struct libstorage_dsm_range_desc *range, uint16_t range_count,
                                    LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg);

/**
 * Write hard disk asynchronously.
 *
 * \param fd Block device descriptor to write.
 * \param buf Data buffer address for writing.
              It must contain the size of metadata when metadata is transferred as part of the LBA.
 * \param nbytes Bytes of written data, only the size of the data,
                 not contain the size of metadata, align by sector size.
 * \param offset The offset, in bytes, from the start of the block device, align by sector size.
 * \param md_buf Metadata buffer address
 * \param md_len The length of metadata.
 * \param dif_flag End-to-end protection flag
 * \param cb param Callback function.
 * \param cb_arg The argument of Callback function. It is provided by the caller
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_async_write(int32_t fd, void *buf, size_t nbytes, uint64_t offset, void *md_buf, size_t md_len,
                               enum libstorage_crc_and_prchk dif_flag,
                               LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg);

/**
 * Read hard disk asynchronously.
 *
 * \param fd Block device descriptor to read.
 * \param buf Data buffer address to read into.
              It must contain the size of metadata when metadata is transferred as part of the LBA.
 * \param nbytes Bytes of read data, only the size of the data, not contain the size of metadata, align by sector size.
 * \param offset The offset, in bytes, align by sector size, from the start of the block device.
 * \param md_buf Metadata buffer address
 * \param md_len The length of metadata.
 * \param dif_flag End-to-end protection flag
 * \param cb param Callback function.
 * \param cb_arg The argument of Callback function. It is provided by the caller
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_async_read(int32_t fd, void *buf, size_t nbytes, uint64_t offset, void *md_buf, size_t md_len,
                              enum libstorage_crc_and_prchk dif_flag, LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg);

/**
 * Write hard disk asynchronously.
 *
 * \param fd Block device descriptor to write.
 * \param iov A scatter gather list of buffers to be written from. iov->iov_len contains the size of metadata.
 * \param iovcnt The number of elements in iov.
 * \param nbytes Bytes of written data, only the size of the data,
                 not contain the size of metadata, align by sector size.
 * \param offset The offset, in bytes, from the start of the block device, align by sector size.
 * \param md_buf Metadata buffer address, the metadata is transferred as part of a separate buffer.
 * \param md_len The length of metadata.
 * \param dif_flag End-to-end protection flag
 * \param cb param Callback function.
 * \param cb_arg The argument of Callback function. It is provided by the caller
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_async_writev(int32_t fd, struct iovec *iov, int iovcnt, size_t nbytes, uint64_t offset,
                                void *md_buf, size_t md_len, enum libstorage_crc_and_prchk dif_flag,
                                LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg);
/**
 * Read hard disk asynchronously.
 *
 * \param fd Block device descriptor to read.
 * \param iov A scatter gather list of buffers to be read into.  iov->iov_len contains the size of metadata.
 * \param iovcnt The number of elements in iov.
 * \param nbytes Bytes of read data, only the size of the data, not contain the size of metadata, align by sector size.
 * \param offset The offset, in bytes, from the start of the block device, align by sector size.
 * \param md_buf Metadata buffer address, the metadata is transferred as part of a separate buffer.
 * \param md_len The length of metadata.
 * \param dif_flag End-to-end protection flag
 * \param cb param Callback function.
 * \param cb_arg The argument of Callback function. It is provided by the caller
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_async_readv(int32_t fd, struct iovec *iov, int iovcnt, size_t nbytes, uint64_t offset, void *md_buf,
                               size_t md_len,
                               enum libstorage_crc_and_prchk dif_flag, LIBSTORAGE_CALLBACK_FUNC cb, void *cb_arg);
/**
 * Read hard disk synchronously.
 *
 * \param fd Block device descriptor to read.
 * \param buf Data buffer address to read into
 * \param nbytes Bytes of buffer, align by sector size.
 * \param offset The offset, in bytes, align by sector size, from the start of the block device.
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_sync_read(int fd, void *buf, size_t nbytes, off_t offset);

/**
 * Write hard disk synchronously.
 *
 * \param fd Block device descriptor to write.
 * \param buf Data buffer address for writing
 * \param nbytes Bytes of buffer, align by sector size.
 * \param offset The offset, in bytes, from the start of the block device.
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_sync_write(int fd, const void *buf, size_t nbytes, off_t offset);

/**
 * Open a block device for I/O operations.
 *
 * \param devname Block device name to open.(e.g nvme0n1)
 * \return the new block device descriptor, a nonnegative integer if operation is successful or -1 if an error occurred
 */
int32_t libstorage_open(const char *devfullname);

/**
 * Close a previously opened block device.
 *
 * \param fd Block device descriptor to close
 * \return 0 if operation is successful or -1 if an error occurred
 */
int32_t libstorage_close(int32_t fd);

/**
 * Allocates memory from the huge-page area of memory. The memory is not cleared.
 *
 * \param size Size(In bytes) to be allocated.
 * \param align If 0, the return is a pointer that is suitably aligned fo any kind of variable.
 *        Otherwise, the return is a pointer that is a multiple of 'align'. In this case, it must
 *        be a power of two.(Mininum alignment is the cacheline size, i.e. 64-bytes.)
 * \return NULL on error. Not enough memory, or invalid arguments(size is 0, align is not a power of two).
 *         Otherwise, return the pointer that point to the allocated object.
 */
void *libstorage_mem_reserve(size_t size, size_t align);

/**
 * Free the memory space pointed to by the provided pointer.
 * If the pointer is NULL, the function does nothing.

 * \param ptr The pointer to memory to be freed.
 */
void libstorage_mem_free(void *ptr);

/**
 * Allocates memory from the buffer pool that is created by Libstorage.
 *
 * \param nbytes Size(In bytes) to be allocated. It can't be lagger than 64k-bytes.
 * \return NULL on error. Not enough memory, or invalid arguments(nbytes is 0 or lagger than 64k-bytes).
 *         Otherwise, return the pointer that point to the allocated object.
 */
void *libstorage_alloc_io_buf(size_t nbytes);

/**
 * Free the memory space pointed to by the provided pointer.
 *
 * \param buf The pointer to memory to be freed.
 * \param nbytes Size of buf
 * \return 0 if operation is successful or -1 if an error occurred
 */
int32_t libstorage_free_io_buf(void *buf, size_t nbytes);

/**
 * The initialization function of Libstorage. It must be called before using Libstorage.
 * Only one call is allowed in a process.
 *
 * \param cfgfile The configuration file of Libstorage. It must be accessible.
 * \return 0 if operation is successful, suitable errno value otherwise.
 */
int32_t libstorage_init_module(const char *cfgfile);

/**
 * The exit function of Libstorage. It may be called when the system exits.
 * Libstorage is not allowed to be used after calling this function.
 *
 * \return 0 if operation is successful, suitable errno value otherwise
 */
int32_t libstorage_exit_module(void);

#endif /* endif LIBSTORAGE_BDEV_RW_H */
