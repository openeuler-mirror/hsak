/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: head file of rw cli
* Author: zhoupengchen
* Create: 2018-10-10
*/

#ifndef UBLOCK_CLI_RW_H_
#define UBLOCK_CLI_RW_H_

#include <stdint.h>
#include <getopt.h>

#define NUM_MAX_NVMES 64

#define SPDK_TRADDR_MAX_LEN 256

const char *g_short_options = "s:c:z:n:d:lfvwth";

struct option g_long_options[] = {
    { "start-block", required_argument, NULL, 's' },
    { "block-count", required_argument, NULL, 'c' },
    { "data-size", required_argument, NULL, 'z' },
    { "namespace-id", required_argument, NULL, 'n' },
    { "data", required_argument, NULL, 'd' },
    { "limited-retry", no_argument, NULL, 'l' },
    { "force-unit-access", no_argument, NULL, 'f' },
    { "show-command", no_argument, NULL, 'v' },
    { "dry-run", no_argument, NULL, 'w' },
    { "latency", no_argument, NULL, 't' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 },
};

enum spdk_rw {
    SPDK_RW_PRINFO_PRCHK_REF = 1U << 26, /* left shift 26 bits */
    SPDK_RW_PRINFO_PRCHK_APP = 1U << 27, /* left shift 27 bits */
    SPDK_RW_PRINFO_PRCHK_GUARD = 1U << 28, /* left shift 28 bits */
    SPDK_RW_PRINFO_PRACT = 1U << 29, /* left shift 29 bits */
    SPDK_RW_FUA = 1U << 30, /* left shift 30 bits */
    SPDK_RW_LR = 1U << 31, /* left shift 31 bits */
};

struct ublock_rw_nvme_cmdline_io {
    uint16_t apptag;
    uint16_t appmask;
    uint32_t control;
    uint64_t nblocks;
    uint64_t metadata;
    char *addr;
    uint64_t addr_size;
    uint64_t slba;
    uint32_t dsmgmt;
    uint32_t reftag;
    uint8_t opcode;
    uint8_t flags;
};

struct ublock_rw_cmdline_config {
    uint64_t start_block_cfg;
    uint64_t block_count_cfg;
    uint64_t data_size_cfg;
    uint32_t namespace_id_cfg;
    uint32_t ref_tag_cfg;
    char *data_cfg;
    char *metadata_cfg;
    int limited_retry_cfg;
    int force_unit_access_cfg;
    int show_cfg;
    int dry_run_cfg;
    int latency_cfg;
    uint8_t prinfo_cfg;
    uint8_t app_tag_mask_cfg;
    uint16_t app_tag_cfg;
    uint8_t opcode_cmd_cfg;
};

struct ublock_rw_cmdline_config cmd_cfg = {
    .start_block_cfg = 0,
    .block_count_cfg = 0,
    .data_size_cfg = 0,
    .namespace_id_cfg = 1,
    .ref_tag_cfg = 0,
    .data_cfg = "",
    .metadata_cfg = "",
    .prinfo_cfg = 0,
    .app_tag_mask_cfg = 0,
    .app_tag_cfg = 0,
    .opcode_cmd_cfg = 0,
};

struct ublock_rw_spdk_nvme_dev {
    struct spdk_nvme_ctrlr *ctrlr;
    struct spdk_nvme_qpair *io_qpair;
    int fd;
    uint32_t ns_id;
    char traddr[SPDK_TRADDR_MAX_LEN + 1];
};

struct spdk_nvme_ns {
    struct spdk_nvme_ctrlr      *ctrlr;
    uint32_t            sector_size;

    /*
     * Size of data transferred as part of each block,
     * including metadata if FLBAS indicates the metadata is transferred
     * as part of the data buffer at the end of each LBA.
     */
    uint32_t            extended_lba_size;

    uint32_t            md_size;
    uint32_t            pi_type;
    uint32_t            sectors_per_max_io;
    uint32_t            sectors_per_stripe;
    uint32_t            id;
    uint16_t            flags;

    /* Namespace Identification Descriptor List (CNS = 03h) */
    uint8_t             id_desc_list[4096]; /* 4096 bytes of namespace id descriptor */
};

struct ublock_rw_read_desc {
    uint64_t nbytes;
    uint64_t read_lba;
    uint64_t payload_blocks;
    uint32_t control;
};

#endif /* ublock_cli_rw.h */
