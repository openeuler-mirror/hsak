/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: cli of rw function
* Author: zhoupengchen
* Create: 2018-10-10
*/

#include <stdio.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <getopt.h>

#include <spdk/env.h>
#include <spdk/nvme.h>
#include <spdk/log.h>
#include <securec.h>
#include "spdk/bdev_module.h"
#include "spdk/barrier.h"
#include "ublock_cli_common.h"
#include "ublock_cli_rw.h"

static struct ublock_rw_spdk_nvme_dev g_spdk_dev[NUM_MAX_NVMES] = {};
static unsigned int g_num_ctrlr = 0;
static int outstanding_commands = 0;

static bool probe_cb(void *cb_ctx,
                     const struct spdk_nvme_transport_id *trid,
                     struct spdk_nvme_ctrlr_opts *opts)
{
    return true;
}

static void attach_cb(void *cb_ctx,
                      const struct spdk_nvme_transport_id *trid,
                      struct spdk_nvme_ctrlr *ctrlr,
                      const struct spdk_nvme_ctrlr_opts *opts)
{
    if (trid == NULL || ctrlr == NULL) {
        return;
    }

    uint32_t i = 0;
    uint32_t num_ns = spdk_nvme_ctrlr_get_num_ns(ctrlr);
    struct spdk_nvme_ns *ns = NULL;
    struct spdk_nvme_qpair *io_qpair = NULL;

    io_qpair = spdk_nvme_ctrlr_alloc_io_qpair(ctrlr, NULL, 0);
    if (io_qpair == NULL) {
        printf("[libstorage-rw] fail to malloc io qpair\n");
        return;
    }

    for (i = 1; i <= num_ns; i++) {
        ns = spdk_nvme_ctrlr_get_ns(ctrlr, i);
        if (ns != NULL && spdk_nvme_ns_is_active(ns) == true) {
            if (g_num_ctrlr == NUM_MAX_NVMES) {
                printf("[libstorage-rw] no resource to manage ctrlr %s\n", trid->traddr);
                return;
            }

            g_spdk_dev[g_num_ctrlr].ctrlr = ctrlr;
            g_spdk_dev[g_num_ctrlr].fd = socket(AF_UNIX, (int)SOCK_RAW, 0);
            if (g_spdk_dev[g_num_ctrlr].fd < 0) {
                printf("[libstorage-rw] fail to create socket file\n");
                exit(EXIT_FAILURE);
            }
            g_spdk_dev[g_num_ctrlr].io_qpair = io_qpair;
            g_spdk_dev[g_num_ctrlr].ns_id = i;
            if (snprintf_s(g_spdk_dev[g_num_ctrlr].traddr,
                           sizeof(g_spdk_dev[g_num_ctrlr].traddr),
                           sizeof(trid->traddr) - 1,
                           "%s",
                           trid->traddr) < 0) {
                printf("[libstorage-rw] snprintf failed!\n");
                exit(EXIT_FAILURE);
            }
            g_num_ctrlr++;
        }
    }
}

static void ublock_rw_init(const char *pci)
{
    int ret;
    struct spdk_env_opts env_opts = {0x0};

    /* spdk env init */
    spdk_env_opts_init(&env_opts);
    env_opts.name = "LibStorage-rw";
    env_opts.mem_size = 300; /* init 300 MB memory in DPDK */
    env_opts.shm_id = -1;
    env_opts.core_mask = "0x01";
    if (spdk_env_init(&env_opts) < 0) {
        SPDK_ERRLOG("Failed to initialize SPDK env\n");
        exit(EXIT_FAILURE);
    }

    if (pci == NULL) {
        /* probe all NVMe device ctrlrs and init g_spdk_dev */
        ret = spdk_nvme_probe(NULL, NULL, probe_cb, attach_cb, NULL);
        if (ret != 0 || g_num_ctrlr == 0) {
            SPDK_ERRLOG("Failed to probe pci, error code:%d, number of ctrlr %d\n",
                        ret,
                        g_num_ctrlr);
            exit(EXIT_FAILURE);
        }
    } else {
        /* probe the specific nvme device used by `libstorage-rw' cmd */
        struct spdk_pci_addr pci_addr;
        struct spdk_nvme_transport_id trid = {0x0};

        if (spdk_pci_addr_parse(&pci_addr, pci)) {
            SPDK_ERRLOG("Could not parse pci address\n");
            exit(EXIT_FAILURE);
        }
        trid.trtype = SPDK_NVME_TRANSPORT_PCIE;
        (void)spdk_pci_addr_fmt(trid.traddr, sizeof(trid.traddr), &pci_addr);

        ret = spdk_nvme_probe(&trid, NULL, probe_cb, attach_cb, NULL);
        if (ret != 0 || g_num_ctrlr == 0) {
            SPDK_ERRLOG("Failed to probe pci, error code:%d, number of ctrlr %d\n",
                        ret,
                        g_num_ctrlr);
            exit(EXIT_FAILURE);
        }
    }
}

static void ublock_rw_fini(void)
{
    unsigned int i = 0;
    struct spdk_nvme_ctrlr *ctrlr = NULL;

    for (i = 0; i < g_num_ctrlr; i++) {
        if (g_spdk_dev[i].ctrlr && ctrlr != g_spdk_dev[i].ctrlr) {
            (void)spdk_nvme_ctrlr_free_io_qpair(g_spdk_dev[i].io_qpair);
            (void)spdk_nvme_detach_ublock(g_spdk_dev[i].ctrlr);
        }

        close(g_spdk_dev[i].fd);

        /* multi-namespaces might have the same ctlr */
        ctrlr = g_spdk_dev[i].ctrlr;
    }

    /* all g_spdk_dev element has been freed, */
    /* cleanup counter of g_spdk_dev */
    g_num_ctrlr = 0;
}

static inline int ublock_rw_spdk_get_error_code(const struct spdk_nvme_cpl *cpl)
{
    if (cpl == NULL) {
        /* unknown error code */
        return 0xfff;
    }

    return (cpl->status.sct << 8) | cpl->status.sc; /* left shift 8 bits for error code calculate */
}

static const struct ublock_rw_spdk_nvme_dev *ublock_rw_spdk_get_nvme_dev(int fd)
{
    for (unsigned int i = 0; i < g_num_ctrlr; i++) {
        if (g_spdk_dev[i].fd == fd) {
            return &g_spdk_dev[i];
        }
    }

    return NULL;
}

static uint32_t ublock_rw_spdk_get_nsid(int fd)
{
    const struct ublock_rw_spdk_nvme_dev *dev = ublock_rw_spdk_get_nvme_dev(fd);
    if (dev != NULL) {
        return dev->ns_id;
    }

    return 0;
}

static struct spdk_nvme_ctrlr *ublock_rw_spdk_get_ctrlr_by_fd(int fd)
{
    const struct ublock_rw_spdk_nvme_dev *dev = ublock_rw_spdk_get_nvme_dev(fd);
    if (dev != NULL) {
        return dev->ctrlr;
    }

    return NULL;
}

static uint64_t ublock_rw_spdk_get_num_sectors_by_fd(int fd)
{
    uint32_t ns_id = ublock_rw_spdk_get_nsid(fd);
    struct spdk_nvme_ctrlr *ctrlr = ublock_rw_spdk_get_ctrlr_by_fd(fd);
    if (ctrlr == NULL) {
        return 0;
    }
    struct spdk_nvme_ns *ns = spdk_nvme_ctrlr_get_ns(ctrlr, ns_id);
    if (ns == NULL) {
        return 0;
    }
    const struct spdk_nvme_ns_data *nsdata = spdk_nvme_ns_get_data(ns);
    if (nsdata == NULL) {
        return 0;
    }

    return nsdata->nsze;
}

static void ublock_rw_spdk_io_completion(void *cb_arg, const struct spdk_nvme_cpl *cpl)
{
    int* status = NULL;
    struct spdk_bdev_io *bdevIo = NULL;

    if (cb_arg == NULL || cpl == NULL) {
        /* already got error, so we think I/O is finished */
        outstanding_commands--;
        return;
    }

    bdevIo = spdk_bdev_io_from_ctx(cb_arg);
    status = (int*)bdevIo->internal.caller_ctx;
    *status = 0;

    if (spdk_nvme_cpl_is_error(cpl)) {
        printf("command error: SC %x SCT %x\n", cpl->status.sc, cpl->status.sct);
        *status = ublock_rw_spdk_get_error_code(cpl);
    }

    spdk_mb();
    outstanding_commands--;
}

static void ublock_rw_spdk_ns_sector_size(unsigned int fd, uint32_t *sector_size)
{
    sleep(5); /* sleep 5 ms */
    if (sector_size == NULL) {
        return;
    }

    uint32_t ns_id = ublock_rw_spdk_get_nsid((int)fd);

    struct spdk_nvme_ctrlr *ctrlr = ublock_rw_spdk_get_ctrlr_by_fd((int)fd);
    if (ctrlr == NULL) {
        printf("fail to get ctrlr\n");
        return;
    }

    struct spdk_nvme_ns *ns = spdk_nvme_ctrlr_get_ns(ctrlr, ns_id);

    if (ns == NULL) {
        printf("fail to get namespace\n");
        return;
    }

    /* sector_size is (512 + 8)B/(4096 + 64)B or (512 + 0)B or (4096 + 0)B */
    *sector_size = ns->extended_lba_size;
    printf("[TEST_CODE] ns=%p\n", ns);
    printf("[TEST_CODE] ns_id=%u\n", ns_id);
    printf("[TEST_CODE] extended=%u\n", ns->extended_lba_size);
    printf("[TEST_CODE] md=%u\n", ns->md_size);
    printf("[TEST_CODE] ss=%u\n", ns->sector_size);
    printf("[TEST_CODE] per_max_io%u\n", ns->sectors_per_max_io);
    const struct spdk_nvme_ns_data *nsdata = spdk_nvme_ns_get_data(ns);
    if (nsdata != NULL) {
        printf("[TEST_CODE] %u\n", nsdata->lbaf[nsdata->flbas.format].lbads);
        printf("[TEST_CODE] %u\n", nsdata->lbaf[nsdata->flbas.format].ms);
    }
}

static struct spdk_nvme_ns *ublock_rw_get_ns_from_bdev(const struct ublock_rw_spdk_nvme_dev *dev)
{
    struct spdk_nvme_ns *ns = NULL;

    if (dev == NULL) {
        printf("fail to get ctrlr, the nvme device is NULL\n");
        return NULL;
    }

    if (dev->ctrlr == NULL || dev->io_qpair == NULL) {
        printf("fail to get ctrlr\n");
        return NULL;
    }

    ns = spdk_nvme_ctrlr_get_ns(dev->ctrlr, dev->ns_id);
    return ns;
}

static int ublock_rw_read_single(struct ublock_rw_read_desc rw_read_desc,
                                 struct spdk_nvme_ns *ns,
                                 const struct ublock_rw_spdk_nvme_dev *dev,
                                 void **payload)
{
    int io_status = 0;
    int rc;
    struct spdk_bdev_io bdevIo;

    *payload = spdk_dma_zmalloc(rw_read_desc.nbytes, 0, NULL);
    if (*payload == NULL) {
        return ENOMEM;
    }

    outstanding_commands = 1;
    bdevIo.internal.caller_ctx = (void*)&io_status;
    rc = spdk_nvme_ns_cmd_read(ns, dev->io_qpair, *payload, rw_read_desc.read_lba, rw_read_desc.payload_blocks,
                               ublock_rw_spdk_io_completion, bdevIo.driver_ctx, rw_read_desc.control);
    if (rc != 0) {
        return rc;
    }

    /* wait for sync finishing I/O */
    while (outstanding_commands != 0) {
        (void)spdk_nvme_qpair_process_completions(dev->io_qpair, 0);
    }

    return io_status;
}

static int ublock_rw_read(int fd, const struct ublock_rw_nvme_cmdline_io *io, int dev_fd)
{
    int rc = 0;
    int io_status;
    uint64_t read_lba;
    uint32_t sector_size;
    uint64_t buffer_remaining;
    uint64_t write_remaining;
    uint64_t write_size = 0;
    uint64_t payload_blocks;
    uint64_t nbytes = 0;
    void *payload = NULL;
    struct spdk_nvme_ns *ns = NULL;
    const struct ublock_rw_spdk_nvme_dev *dev = NULL;
    struct ublock_rw_read_desc rw_read_desc = {};

    dev = ublock_rw_spdk_get_nvme_dev(fd);
    ns = ublock_rw_get_ns_from_bdev(dev);
    if (ns == NULL) {
        printf("fail to get namespace\n");
        return -1;
    }
    /* sector_size is (512 + 8)B/(4096 + 64)B or (512 + 0)B or (4096 + 0)B */
    sector_size = ns->extended_lba_size;
    payload_blocks = ns->sectors_per_max_io;

    buffer_remaining = (io->addr_size - 1) / sector_size + 1;
    read_lba = io->slba;
    write_remaining = io->addr_size;

    while (buffer_remaining > 0) {
        if (buffer_remaining < payload_blocks) {
            payload_blocks = buffer_remaining;
        }

        nbytes = payload_blocks * sector_size;

        rw_read_desc.nbytes = nbytes;
        rw_read_desc.read_lba = read_lba;
        rw_read_desc.payload_blocks = payload_blocks;
        rw_read_desc.control = io->control;
        io_status = ublock_rw_read_single(rw_read_desc, ns, dev, &payload);
        if (io_status != 0) {
            rc = io_status;
            goto exit;
        }

        read_lba += payload_blocks;
        buffer_remaining -= payload_blocks;

        if (write_remaining > nbytes) {
            write_remaining -= nbytes;
            write_size = nbytes;
        } else {
            write_size = write_remaining;
        }

        /* NVMe spdk read cmd success, write it into file */
        if (write(dev_fd, (void *)payload, write_size) < 0) {
            printf("fail to write file: %s\n", strerror(errno));
            rc = -1;
            goto exit;
        }

        spdk_dma_free(payload);
        payload = NULL;
    }

exit:
    spdk_dma_free(payload);
    return rc;
}

static int ublock_rw_write(int fd, struct ublock_rw_nvme_cmdline_io *io, int dev_fd)
{
    int ret = 0;
    int io_status = 0;
    uint64_t write_lba;
    uint32_t sector_size;
    uint64_t buffer_remaining;
    uint64_t payload_blocks;
    uint64_t nbytes = 0;
    void *payload = NULL;
    const struct ublock_rw_spdk_nvme_dev *dev = NULL;
    struct spdk_nvme_ns *ns = NULL;
    struct spdk_bdev_io bdevIo;

    dev = ublock_rw_spdk_get_nvme_dev(fd);
    ns = ublock_rw_get_ns_from_bdev(dev);
    if (ns == NULL) {
        printf("fail to get namespace\n");
        return -1;
    }
    /* sector_size is (512 + 8)B/(4096 + 64)B or (512 + 0)B or (4096 + 0)B */
    sector_size = ns->extended_lba_size;
    payload_blocks = ns->sectors_per_max_io;

    buffer_remaining = (io->addr_size - 1) / sector_size + 1;
    write_lba = io->slba;

    while (buffer_remaining > 0) {
        if (buffer_remaining < payload_blocks) {
            payload_blocks = buffer_remaining;
        }

        nbytes = payload_blocks * sector_size;
        payload = spdk_dma_zmalloc(nbytes, 0, NULL);
        if (payload == NULL) {
            ret = ENOMEM;
            goto exit;
        }

        if (read(dev_fd, (void *)payload, nbytes) < 0) {
            printf("fail to write file: %s\n", strerror(errno));
            ret = -1;
            goto exit;
        }

        outstanding_commands = 1;
        bdevIo.internal.caller_ctx = (void*)&io_status;
        ret = spdk_nvme_ns_cmd_write(ns, dev->io_qpair, payload, write_lba, payload_blocks,
                                     ublock_rw_spdk_io_completion, bdevIo.driver_ctx, io->control);
        if (ret != 0) {
            goto exit;
        }

        /* wait for sync finishing I/O */
        while (outstanding_commands != 0) {
            (void)spdk_nvme_qpair_process_completions(dev->io_qpair, 0);
        }

        write_lba += payload_blocks;
        buffer_remaining -= payload_blocks;
        spdk_dma_free(payload);
        payload = NULL;

        if (io_status != 0) {
            ret = io_status;
            goto exit;
        }
    }

exit:
    spdk_dma_free(payload);
    return ret;
}

static int ublock_rw_spdk_io(int fd, struct ublock_rw_nvme_cmdline_io *io, int dev_fd)
{
    if (io == NULL) {
        return -1;
    }

    int rc = 0;

    switch (io->opcode) {
        case SPDK_NVME_OPC_READ:

            rc = ublock_rw_read(fd, io, dev_fd);
            break;

        case SPDK_NVME_OPC_WRITE:
            rc = ublock_rw_write(fd, io, dev_fd);
            break;

        default:
            break;
    }

    return rc;
}

static void usage(void)
{
    printf("Usage: libstorage-rw <COMMAND> <device> [OPTIONS...]\n\n");
    printf("COMMAND:\n");
    printf(" read    Copy specified logical blocks on the given device to\n");
    printf("         specified data buffer(default data buffer is stdout).\n\n");
    printf(" write   Copy from provided data buffer to specified logical blocks\n");
    printf("          on the given device(default data buffer is stdin).\n\n");
    printf(" help    Show detail information which help to use this CLI.\n\n");
    printf("Options:\n");
    printf(" [ --start-block=<NUM>, -s <NUM> ]      --- 64-bit address of first logical\n");
    printf("                                            block to access (default lba is\n");
    printf("                                            0)\n");
    printf(" [ --block-count=<NUM>, -c <NUM> ]      --- number of logical blocks(zeroes\n");
    printf("                                            based) on device to access\n");
    printf("                                            (default number of lb is 0)\n");
    printf(" [ --data-size=<NUM>, -z <NUM> ]        --- size of data in bytes (must be\n");
    printf("                                            given from cmdline and suffix\n");
    printf("                                            supported)\n");
    printf(" [ --namespace-id=<NUM>, -n <NUM> ]     --- namespace id (default nsid is 1)\n");
    printf(" [ --data=<FILE>, -d <FILE> ]           --- data file to write in or read\n");
    printf("                                            from\n");
    printf(" [ --limited-retry, -l ]                --- controller apply limited retry\n");
    printf("                                            efforts.\n");
    printf(" [ --force-unit-access, -f ]            --- force device to commit data\n");
    printf("                                            before command completes\n");
    printf(" [ --show-command, -v ]                 --- show command before sending\n");
    printf(" [ --dry-run, -w ]                      --- show command instead of sending\n");
    printf(" [ --latency, -t ]                      --- output latency statistics\n");
    printf(" [ --help, -h ]                         --- show command help information\n");
    return;
}

static struct binary_cmd_suffix {
    unsigned int shift;
    const char *cmd_suffix;
} binary_cmd_suffixes[] = {
    { 50, "Pi" },
    { 40, "Ti" },
    { 30, "Gi" },
    { 20, "Mi" },
    { 10, "Ki" },
    { 0, "" }
};

static unsigned long usuffix_binary_cmd_parse(const char *value)
{
    char *u_cmd_suffix = NULL;
    errno = 0;
    unsigned long ret = strtoul(value, &u_cmd_suffix, 0);
    if (errno) {
        return 0;
    }
    if (u_cmd_suffix == NULL) {
        return 0;
    }

    /* only supported usuffix is 1K, 1k, 1KB, 1Kb, 1kB, 1kb */
    if (strlen(u_cmd_suffix) >= 3) { /* only 2 bytes suffix, for example "KB", so it should be less than 3 */
        errno = EINVAL;
        return 0;
    }

    struct binary_cmd_suffix *s = NULL;
    if (strlen(u_cmd_suffix) == 2 && tolower(u_cmd_suffix[1]) != 'b') { /* only 2 bytes suffix, check item 1 */
        errno = EINVAL;
        return 0;
    }
    for (s = binary_cmd_suffixes; s->shift != 0; s++) {
        if (tolower(u_cmd_suffix[0]) == tolower(s->cmd_suffix[0])) {
            ret <<= s->shift;
            return ret;
        }
    }

    if (u_cmd_suffix[0] != '\0') {
        errno = EINVAL;
    }

    return ret;
}

static int ublock_rw_judge_err(int err, const char *endptr)
{
    if ((bool)err || *endptr != '\0') {
        return -1;
    }

    return 0;
}

static bool ublock_rw_arg_is_negative(char first_char, const char * arg_name, const char * arg_value)
{
    if (arg_value == NULL) {
        return true;
    }

    if (first_char == '-') {
        printf("Expected non-negative unsigned long integer"
               " argument for '%s' but got '%s'!\n",
               arg_name, arg_value);
        return true;
    }
    return false;
}

static int parse_arg_s(void)
{
    if (ublock_rw_arg_is_negative(optarg[0], "start-block", optarg)) {
        return -1;
    }
    cmd_cfg.start_block_cfg = usuffix_binary_cmd_parse(optarg);
    if (errno) {
        printf("parse '%s' for start-block fail!\n", optarg);
#ifdef DEBUG
        printf("strtoul error: %s\n", strerror(errno));
#endif
        return -1;
    }
    return 0;
}

static int parse_arg_c(void)
{
    int rc;
    char *endptr = NULL;

    if (ublock_rw_arg_is_negative(optarg[0], "block-count", optarg)) {
        return -1;
    }
    cmd_cfg.block_count_cfg = strtoul(optarg, &endptr, 0);
    rc = ublock_rw_judge_err(errno, endptr);
    if (rc != 0) {
        printf("parse '%s' for block-count fail!\n", optarg);
#ifdef DEBUG
        if (errno) {
            printf("strtoul error: %s\n", strerror(errno));
        }
#endif
        return -1;
    }
    return 0;
}

static int parse_arg_z(void)
{
    if (ublock_rw_arg_is_negative(optarg[0], "data-size", optarg)) {
        return -1;
    }
    cmd_cfg.data_size_cfg = usuffix_binary_cmd_parse(optarg);
    if (errno) {
        printf("parse '%s' for data-size fail!\n", optarg);
#ifdef DEBUG
        printf("strtoul error: %s\n", strerror(errno));
#endif
        return -1;
    }
    return 0;
}

static int parse_arg_n(void)
{
    unsigned long long tmp;
    char *endptr = NULL;
    int rc;

    tmp = strtoul(optarg, &endptr, 0);
    rc = ublock_rw_judge_err(errno, endptr);
    if (rc != 0 || tmp >= (1ULL << 32)) { /* uint is 32 bits */
        printf("Expected dword argument for namespace-id but got '%s'!\n",
               optarg);
        return -1;
    }
    cmd_cfg.namespace_id_cfg = (uint32_t)tmp;
    return 0;
}

static int ublock_rw_argconfig_parse(int argc, char * const argv[])
{
    int opt;
    int rc = 0;

    for (opt = getopt_long(argc, argv, g_short_options, g_long_options, NULL); opt != -1;
         opt = getopt_long(argc, argv, g_short_options, g_long_options, NULL)) {
        errno = 0;
        switch (opt) {
            case 's':
                rc = parse_arg_s();
                break;

            case 'c':
                rc = parse_arg_c();
                break;

            case 'z':
                rc = parse_arg_z();
                break;

            case 'n':
                rc = parse_arg_n();
                break;

            case 'd':
                cmd_cfg.data_cfg = optarg;
                break;

            case 'l':
                cmd_cfg.limited_retry_cfg = 1;
                break;

            case 'f':
                cmd_cfg.force_unit_access_cfg = 1;
                break;

            case 'v':
                cmd_cfg.show_cfg = 1;
                break;

            case 'w':
                cmd_cfg.dry_run_cfg = 1;
                break;

            case 't':
                cmd_cfg.latency_cfg = 1;
                break;

            case 'h':
                usage();
                break;

            case '?':
                usage();
                rc = -1;
                break;

            default:
                break;
        }
        if (rc != 0) {
            return -EINVAL;
        }
    }
    return 0;
}

static int ublock_rw_spdk_get_fd_by_dev(const char *dev, uint32_t nsid)
{
    for (unsigned int i = 0; i < g_num_ctrlr; i++) {
        if (strcmp(g_spdk_dev[i].traddr, dev) == 0) {
            if (nsid == g_spdk_dev[i].ns_id) {
                return g_spdk_dev[i].fd;
            }
        }
    }

    printf("Cannot find the NVMe device %s whose nsid is %u\n", dev, nsid);
    return -1;
}

static int ublock_rw_parse_and_open(int argc, char * const * argv)
{
    int ret;

    if (argv == NULL) {
        return -1;
    }

    ret = ublock_rw_argconfig_parse(argc, argv);
    if (ret != 0) {
        return ret;
    }

    if (optind >= argc) {
        usage();
        errno = EINVAL;
        perror(argv[0]);
        return -EINVAL;
    }

    return ublock_rw_spdk_get_fd_by_dev(argv[optind], cmd_cfg.namespace_id_cfg);
}

static long int ublock_rw_gen_latency(struct timeval begin,
                                      struct timeval end)
{
    return ((end.tv_sec - begin.tv_sec) * 1000000 + /* 1000000 is used to calculate mircoseconds */
            (end.tv_usec - begin.tv_usec));
}

static void ublock_rw_showcommand(int fd,
                                  uint8_t opcode,
                                  uint32_t control,
                                  const void *meta_buffer,
                                  struct ublock_rw_cmdline_config cfg)
{
    struct spdk_nvme_ctrlr *ctrlr = ublock_rw_spdk_get_ctrlr_by_fd(fd);
    if (ctrlr == NULL) {
        return;
    }
    uint8_t i = 0;
    uint32_t ns_id = ublock_rw_spdk_get_nsid(fd);
    struct spdk_nvme_ns *ns = spdk_nvme_ctrlr_get_ns(ctrlr, ns_id);
    if (ns == NULL) {
        return;
    }
    const struct spdk_nvme_ns_data *nsdata = spdk_nvme_ns_get_data(ns);
    if (nsdata == NULL) {
        return;
    }

    printf("opcode            : %02x\n", opcode);
    printf("flags             : %02x\n", 0);
    printf("control           : %08x\n", control);
    printf("nblocks           : %08llu\n", (unsigned long long)cfg.block_count_cfg);
    printf("ns id             : %u\n", cfg.namespace_id_cfg);
    printf("number of ns      : %u\n", spdk_nvme_ctrlr_get_num_ns(ctrlr));
    printf("metadata          : %" PRIu64 "\n", (uint64_t)(uintptr_t)meta_buffer);
    printf("addr              : %s\n", strlen(cfg.data_cfg) > 0 ? cfg.data_cfg : "STDIO");
    printf("data size         : %08llu\n", (unsigned long long)cfg.data_size_cfg);
    printf("sbla              : %" PRIu64 "\n", (uint64_t)cfg.start_block_cfg);
    printf("dsmgmt            : %08x\n", 0);
    printf("reftag            : %08x\n", cfg.ref_tag_cfg);
    printf("apptag            : %04x\n", cfg.app_tag_cfg);
    printf("appmask           : %04x\n", cfg.app_tag_mask_cfg);
    printf("dry run           : %s\n", (bool)cfg.dry_run_cfg ? "true" : "false");
    printf("show              : %s\n", (bool)cfg.show_cfg ? "true" : "false");
    printf("limited retry     : %s\n", (bool)cfg.limited_retry_cfg ? "true" : "false");
    printf("force unit access : %s\n", (bool)cfg.force_unit_access_cfg ? "true" : "false");
    printf("sector size       : (%u + %u) B\n",
           spdk_nvme_ns_get_sector_size(ns),
           spdk_nvme_ns_get_md_size(ns));
    printf("capacity          : %llu GB\n",
           (long long unsigned)spdk_nvme_ns_get_size(ns) / 1024 / 1024 / 1024); /* 1024 used to convert GB */
    printf("lba utilization   : %llu\n", (long long unsigned)nsdata->ncap);
    for (i = 0; i < nsdata->nlbaf; ++i) {
        printf("lbaf[%2u]          : ms=%2u lbads=%2u rp=0x%u %s\n",
               i,
               nsdata->lbaf[i].ms,
               nsdata->lbaf[i].lbads,
               nsdata->lbaf[i].rp,
               i == nsdata->flbas.format ? "(in use)" : "");
    }
}

static int ublock_rw_submit_io_prepare(uint32_t *pcontrol, int fd)
{
    uint32_t phys_sector_size = 0;
    uint64_t buffer_size;
    uint64_t num_sectors;

    if (pcontrol == NULL) {
        return EINVAL;
    }

    /* Protection Information Field (PRINFO): */
    /* Specifies the protection information action and check field */
    /* 00: Guard field */
    /* 01: App Tag field */
    /* 02: Ref Tag field */
    /* 03: PRACT field */
    if (cmd_cfg.prinfo_cfg > 0xf) {
        return EINVAL;
    }
    *pcontrol |= ((cmd_cfg.prinfo_cfg & 0xf) << 26); /* left shift 26 bits for cmd cfg setting */
    if (cmd_cfg.limited_retry_cfg != 0) {
        *pcontrol |= (uint32_t)SPDK_RW_LR;
    }
    if (cmd_cfg.force_unit_access_cfg != 0) {
        *pcontrol |= (uint32_t)SPDK_RW_FUA;
    }

    if (cmd_cfg.data_size_cfg == 0) {
        fprintf(stdout, "data size not provided\n");
        return EINVAL;
    }

    ublock_rw_spdk_ns_sector_size((unsigned int)fd, &phys_sector_size);
    if (phys_sector_size == 0) {
        fprintf(stdout, "fail to get sector size\n");
        return EINVAL;
    }

    num_sectors = ublock_rw_spdk_get_num_sectors_by_fd(fd);
    if (num_sectors == 0) {
        fprintf(stdout, "fail to get number of sectors\n");
        return EINVAL;
    }

    if (cmd_cfg.block_count_cfg > (num_sectors - 1)) {
        fprintf(stdout, "block count out of range"
                "(the namespace nblocks capability is %llu)\n",
                (unsigned long long)num_sectors);
        return EINVAL;
    }

    /* number of blocks is zeroes based */
    buffer_size = (cmd_cfg.block_count_cfg + 1) * phys_sector_size;
    if (cmd_cfg.data_size_cfg < buffer_size) {
        /* block_count out of namespace range */
        if (cmd_cfg.start_block_cfg > (num_sectors - cmd_cfg.block_count_cfg - 1)) {
            fprintf(stdout, "block count or start block out of range"
                    "(the namespace nblocks capability is %llu)\n",
                    (unsigned long long)num_sectors);
            return EINVAL;
        }
        printf("Rounding data size to fit block count (%llu bytes)\n",
               (unsigned long long)buffer_size);
    } else {
        buffer_size = cmd_cfg.data_size_cfg;
        cmd_cfg.block_count_cfg = buffer_size / phys_sector_size;
        if (buffer_size % phys_sector_size == 0) {
            cmd_cfg.block_count_cfg -= 1;
        }
        /* data_size out of namespace range */
        if (cmd_cfg.block_count_cfg > (num_sectors - 1) ||
            cmd_cfg.start_block_cfg > (num_sectors - cmd_cfg.block_count_cfg - 1)) {
            fprintf(stdout, "data size or start block out of range"
                    "(the namespace nblocks capability is %llu)\n",
                    (unsigned long long)num_sectors);
            return EINVAL;
        }
        printf("Rounding block count to fit data size (%llu bytes)\n",
               (unsigned long long)(cmd_cfg.block_count_cfg + 1) * phys_sector_size);
    }

    return 0;
}

static int ublock_rw_submit_io(uint8_t opcode,
                               int argc,
                               char * const * argv)
{
    int err;
    int dev_fd = -1; /* file descriptor of I/O data buffer */
    int fd = -1; /* file descriptor of I/O cmdline file */
    uint32_t control = 0;
    int flags = -1; /* flags for open dev default */
    int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    struct ublock_rw_nvme_cmdline_io io;
    struct timeval begin;
    struct timeval end;
    char *command = (bool)(opcode & 1) ? "write" : "read";

    if ((bool)(opcode & 1)) {
        flags = O_RDONLY;
        dev_fd = STDIN_FILENO; /* write from standard input or output by default */
    } else {
        flags = O_WRONLY | O_CREAT;
        dev_fd = STDOUT_FILENO; /* read from standard input or output by default */
    }

    fd = ublock_rw_parse_and_open(argc,
                                  argv);
    if (fd < 0) {
        return fd;
    }

    err = ublock_rw_submit_io_prepare(&control, fd);
    if (err != 0) {
        return err;
    }

    if (strlen(cmd_cfg.data_cfg) != 0) {
        dev_fd = open(cmd_cfg.data_cfg, flags, mode);
        if (dev_fd < 0) {
            perror(cmd_cfg.data_cfg);
            return EINVAL;
        }
    }

    if (cmd_cfg.show_cfg != 0) {
        ublock_rw_showcommand(fd, opcode, control, NULL, cmd_cfg);
    }

    if (cmd_cfg.dry_run_cfg != 0) {
        if (cmd_cfg.show_cfg == 0) {
            ublock_rw_showcommand(fd, opcode, control, NULL, cmd_cfg);
        }
        goto free_and_return;
    }

    io.flags = 0;
    io.dsmgmt = 0;
    io.opcode = opcode;
    io.control = control;
    io.nblocks = cmd_cfg.block_count_cfg;
    io.addr = cmd_cfg.data_cfg;
    io.addr_size = cmd_cfg.data_size_cfg;
    io.slba = cmd_cfg.start_block_cfg;
    io.reftag = cmd_cfg.ref_tag_cfg;
    io.appmask = cmd_cfg.app_tag_mask_cfg;
    io.apptag = cmd_cfg.app_tag_cfg;

    (void)gettimeofday(&begin, NULL);
    err = ublock_rw_spdk_io(fd, &io, dev_fd);
    (void)gettimeofday(&end, NULL);
    if (cmd_cfg.latency_cfg != 0) {
        printf("\n[I/O latency] %s: %ld us\n",
               command,
               ublock_rw_gen_latency(begin, end));
    }

    if (err < 0) {
        perror("submit-io");
    } else if (err > 0) {
        printf("\n%s: %x(%04x)\n", command, (err & 0x3ff), err);
    } else {
        printf("\n%s: Success\n", command);
    }
free_and_return:
    if (strlen(cmd_cfg.data_cfg) != 0) {
        close(dev_fd);
    }
    return err;
}

static int ublock_rw_para_need_usage(int argc, char * const argv[])
{
    if (argc < 2) { /* 2 parameters at least */
        /* libstorage-rw cli must identify <COMMAND> */
        usage();
        printf("<COMMAND> ERROR: choose an command from read/write/help\n");
        return -1;
    } else if (argc < 3) { /* 3 parameters at least */
        /* help command to show usage information */
        if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
            strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "--?") == 0) {
            usage();
            return 1; /* 1 means has executed the command here, so no need to parse parameters in main function */
        }

        /* libstorage-rw cli must identify <device> */
        usage();
        printf("<device> ERROR: identify NVMe device(ex. 0000:08:00.0)\n");
        return -1;
    }

    return 0;
}

static int ublock_rw_para_check(int argc, char * const argv[])
{
    if (argv == NULL) {
        printf("Internal Error\n");
        return -1;
    }

    if (ublock_rw_para_need_usage(argc, argv) != 0) {
        return -1;
    }

    if (strcmp(argv[1], "read") == 0) {
        cmd_cfg.opcode_cmd_cfg = (int)SPDK_NVME_OPC_READ;
    } else if (strcmp(argv[1], "write") == 0) {
        cmd_cfg.opcode_cmd_cfg = (int)SPDK_NVME_OPC_WRITE;
    } else {
        usage();
        printf("<COMMAND> ERROR: choose an command from read/write/help\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;

    ret = ublock_rw_para_check(argc, argv);
    if (ret != 0) {
        return (ret < 0) ? -1 : 0;
    }

    /* I/O command */
    if (ublock_str_is_nvme_pci_addr(argv[2])) { /* 2 is get the second parameter */
        ublock_rw_init(argv[2]); /* 2 is get the second parameter */
        ret = ublock_rw_submit_io(cmd_cfg.opcode_cmd_cfg,
                                  argc - 1,
                                  &argv[1]);
        goto EXIT;
    }
    usage();
    printf("<device> ERROR: '%s' is not a correct NVMe device"
           "(ex. 0000:08:00.0)\n",
           argv[2]);  /* 2 is get the second parameter */
    ret = -2; /* -2 means the inputted device is not a correct NVMe device */

EXIT:
    ublock_rw_fini();
    return ret;
}
