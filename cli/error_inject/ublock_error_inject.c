/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: error injection
* Author: louhongxiang
* Create: 2018-10-12
*/

#include <getopt.h>
#include <regex.h>
#include <spdk/env.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "ublock.h"
#include "ublock_internal.h"
#include "ublock_cli_common.h"

#define UBLOCK_DEVICE_NAME_MAX_LEN 64
#define UBLOCK_ERR_INJC_NOT_SET 0

#define UBLOCK_CLIENT_ERROR_INJECT_SMART "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"smart_error_inject\",\"params\":{\"pci\":\"%s\",\"type\":%d,\"per_used\":%u,\
\"shutdowns\":%lu,\"media_errors\":%lu}}"

#define UBLOCK_CLIENT_ERROR_INJECT_RET_CODE "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"error_injc_code\",\"params\":{\"devname\":\"%s\",\"type\":%d,\"flag\":%d}}"

#define UBLOCK_CLIENT_ERROR_INJECT_IO_SLOW "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"error_injc_slowio\",\"params\":{\"devname\":\"%s\",\"type\":%d,\"flag\":%d,\"io_delay_us\":%u,\
\"lba_start\":%lu,\"lba_end\":%lu,\"count\":%u}}"

#define UBLOCK_CLIENT_ERROR_INJECT_IO_PROC "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"error_injc_io_proc\",\"params\":{\"devname\":\"%s\",\"type\":%d,\"flag\":%d,\"lba_start\":%lu,\"lba_end\":%lu}}"

#define UBLOCK_CLIENT_ERROR_INJECT_ERROR_STATUS "{\"jsonrpc\":\"2.0\",\"id\": 1,\"method\":\
\"error_injc_error_status\",\"params\":{\"devname\":\"%s\",\"type\":%d,\"flag\":%d,\"sc\":%u,\"sct\":%u,\
\"lba_start\":%lu,\"lba_end\":%lu}}"


#define UBLOCK_CLIENT_ERROR_CMD_MAX_LEN 512

static bool g_type_spec_flag = false;
static bool g_shut_down_flag = false;
static bool g_media_error_flag = false;

static int g_sc_sct_count = 0;

struct err_injc_args {
    char *devname;
    int err_type;
    int percentage_used;
    int flag_per_used;
    int32_t flag;
    uint32_t io_delay_us;
    uint64_t lba_start;
    uint64_t lba_end;
    int flag_lba_spec;
    uint32_t slowio_count;
    uint32_t sc;
    uint32_t sct;
    uint64_t unsafe_shutdowns;
    uint64_t media_errors;
};

/* to distinguish type of error injection to libstorage */
enum ublock_err_injc_kind_to_libstorage {
    /* slow io error */
    ERR_TYPE_SLOW_IO = 0,
    /* io timeout */
    ERR_TYPE_IO_TIMEOUT = 1,
    /* UNC error */
    ERR_TYPE_UNC_ERROR = 2,
    /* readonly error */
    ERR_TYPE_READONLY = 3,
    /* error of percentage used is full */
    ERR_TYPE_PERCENTAGE = 4,
    /* error of temperature is beyond threshold */
    ERR_TYPE_TEMPERATURE = 5,
    /* error of nvme disk has low available spare */
    ERR_TYPE_SPARE_LOW = 6,
    /* error of volatile memory backup device has failed */
    ERR_TYPE_VOLATILE_MEM = 7,
    /* error of media has significant error */
    ERR_TYPE_MEDIA_FATAL_ERR = 8,
    /* read crc error */
    ERR_TYPE_READ_CRC = 9,
    /* read lba error */
    ERR_TYPE_READ_LBA = 10,
    /* write crc error */
    ERR_TYPE_WRITE_CRC = 11,
    /* clean error of smart information */
    ERR_TYPE_CLEANUP_SMART_ERR = 12,
    /* nvme error status code */
    ERR_TYPE_ERROR_STATUS = 13,
    /* modify unsafe shutdown counts in smart info */
    ERR_TYPE_MODIFY_UNSAFE_CNT = 14,
    /* modify media and date integrity errors counts in smart info */
    ERR_TYPE_MODIFY_MEDIA_ERR_CNT = 15
};

/* meaning of the value stands for flag */
enum ublock_err_injc_flag_value {
    ERR_INJC_FLAG_DISABLE_ALL = 0,
    ERR_INJC_FLAG_ENABLE = 1,
    ERR_INJC_FLAG_DISABLE_ONE_ITEM = 2,
    ERR_INJC_FLAG_ENABLE_FOR_COV_UNC = 3
};

/* print help information and exit */
static void usage(char *opt)
{
    printf("\nUsage:  %s -d <device> -t <error_types> [parameters...]\n", opt);
    printf("        %s -help/--help    print help information.\n\n", opt);
    printf("-d      device. The '<device>' should be pci address or namespace id.\n");
    printf("        pci address : should be given when inject error into smart information\n");
    printf("                      e.g. 0000:08:00.0\n");
    printf("        namespace id: should be given when inject error into io path.\n");
    printf("                      e.g. nvme0n1\n");
    printf("-t      types of errors wants to inject, integer ONLY!!\n");
    printf("        0  -simulate slow io pass through\n");
    printf("            make io delayed for a period of time. after injecting this error, read \n");
    printf("            or write will be delayed for n us, n is specied by -u option with an \n");
    printf("            integer. lba range and count of io to delay are needed to provide also\n");
    printf("        1  -error of timeout\n");
    printf("            after enable this error injection, every io read or write will return a \n");
    printf("            status code that means timeout\n");
    printf("        2  -error of UNC\n");
    printf("            a.  uncorrectable UNC error. enabled by -f 1 option\n");
    printf("                act like correctable UNC error is injected, but the error will no be \n");
    printf("                cleaned after a write operation is performed. this error is cleaned \n");
    printf("                by option '-f 0'\n");
    printf("            b.  correctable UNC error. enabled by -f 3 option\n");
    printf("                mark a range of logical blocks as invalid. when the specified logical\n");
    printf("                block(s) are read after this operation, a failure is returned with \n");
    printf("                Unrecovered Read Error status. after a write operation is performed \n");
    printf("                on those logical blocks, the error is cleaned\n");
    printf("        3  -error of readonly\n");
    printf("            inject an error that means the media has been placed in read only mode\n");
    printf("        4  -error of percentage used is full\n");
    printf("            configurate percentage_used field of smart information with the value \n");
    printf("            that specified by -p option.So that -p option must be provided when \n");
    printf("            the type of error injection is 4.\n");
    printf("        5  -error of temperature is beyond threshold\n");
    printf("            inject an error that tmperature is above an over temperature threshold \n");
    printf("            or below an ender temperature threshold\n");
    printf("        6  -error of nvme disk has low available spare\n");
    printf("            inject an error that available spare space of the nvme disk specified \n");
    printf("            has fallen below the threshold\n");
    printf("        7  -error of volatile memory backup device has failed\n");
    printf("            inject an error that volatile memory backup device has failed\n");
    printf("        8  -error of media has significant error\n");
    printf("            inject an error that means nvme disk reliability has been degraded due \n");
    printf("            to significant media related errors or any internal error that degrades \n");
    printf("            nvme disk reliability\n");
    printf("        9  -error of read CRC check error\n");
    printf("            specify one or several lba ranges to inject this error, and read operation\n");
    printf("            in these lba ranges will get a return status means read CRC check error.\n");
    printf("        10 -error of read LBA check error\n");
    printf("            specify one or several lba ranges to inject this error, and read operation\n");
    printf("            in these lba ranges will get a return status means read LBA check error.\n");
    printf("        11 -error of write CRC check error\n");
    printf("            specify one or several lba ranges to inject this error, and write operation\n");
    printf("            in these lba ranges will get a return status means write LBA check error.\n");
    printf("        12 -clean error of smart information\n");
    printf("            clean all errors injected into smart information before by option -t (3~8 \n");
    printf("            and 14~16) specified\n");
    printf("        13 -error code returned by nvme\n");
    printf("            specify sc(--sc option) and sct(--sct option) returned by nvme, and a lba \n");
    printf("            range is needed\n");
    printf("        14 -modify unsafe shutdown counts in smart info\n");
    printf("            modify the value of unsafe_shutdowns field which is in smart info to be the \n");
    printf("            value follows option '--shutdown'\n");
    printf("        15 -modify media and date integrity errors counts in smart info\n");
    printf("            modify the value of media_and_data_integrity_errors field which is in smart \n");
    printf("            info to be the value follows option '--media_error'\n");
    printf("-c      count of io to delay when error injection of slow io is injected.\n");
    printf("-p      percentage_used in smart information that needed to provide when type of \n");
    printf("        error is 4. if the parameter is 0, then clean this error.\n");
    printf("-f      flag of operation when lba ranges is specified\n");
    printf("        0  -disable error. when error relates to lba range, it also clean all lba ranges\n");
    printf("        1  -enable error. when error relates to lba range, then a range of lba is needed\n");
    printf("            to provide\n");
    printf("        2  -clean THE lba range that specified, only works when error relates to lba\n");
    printf("        3  -inject recoverable UNC error, it only works when type of error is 2\n");
    printf("        if type of error is 2 and UNC error is recoverable, flag 0 or 2 will not work\n");
    printf("-s      start of lba range, when a lba range is specified. integer ONLY!\n");
    printf("-e      end of lba range, when a lba range is specified. integer ONLY!\n");
    printf("-u      time to delay when injecting slow io error, integer ONLY for microsecond(us)\n");
    printf("--sc    sc value when error type is 13 to inject nvme status error\n");
    printf("--sct   sct value when error type is 13 to inject nvme status error\n");
    printf("--shutdown      specify the value of unsafe_shutdown field in smart info\n");
    printf("--media_error   specify the value of media_and_data_integrity_errors field in smart info\n\n");
}

static plog_server_sh *ublock_get_rpc_shm_map(void)
{
    int shm_fd = -1;
    plog_server_sh *plg_map = NULL;
    char *ublock_shm_file = UBLOCK_RPC_SHM_FILE_NAME;
    shm_fd = shm_open(ublock_shm_file, O_RDWR, 0600); /* 0600 is the file access type */
    if (shm_fd < 0) {
        printf("shm_open %s failed!\n", ublock_shm_file);
        return NULL;
    }

    plg_map = (plog_server_sh *)mmap(NULL,
                                     sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM,
                                     PROT_READ,
                                     MAP_SHARED,
                                     shm_fd,
                                     0);
    if (plg_map == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        close(shm_fd);
        return NULL;
    }
    close(shm_fd);
    return plg_map;
}

static char *ublock_get_pci_by_ctrlr_name(char *ctrlr_name)
{
    if (ctrlr_name == NULL) {
        printf("invalid parameters!\n");
        return NULL;
    }

    int i;
    int rc = 0;
    char *pci_ret = NULL;
    plog_server_sh *plg_map = NULL;

    plg_map = ublock_get_rpc_shm_map();
    if (plg_map == NULL) {
        return NULL;
    }

    for (i = 0; i < UBLOCK_PLG_DEVICE_MAX_NUM; i++) {
        if (strlen(plg_map[i].ctrlr_name) == 0) {
            continue;
        }
        if (strcmp(plg_map[i].ctrlr_name, ctrlr_name) != 0) {
            continue;
        }
        if (strlen(plg_map[i].pci) > 0 && strlen(plg_map[i].pci) < UBLOCK_PCI_ADDR_MAX_LEN) {
            pci_ret = (char *)malloc(strlen(plg_map[i].pci) + 1);
            if (pci_ret == NULL) {
                printf("fail to malloc sockect address of LibStorage to get\n");
                (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
                return NULL;
            }
            rc = strcpy_s(pci_ret,
                          strlen(plg_map[i].pci) + 1,
                          plg_map[i].pci);
            if (rc != 0) {
                printf("strcpy failed!\n");
                free(pci_ret);
                pci_ret = NULL;
            }
            (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
            return pci_ret;
        }
    }

    (void)munmap(plg_map, sizeof(plog_server_sh) * UBLOCK_PLG_DEVICE_MAX_NUM);
    return NULL;
}

static char *ublock_get_pci_by_devname(char *devname)
{
    char *ctrlr_name = NULL;
    char *ctrlr_name_end = NULL;
    char *pci = NULL;
    size_t ctrlr_name_len;
    int rc;

    if (devname == NULL) {
        return NULL;
    }

    if (strlen(devname) < 7 || /* length of devname is 7 bytes at least, like "nvme0n1" */
        strncasecmp(devname, "nvme", strlen("nvme")) != 0) {
        printf("device name is not in legal format\n");
        return NULL;
    }

    ctrlr_name_end = strchr((devname + 1), 'n');
    if (ctrlr_name_end == NULL) {
        printf("cannot get ctrlr name from device name\n");
        return NULL;
    }
    ctrlr_name_len = ctrlr_name_end - devname;

    ctrlr_name = (char *)malloc(sizeof(char) * UBLOCK_DEVICE_NAME_MAX_LEN);
    if (ctrlr_name == NULL) {
        printf("malloc for ctrlr name failed!\n");
        return NULL;
    }

    /* copy nvmeX from device name "nvmeXnY" */
    rc = strncpy_s(ctrlr_name, UBLOCK_DEVICE_NAME_MAX_LEN - 1, devname, ctrlr_name_len);
    if (rc != 0) {
        printf("strncpy failed!\n");
        free(ctrlr_name);
        return NULL;
    }
    pci = ublock_get_pci_by_ctrlr_name(ctrlr_name);
    if (pci == NULL) {
        printf("get pci by ctrlr name failed!\n");
    }

    free(ctrlr_name);
    return pci;
}

static int ublock_inject_get_smart_info_cmdstr(char **ppsockaddr, char **ppcmd_string,
                                               struct err_injc_args args)
{
    int rc;
    char *pci = NULL;
    char *psockaddr = NULL;
    char *pcmd_string = NULL;

    pci = args.devname;
    if (!ublock_str_is_nvme_pci_addr(pci)) {
        printf("pci address is not in valid format: %s\n", pci);
        printf("valid format should be like 0000:08:00.0\n");
        return -1;
    }

    psockaddr = (char *)malloc(sizeof(char) * strlen(UBLOCK_RPC_ADDR) + 1);
    if (psockaddr == NULL) {
        printf("malloc for socket address of ublock failed!\n");
        return -1;
    }
    rc = strncpy_s(psockaddr, strlen(UBLOCK_RPC_ADDR) + 1, UBLOCK_RPC_ADDR, strlen(UBLOCK_RPC_ADDR));
    if (rc != 0) {
        printf("strncpy failed!\n");
        free(psockaddr);
        return -1;
    }
    pcmd_string = (char *)calloc(UBLOCK_CLIENT_ERROR_CMD_MAX_LEN, sizeof(char));
    if (pcmd_string == NULL) {
        printf(" fail to calloc cmd string\n");
        free(psockaddr);
        return -1;
    }

    rc = snprintf_s(pcmd_string, UBLOCK_CLIENT_ERROR_CMD_MAX_LEN, UBLOCK_CLIENT_ERROR_CMD_MAX_LEN,
                    UBLOCK_CLIENT_ERROR_INJECT_SMART,
                    pci,
                    args.err_type,
                    args.percentage_used,
                    args.unsafe_shutdowns,
                    args.media_errors);
    if (rc < 0) {
        printf("snprintf failed!\n");
        free(psockaddr);
        free(pcmd_string);
        return -1;
    }
    *ppsockaddr = psockaddr;
    *ppcmd_string = pcmd_string;
    return 0;
}

static int ublock_inject_error_to_smart_info(struct err_injc_args args)
{
    int rc;
    char *sockaddr = NULL;
    char *cmd_string = NULL;

    if (args.devname == NULL) {
        printf("pci should not be NULL when error is injected to smart info\n");
        return -1;
    }

    rc = ublock_inject_get_smart_info_cmdstr(&sockaddr, &cmd_string, args);
    if (rc != 0) {
        return rc;
    }

    rc = ublock_send_request_err_injc(sockaddr, cmd_string);
    if (rc != 0) {
        printf("fail to send request to inject error to smart info!\n");
    }

    free(sockaddr);
    free(cmd_string);
    return rc;
}

static char *ublock_inject_error_format_cmdline_to_libstorage(struct err_injc_args args)
{
    char *cmd_line = NULL;
    char *cmd_str = NULL;
    size_t cmd_len = UBLOCK_CLIENT_ERROR_CMD_MAX_LEN - 1;
    int rc = 0;

    cmd_line = (char *)malloc(sizeof(char) * UBLOCK_CLIENT_ERROR_CMD_MAX_LEN);
    if (cmd_line == NULL) {
        printf("malloc for command to send to libstorage failed\n");
        return NULL;
    }

    switch (args.err_type) {
        case ERR_TYPE_SLOW_IO:
            cmd_str = UBLOCK_CLIENT_ERROR_INJECT_IO_SLOW;
            rc = snprintf_s(cmd_line, UBLOCK_CLIENT_ERROR_CMD_MAX_LEN,
                            cmd_len, cmd_str, args.devname, args.err_type,
                            args.flag, args.io_delay_us, args.lba_start,
                            args.lba_end, args.slowio_count);
            break;
        case ERR_TYPE_IO_TIMEOUT:
            cmd_str = UBLOCK_CLIENT_ERROR_INJECT_RET_CODE;
            rc = snprintf_s(cmd_line, UBLOCK_CLIENT_ERROR_CMD_MAX_LEN,
                            cmd_len, cmd_str, args.devname, args.err_type,
                            args.flag);
            break;
        case ERR_TYPE_UNC_ERROR:
        case ERR_TYPE_READ_CRC:
        case ERR_TYPE_READ_LBA:
        case ERR_TYPE_WRITE_CRC:
            cmd_str = UBLOCK_CLIENT_ERROR_INJECT_IO_PROC;
            rc = snprintf_s(cmd_line, UBLOCK_CLIENT_ERROR_CMD_MAX_LEN,
                            cmd_len, cmd_str, args.devname, args.err_type,
                            args.flag, args.lba_start, args.lba_end);
            break;
        case ERR_TYPE_ERROR_STATUS:
            cmd_str = UBLOCK_CLIENT_ERROR_INJECT_ERROR_STATUS;
            rc = snprintf_s(cmd_line, UBLOCK_CLIENT_ERROR_CMD_MAX_LEN,
                            cmd_len, cmd_str, args.devname, args.err_type,
                            args.flag, args.sc, args.sct, args.lba_start,
                            args.lba_end);
            break;
        default:
            printf("type of error is not correct.\n");
            free(cmd_line);
            return NULL;
    }

    if (rc < 0) {
        printf("snprintf failed!\n");
        free(cmd_line);
        return NULL;
    }

    return cmd_line;
}

static int ublock_inject_error_to_libstorage(char *pci, struct err_injc_args args)
{
    int rc;
    char *sockaddr = NULL;
    char *cmd_line = NULL;

    if (pci == NULL) {
        printf("pci pointer should not be NULL\n");
        return -1;
    }

    sockaddr = ublock_get_sockaddr(pci);
    if (sockaddr == NULL) {
        printf("cannot get sockaddr by pci %s\n", pci);
        return -1;
    }

    cmd_line = ublock_inject_error_format_cmdline_to_libstorage(args);
    if (cmd_line == NULL) {
        printf("construct command string to inject error failed\n");
        rc = -1;
        goto fail_format;
    }

    rc = ublock_send_request_err_injc(sockaddr, cmd_line);
    if (rc != 0) {
        printf("send rpc to libstorage to inject error failed\n");
    }

    free(cmd_line);

fail_format:
    free(sockaddr);

    return rc;
}

static int ublock_cleanup_injected_smart_error(struct err_injc_args *pargs)
{
    int rc;

    pargs->err_type = 0;
    pargs->percentage_used = 0;
    pargs->unsafe_shutdowns = 0;
    pargs->media_errors = 0;
    rc = ublock_inject_error_to_smart_info(*pargs);
    if (rc != 0) {
        printf("fail to clean error to smart info\n");
    }
    return rc;
}

static int opt_args(struct err_injc_args args)
{
    char *pci = NULL;
    int rc = 0;
    int err_type = args.err_type;

    /* after call verify_args(), err_type is in range of 0~15 */
    if (err_type == (int)ERR_TYPE_CLEANUP_SMART_ERR) {
        /* clean error injection of smart information */
        rc = ublock_cleanup_injected_smart_error(&args);
    } else if ((err_type > (int)ERR_TYPE_UNC_ERROR && err_type < (int)ERR_TYPE_READ_CRC) ||
               (err_type > (int)ERR_TYPE_ERROR_STATUS && err_type <= (int)ERR_TYPE_MODIFY_MEDIA_ERR_CNT)) {
        /* device injected error of smart info is specified by pci address */
        rc = ublock_inject_error_to_smart_info(args);
        if (rc != 0) {
            printf("fail to inject error to smart info\n");
        }
    } else {
        if (strncasecmp(args.devname, "nvme", strlen("nvme")) != 0) {
            printf("this error injection needs namespce name to specify device in format.\n");
            printf("e.g. nvme0n1\n");
            return -1;
        }
        pci = ublock_get_pci_by_devname(args.devname);
        if (pci == NULL) {
            printf("get pci by device name failed!\n");
            return -1;
        }

        rc = ublock_inject_error_to_libstorage(pci, args);
        if (rc != 0) {
            printf("fail to inject error to libstorage\n");
        }

        free(pci);
    }

    return rc;
}

static int check_type_percentage(struct err_injc_args *args)
{
    if (args->flag_per_used == UBLOCK_ERR_INJC_NOT_SET) {
        printf("need to specify percentage_used by -p option when error type is 4\n");
        return -1;
    }
    return 0;
}

static int check_type_slow_io(struct err_injc_args *args)
{
    if (args->flag == 0) {
        return 0;
    }
    if (args->io_delay_us == UBLOCK_ERR_INJC_NOT_SET ||
        args->slowio_count == UBLOCK_ERR_INJC_NOT_SET) {
        printf("error: need to specify time to delay and count of io to delay!\n");
        return -1;
    }
    return 0;
}

static int check_type_err_status(void)
{
    if (g_sc_sct_count < 2) { // 2: means sc and sct are both setted.
        printf("sc and sct value need to be provided by option --sc and --sct\n");
        return -1;
    }
    return 0;
}

static int check_type_write_crc(struct err_injc_args *args)
{
    if (args->flag < (int)ERR_INJC_FLAG_DISABLE_ALL ||
        args->flag > (int)ERR_INJC_FLAG_DISABLE_ONE_ITEM) {
        printf("invalid flag for error injection\n");
        return -1;
    }
    return 0;
}

static int check_type_unc_err(struct err_injc_args *args)
{
    if (args->flag == (int)ERR_INJC_FLAG_DISABLE_ALL) {
        return 0;
    }
    if (args->flag < (int)ERR_INJC_FLAG_DISABLE_ALL ||
        args->flag > (int)ERR_INJC_FLAG_ENABLE_FOR_COV_UNC) {
        printf("invalid flag for error injection\n");
        return -1;
    }
    if (args->flag_lba_spec != 2) { // 2: means lba start and end are both setted.
        printf("error: start and end of lba range both need to specified!\n");
        return -1;
    }
    if (args->lba_start > args->lba_end) {
        printf("start of lba address should not larger than end of lba address\n");
        return -1;
    }
    return 0;
}

static int check_type_io_timeout(struct err_injc_args *args)
{
    if (args->flag != (int)ERR_INJC_FLAG_DISABLE_ALL &&
        args->flag != (int)ERR_INJC_FLAG_ENABLE) {
        printf("error need to specify -f 0 or 1\n");
        return -1;
    }
    return 0;
}

static int check_type_modify_unsafe_cnt(void)
{
    if (!g_shut_down_flag) {
        printf("parameter must be provided by option --shutdown\n");
        return -1;
    }
    return 0;
}

static int check_type_modify_media_err_cnt(void)
{
    if (!g_media_error_flag) {
        printf("parameter must be provided by option --media_error\n");
        return -1;
    }
    return 0;
}

static int verify_args(struct err_injc_args args)
{
    int rc;

    if (args.devname == NULL) {
        printf("need to specify device name by -d option\n");
        goto bad;
    }
    if (args.err_type < (int)ERR_TYPE_SLOW_IO ||
        args.err_type > (int)ERR_TYPE_MODIFY_MEDIA_ERR_CNT) {
        printf("type of error injection is incorrect\n");
        goto bad;
    } else if (-1 == args.flag) {
        printf("flag should be provided by -f option\n");
        goto bad;
    }

    if (!g_type_spec_flag) {
        printf("error type must be provided!\n");
        goto bad;
    }

    /* if err_type == 12, it means clear error injection in smart info. */
    rc = 0;
    switch (args.err_type) {
        case ERR_TYPE_PERCENTAGE:
            rc = check_type_percentage(&args);
            break;
        case ERR_TYPE_SLOW_IO:
            rc = check_type_slow_io(&args);
            if (rc != 0) {
                goto bad;
            }
        /* fall-through */
        case ERR_TYPE_ERROR_STATUS:
            rc = check_type_err_status();
            if (rc != 0) {
                goto bad;
            }
        /* fall-through */
        case ERR_TYPE_READ_CRC:
        /* fall-through */
        case ERR_TYPE_READ_LBA:
        /* fall-through */
        case ERR_TYPE_WRITE_CRC:
            rc = check_type_write_crc(&args);
            if (rc != 0) {
                goto bad;
            }
        /* fall-through */
        case ERR_TYPE_UNC_ERROR:
            rc = check_type_unc_err(&args);
            break;
        case ERR_TYPE_IO_TIMEOUT:
            rc = check_type_io_timeout(&args);
            break;
        case ERR_TYPE_MODIFY_UNSAFE_CNT:
            rc = check_type_modify_unsafe_cnt();
            break;
        case ERR_TYPE_MODIFY_MEDIA_ERR_CNT:
            rc = check_type_modify_media_err_cnt();
            break;

        default:
            break;
    }
    if (rc == 0) {
        return 0;
    }
bad:
    printf("error: invalid options.");
    usage("libstorage-error-inject");
    return -1;
}

static bool check_err_endchr(char endchr)
{
    if (errno || endchr != '\0') {
        return true;
    }
    return false;
}

static void parse_arg_d(struct err_injc_args *args)
{
    if (strncasecmp(optarg, "nvme", strlen("nvme")) != 0 &&
        ublock_str_is_nvme_pci_addr(optarg) == 0) {
        printf("device name must be provided!\n");
        exit(1);
    }
    args->devname = optarg;
}

static void parse_arg_t(struct err_injc_args *args)
{
    int rc;

    rc = ublock_string_to_int(optarg, &args->err_type);
    if (rc < 0) {
        printf("unsigned integer expected for proper error type parameter\n");
        exit(1);
    }
    if ((args->err_type > (int)ERR_TYPE_UNC_ERROR && args->err_type < (int)ERR_TYPE_READ_CRC) ||
        (args->err_type == (int)ERR_TYPE_CLEANUP_SMART_ERR) || (args->err_type > (int)ERR_TYPE_ERROR_STATUS &&
         args->err_type <= (int)ERR_TYPE_MODIFY_MEDIA_ERR_CNT)) {
        args->flag = 0;
    }
    if (args->err_type != (int)ERR_TYPE_ERROR_STATUS) {
        g_sc_sct_count = 2; // 2: means sc and sct are both setted.
    }
    g_type_spec_flag = true;
}

static void parse_arg_p(struct err_injc_args *args, char *name)
{
    int rc;

    rc = ublock_string_to_int(optarg, &args->percentage_used);
    if (rc < 0) {
        printf("unsigned integer expected for proper percentage used parameter\n");
        exit(1);
    }
    if (args->percentage_used < 0 || args->percentage_used > 255) { // 0~255 is the degree of disk wear.
        printf("percentage_used should be an integer in 0~255\n");
        usage(name);
        exit(1);
    }
    /* used to judge whether percentage_used is specified or not. */
    args->flag_per_used = 1;
}

static void parse_arg_f(struct err_injc_args *args)
{
    int rc;

    rc = ublock_string_to_int(optarg, &args->flag);
    if (rc < 0) {
        printf("unsigned integer expected for proper flag parameter\n");
        exit(1);
    }
}

static void parse_arg_s(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->lba_start = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("unsigned integer expected for lba start parameter\n");
        exit(1);
    }
    args->flag_lba_spec++;
}

static void parse_arg_e(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->lba_end = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("unsigned integer expected for lba end parameter\n");
        exit(1);
    }
    args->flag_lba_spec++;
}

static void parse_arg_u(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->io_delay_us = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("unsigned integer expected for time parameter to delay\n");
        exit(1);
    }
}

static void parse_arg_c(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->slowio_count = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("unsigned integer expected for count of slow io parameter\n");
        exit(1);
    }
}

static void parse_arg_uc_s(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->sc = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("hexadecimal or decimal unsigned integer is expected\n");
        exit(1);
    }
    if (args->sc > INT_MAX) {
        printf("sc should not be greater than %d\n", INT_MAX);
        exit(1);
    }
    g_sc_sct_count++;
}

static void parse_arg_uc_t(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->sct = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("hexadecimal or decimal unsigned integer is expected\n");
        exit(1);
    }
    if (args->sct > INT_MAX) {
        printf("sct should not be greater than %d\n", INT_MAX);
        exit(1);
    }
    g_sc_sct_count++;
}

static void parse_arg_uc_d(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->unsafe_shutdowns = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("unsigned integer expected for unsafe_shutdowns count\n");
        exit(1);
    }
    g_shut_down_flag = true;
}

static void parse_arg_uc_m(struct err_injc_args *args)
{
    char *endptr = NULL;

    args->media_errors = strtoul(optarg, &endptr, 0);
    if (check_err_endchr(endptr[0])) {
        printf("unsigned integer expected for media_errors count\n");
        exit(1);
    }
    g_media_error_flag = true;
}

static int parse_check_arg(struct err_injc_args args)
{
    int rc;

    rc = opt_args(args);
    if (rc == 0) {
        printf("inject error success\n");
    } else {
        printf("inject error fail\n");
    }
    return rc;
}

static int parse_opts(int opt, struct err_injc_args *args, char* name)
{
    switch (opt) {
        case 'd':
            parse_arg_d(args);
            break;

        case 't':
            parse_arg_t(args);
            break;

        case 'p':
            parse_arg_p(args, name);
            break;

        case 'f':
            parse_arg_f(args);
            break;

        case 's':
            parse_arg_s(args);
            break;

        case 'e':
            parse_arg_e(args);
            break;

        case 'u':
            parse_arg_u(args);
            break;

        case 'c':
            parse_arg_c(args);
            break;

        case 'S':
            parse_arg_uc_s(args);
            break;

        case 'T':
            parse_arg_uc_t(args);
            break;

        case 'D':
            parse_arg_uc_d(args);
            break;

        case 'M':
            parse_arg_uc_m(args);
            break;

        case '?':
            printf("cannot parse option name!\n");

        /* fall-through */
        case 'h':

        /* fall-through */
        default:
            usage(name);
            return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int rc;
    int opt;
    struct err_injc_args args;
    const char *op_str = "d:t:p:f:s:e:u:c:";
    struct option long_options[] = {
        { "sc", required_argument, NULL, 'S' },
        { "sct", required_argument, NULL, 'T' },
        { "shutdown", required_argument, NULL, 'D' },
        { "media_error", required_argument, NULL, 'M' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    if (argv == NULL) {
        return -1;
    }

    if (argc == 1 || strcmp(argv[1], "-help") == 0) {
        usage(argv[0]);
        exit(0);
    }

    rc = memset_s(&args, sizeof(struct err_injc_args), 0, sizeof(struct err_injc_args));
    if (rc != 0) {
        printf("memset failed!\n");
        return -1;
    }
    args.flag = -1;
    opt = getopt_long(argc, argv, op_str, long_options, NULL);
    for (; opt != -1; opt = getopt_long(argc, argv, op_str, long_options, NULL)) {
        errno = 0;
        rc = parse_opts(opt, &args, argv[0]);
        if (rc == (-1)) {
            return -1;
        }
        if (optarg[0] == '-') {
            printf("parameter should be unsiged integer or string\n");
            exit(1);
        }
    }

    if (verify_args(args) != 0) {
        printf("%s invalid options\n", argv[0]);
        return -1;
    }

    rc = parse_check_arg(args);

    return rc;
}
