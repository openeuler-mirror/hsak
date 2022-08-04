/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: common function api of cli
* Author: zhoupengchen
* Create: 2018-10-10
*/

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "ublock_cli_common.h"

bool ublock_str_is_nvme_pci_addr(const char *str)
{
    /* The NVMe device pci address format is DDDD:BB:DD.F */
    char *pattern = "^[0-9a-fA-F]\\{4,8\\}:[0-9a-fA-F]\\{2\\}:[0-9a-fA-F]\\{2\\}\\.[0-7]$";

    int ret;
    int cflags = 0;
    const size_t nmatch = 10; /* 10 bytes size for regex matching */
    regmatch_t pm[10]; /* 10 bytes tmp buf for regex matching */
    regex_t reg;

    ret = regcomp(&reg, pattern, cflags);
    if (ret != 0) {
        syslog(LOG_ERR, "regcomp failed\n");
        return false;
    }
    ret = regexec(&reg, str, nmatch, pm, cflags);
    regfree(&reg);

    if (ret == 0) {
        return true;
    } else {
        return false;
    }
}
