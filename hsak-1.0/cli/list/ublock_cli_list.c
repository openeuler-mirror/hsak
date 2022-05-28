/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
* Description: cli of disk list
* Author: zhoupengchen
* Create: 2018-9-19
*/

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/queue.h>

#include <spdk/env.h>
#include "ublock.h"
#include "ublock_cli_common.h"
#include "ublock_internal.h"

struct ublock_list_item {
    char pci[UBLOCK_PCI_ADDR_MAX_LEN];
    char size[24]; /* 24 is the size of buf to store disk size info */
    char sector[21]; /* 21 is the size of buf to store disk sector info */
    char sn[21]; /* 21 is the size of buf to store disk sn info */
    char mn[41]; /* 41 is the size of buf to store disk mn info */
    char fr[9]; /* 9 is the size of buf to store disk fr info */
    /* flag int status = 0 or 1, */
    /* 0 for ok to print; 1 for not ok to print */
    int status;
    TAILQ_ENTRY(ublock_list_item) next;
};

static TAILQ_HEAD(, ublock_list_item) g_item_list;

static struct ublock_bdev_mgr g_bdev_list;

static int ublock_list_bdev2item(const struct ublock_bdev *bdev, struct ublock_list_item *item)
{
    int ret;

    ret = strcpy_s(item->pci, sizeof(item->pci), bdev->pci);
    if (ret != 0) {
        printf("[libstorage-list] strcpy_s failed, error number: %d\n", ret);
        return -1;
    }

    ret = snprintf_s(&(item->size[0]), sizeof(item->size), sizeof(item->size) - 1,
                     "%lu GB", bdev->info.cap_size >> 30); /* right shift 30 bits used to convert bytes to GB */
    if (ret < 0) {
        printf("[libstorage-list] snprintf_s item->size failed, error number: %d\n", ret);
        return -1;
    }

    ret = snprintf_s(&(item->sector[0]), sizeof(item->sector), sizeof(item->sector) - 1,
                     "%-4lu + %-4u", bdev->info.sector_size, bdev->info.md_size);
    if (ret < 0) {
        printf("[libstorage-list] snprintf_s item->sector failed, error number: %d\n", ret);
        return -1;
    }

    ret = memcpy_s(&(item->sn[0]), sizeof(item->sn), &(bdev->info.serial_number[0]),
                   sizeof(bdev->info.serial_number));

    ret += memcpy_s(&(item->mn[0]), sizeof(item->mn), &(bdev->info.model_number[0]),
                    sizeof(bdev->info.model_number));

    ret += memcpy_s(&(item->fr[0]), sizeof(item->fr), &(bdev->info.firmware_revision[0]),
                    sizeof(bdev->info.firmware_revision));
    if (ret != 0) {
        printf("[libstorage-list] memcpy_s failed, error number: %d\n", ret);
        return -1;
    }

    item->status = 0;

    return 0;
}

static bool ublock_list_has_item(const struct ublock_list_item *item)
{
    if (item == NULL) {
        return false;
    }

    struct ublock_list_item *tmp = NULL;
    struct ublock_list_item *each_item = NULL;

    TAILQ_FOREACH_SAFE(each_item, &g_item_list, next, tmp) {
        if (strcmp(each_item->pci, item->pci) == 0) {
            return true;
        }
    }

    return false;
}

static void ublock_list_print_item(const struct ublock_list_item *item)
{
    if (item == NULL) {
        return;
    }

    if (item->status == 0) {
        printf("%-16s %-20s %-40s %-26s %-16s %-8s\n",
               item->pci,
               item->sn,
               item->mn,
               item->size,
               item->sector,
               item->fr);
    }
}

static void ublock_list_print_header(void)
{
    printf("\n%-16s-%-20s-%-40s-%-26s-%-16s-%-8s\n",
           "----------------",
           "--------------------",
           "----------------------------------------",
           "--------------------------",
           "----------------",
           "--------");
    printf("%-16s %-20s %-40s %-26s %-16s %-8s\n",
           "Node",
           "SN",
           "Model",
           "Size",
           "Format",
           "FW Rev");
    printf("%-16s %-20s %-40s %-26s %-16s %-8s\n",
           "----------------",
           "--------------------",
           "----------------------------------------",
           "--------------------------",
           "----------------",
           "--------");
}

static int ublock_list_print_rear(int flg)
{
    struct ublock_list_item *tmp = NULL;
    struct ublock_list_item *each_item = NULL;

    printf("%-16s-%-20s-%-40s-%-26s-%-16s-%-8s\n",
           "----------------",
           "--------------------",
           "----------------------------------------",
           "--------------------------",
           "----------------",
           "--------");
    if (flg > 0) {
        printf("\n[WARNING] Cannot List The Following NVMe Devices:\n");
        TAILQ_FOREACH_SAFE(each_item, &g_item_list, next, tmp) {
            if (each_item->status == 1) {
                printf("%s\n", each_item->pci);
            }
        }

        return 1;
    }

    return 0;
}

/* probe all NVMe devices and store into g_bdev_list */
static int ublock_list_probe_nvme_devices(void)
{
    int rc;
    struct ublock_bdev *bdev = NULL;
    struct ublock_bdev *tmp = NULL;
    struct ublock_bdev bdev_info;

    rc = ublock_get_bdevs(&g_bdev_list);
    if (rc != 0) {
        printf("[libstorage-list] ublock_get_bdevs failed\n");
        return rc;
    }
    TAILQ_FOREACH_SAFE(bdev, &g_bdev_list.bdevs, link, tmp) {
        rc = ublock_get_bdev(bdev->pci, &bdev_info);
        if (rc < 0) {
            bdev->ctrlr = (void *)-1;
            continue;
        } else {
            rc = memcpy_s(&(bdev->info),
                          sizeof(struct ublock_bdev_info),
                          &(bdev_info.info),
                          sizeof(bdev_info.info));
            if (rc != 0) {
                printf("[libstorage-list] memcpy failed\n");
                return -1;
            }
            bdev->ctrlr = bdev_info.ctrlr;
        }
    }

    return 0;
}

static struct ublock_list_item *ublock_malloc_set_list_item(void)
{
    struct ublock_list_item *item = NULL;

    item = (struct ublock_list_item *)calloc(1, sizeof(struct ublock_list_item));
    if (item == NULL) {
        printf("[libstorage-list] calloc failed\n");
        return NULL;
    }

    return item;
}

static int ublock_insert_item_into_list(struct ublock_list_item *item, const char *pci)
{
    int rc;

    item->status = 1;
    rc = strcpy_s(item->pci, sizeof(item->pci), pci);
    if (rc != 0) {
        printf("[libstorage-list] strcpy_s failed, error number: %d\n", rc);
        return -1;
    }
    if (!ublock_list_has_item(item)) {
        TAILQ_INSERT_TAIL(&g_item_list, item, next);
        return 0; /* 0 means the item is inserted into the g_item_list successfully */
    }

    return 1; /* 1 means the item is already in g_item_list, no need insert */
}

/* store all NVMe devices bdev into g_item_list for showup */
static int ublock_list_bdevs(void)
{
    int rc;
    struct ublock_bdev *bdev = NULL;
    struct ublock_bdev *tmp = NULL;
    struct ublock_list_item *item = NULL;

    TAILQ_FOREACH_SAFE(bdev, &g_bdev_list.bdevs, link, tmp) {
        item = ublock_malloc_set_list_item();
        if (item == NULL) {
            printf("[libstorage-list] malloc and memset failed\n");
            return -1;
        }

        if (bdev->ctrlr == (void *)-1) {
            rc = ublock_insert_item_into_list(item, bdev->pci);
            if (rc != 0) {
                free(item);
            }
            if (rc < 0) {
                return -1;
            }

            continue;
        }

        if (ublock_list_bdev2item(bdev, item) != 0) {
            /* failure of ublock_list_bdev2item lead to fail to list device, */
            /* and this device should be added into warning */
            item->status = 1;
            rc = strcpy_s(item->pci, sizeof(item->pci), bdev->pci);
            if (rc != 0) {
                printf("[libstorage-list] strcpy_s failed, error number: %d\n",
                       rc);
                free(item);
                return -1;
            }
        }
        if (!ublock_list_has_item(item)) {
            TAILQ_INSERT_TAIL(&g_item_list, item, next);
        } else {
            /* cleanup repeat item */
            free(item);
        }
    }

    return 0;
}

static int ublock_list_bdev_is_exist(const char *pci)
{
    int rc;
    int cnt_in_list = 0;
    struct ublock_bdev *bdev = NULL;
    struct ublock_bdev *tmp = NULL;
    struct ublock_list_item *item = NULL;

    TAILQ_FOREACH_SAFE(bdev, &g_bdev_list.bdevs, link, tmp) {
        if (strcmp(pci, bdev->pci) != 0) {
            continue;
        }

        cnt_in_list++;
        item = ublock_malloc_set_list_item();
        if (item == NULL) {
            printf("[libstorage-list] malloc and memset failed\n");
            return -1;
        }

        if (bdev->ctrlr == (void *)-1) {
            rc = ublock_insert_item_into_list(item, bdev->pci);
            if (rc != 0) {
                free(item);
            }
            if (rc < 0) {
                return -1;
            }
            return cnt_in_list;
        }

        if (ublock_list_bdev2item(bdev, item) != 0) {
            /* failure of ublock_list_bdev2item lead to fail to list device, */
            /* and this device should be added into warning */
            item->status = 1;
            rc = strcpy_s(item->pci, sizeof(item->pci), pci);
            if (rc != 0) {
                printf("[libstorage-list] strcpy_s failed, error number: %d\n", rc);
                free(item);
                return -1;
            }
        }
        if (!ublock_list_has_item(item)) {
            TAILQ_INSERT_TAIL(&g_item_list, item, next);
        } else {
            /* remove repeat item */
            free(item);
        }
    }

    return cnt_in_list;
}

/* store specific NVMe device bdev into g_item_list for showup */
static int ublock_list_bdev(const char *pci)
{
    int rc;
    int flg_in_list;
    struct ublock_list_item *item = NULL;

    if (pci == NULL) {
        return -1;
    }

    flg_in_list = ublock_list_bdev_is_exist(pci);
    /* the given pci address not in the bdev list, */
    /* which means it is not local NVMe device */
    if (flg_in_list < 0) {
        return -1;
    } else if (flg_in_list == 0) {
        item = ublock_malloc_set_list_item();
        if (item == NULL) {
            printf("[libstorage-list] malloc and memset failed\n");
            return -1;
        }

        rc = ublock_insert_item_into_list(item, pci);
        if (rc != 0) {
            free(item);
        }
        if (rc < 0) {
            return -1;
        }
    }
    return 0;
}

static void ublock_list_init(void)
{
    int ret;

    /* check if ublock server already start */
    if (!ublock_query_server_exist(UBLOCK_SERVER_LOCKFILE, false, getpid())) {
        /* no ublock server, this cmdline tools cannot go on */
        printf("[libstorage-list] fail to list for no ublock server running\n");
        exit(EXIT_FAILURE);
    }

    /* tail-queue of printing items initialization */
    TAILQ_INIT(&g_item_list);

    /* tail-queue of all bdev of probed NVMe devices */
    ret = ublock_list_probe_nvme_devices();
    if (ret != 0) {
        /* cannot finish listing when probing all NVMe devices failed */
        printf("[libstorage-list] fail to probe NVMe devices\n");
        exit(EXIT_FAILURE);
    }
}

static void ublock_list_fini(void)
{
    struct ublock_bdev *bdev = NULL;
    struct ublock_bdev *tmp = NULL;
    struct ublock_list_item *each_item = NULL;

    while (!TAILQ_EMPTY(&g_item_list)) {
        each_item = TAILQ_FIRST(&g_item_list);
        TAILQ_REMOVE(&g_item_list, each_item, next);
        free(each_item);
    }

    TAILQ_FOREACH_SAFE(bdev, &g_bdev_list.bdevs, link, tmp) {
        if (bdev->ctrlr != NULL && bdev->ctrlr != (void *)-1) {
            ublock_free_bdev(bdev);
        }
    }

    ublock_free_bdevs(&g_bdev_list);
}

static void usage(void)
{
    printf("Usage: libstorage-list [<commands>] [<device>]\n");
    printf("       The '<device>' should be the pci address of NVMe device "
           "(ex: 0000:08:00.0).\n");
    printf("\n");
    printf("The following are all supported commands:\n");
    printf("    libstorage-list              List all NVMe devices on the machine\n");
    printf("    libstorage-list help         Show libstorage-list usage\n");
    printf("    libstorage-list <devices>    List the specified NVMe device whose pci"
           "address is <devices>\n");
}

static int ublock_list(void)
{
    int ret;
    int error_item = 0;
    struct ublock_list_item *tmp = NULL;
    struct ublock_list_item *each_item = NULL;

    ublock_list_print_header();

    TAILQ_FOREACH_SAFE(each_item, &g_item_list, next, tmp) {
        error_item += each_item->status;
        ublock_list_print_item(each_item);
    }

    ret = ublock_list_print_rear(error_item);

    /* if there is some devices failing to list, notify CLI */
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int i;

    if (argc < 1) {
        ret = -1;
        printf("Unknow error for CLI parameter\n");
        goto END;
    } else if (argc == 1) {
        /* print info of all nvme device on the machine */
        ublock_list_init();
        ret = ublock_list_bdevs();
        if (ret != 0) {
            goto END;
        }
        ret = ublock_list();
        goto END;
    }

    if (strcmp(argv[1], "help") == 0) {
        usage();
        goto END;
    }

    /* CLI parameter checking */
    for (i = 1; i < argc; ++i) {
        if (ublock_str_is_nvme_pci_addr(argv[i]) == 0) {
            printf("[libstorage-list] error device information: `%s', "
                   "(example: 0000:08:00.0)\n",
                   argv[i]);
            goto END;
        }
    }
    /* print info of the identified nvme device */
    ublock_list_init();
    for (i = 1; i < argc; ++i) {
        ret = ublock_list_bdev(argv[i]);
        if (ret != 0) {
            goto END;
        }
    }
    ret = ublock_list();

END:
    ublock_list_fini();
    return ret;
}
