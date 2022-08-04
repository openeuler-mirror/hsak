/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
* Description: IO stat function
* Author: zhangsaisai
* Create: 2018-9-1
*/

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <time.h>

#include "ublock.h"
#include "ublock_internal.h"

#define SLEEP_MIN 1
#define SLEEP_MAX 3600

static unsigned int dev_nr = 0;   /* Number of devices found */
static long interval = 1;    /* IO statistics interval, default 1. */
int flags = 0;    /* Flag for common options */
long count = LONG_MAX;    /* IO statistics count, default LONG_MAX. */
int dlist_idx = 0;     /* Number of devices entered on the command line */

char dev_list[STAT_MAX_NUM][STAT_NAME_LEN];    /* Name of devices entered on the command line */
static struct libstorage_bdev_io_stat *g_io_stat_map; /* Share memory mmap area */
struct io_stats *st_iodev[2]; /* IO statistics require 2 statistical values to be subtracted */
unsigned long long uptime[2] = { 0, 0 }; /* latency statistics require 2 statistical values to be subtracted */
unsigned int cpu_hz; /* Number of ticks per second */

/* get cpu frequency */
static uint64_t get_tsc_freq_local(void)
{
#ifdef CLOCK_MONOTONIC_RAW
#define NS_PER_SEC 1E9

    struct timespec sleeptime = { .tv_nsec = (long)(NS_PER_SEC / 10) }; /* 1/10 second */

    struct timespec t_start, t_end;
    uint64_t tsc_hz;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
        uint64_t ns, end, start = get_tsc_cycles_local();
        nanosleep(&sleeptime, NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
        end = get_tsc_cycles_local();
        if (t_start.tv_sec > t_end.tv_sec ||
                (t_start.tv_sec == t_end.tv_sec && t_start.tv_nsec >= t_end.tv_nsec) ||
                start > end) {
            return 0;
        }

        ns = (uint64_t)((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
        ns += (uint64_t)(t_end.tv_nsec - t_start.tv_nsec);

        double secs = (double)ns / NS_PER_SEC;
        tsc_hz = (uint64_t)((end - start) / secs);
        return tsc_hz;
    }
#endif
    return 0;
}

/* get number of clock ticks per second */
static void get_cpu_hz(void)
{
    long ticks;

    ticks = sysconf(_SC_CLK_TCK);
    if (ticks == -1) {
        perror("sysconf");
        ticks = 250; /* if sysconf error, set it to 250 as default */
    }

    cpu_hz = (unsigned int)ticks;
}

/* print usage and exit */
static void usage(const char *progname)
{
    fprintf(stderr, ("Usage: %s [-t <interval>] [-i <count>] [-d <device1,device2,...>]\n "), progname);
    exit(1);
}

static int mmap_sharemem(void)
{
#define MAX_SHM_OFFSET    (sizeof(struct libstorage_bdev_io_stat) * STAT_MAX_NUM)

    int shm_fd = -1;
    char *path = LIBSTORAGE_STAT_SHM_FILE_NAME;
    struct stat shm_stat;

    /* open share memory */
    shm_fd = shm_open(path, O_RDWR, 0600); /* 0600 is file access type */
    if (shm_fd < 0) {
        char *tmp_str = strerror(errno);
        if (tmp_str != NULL) {
            printf("open share memory failed[errno=%s].\n", tmp_str);
        } else {
            printf("open share memory failed[errno=%d].\n", errno);
        }
        return -1;
    }

    if (fstat(shm_fd, &shm_stat) == (-1)) {
        printf("get share memory stat failed[errno=%d].\n", errno);
        close(shm_fd);
        return -1;
    }

    if (shm_stat.st_size != MAX_SHM_OFFSET) {
        printf("share memory size different with request size, maybe software version didn't match.\n");
        close(shm_fd);
        return -1;
    }

    g_io_stat_map = (struct libstorage_bdev_io_stat *)mmap(NULL,
                                                           MAX_SHM_OFFSET,
                                                           PROT_READ,
                                                           MAP_SHARED,
                                                           shm_fd,
                                                           0);
    if (g_io_stat_map == MAP_FAILED) {
        char *tmp_str = strerror(errno);
        if (tmp_str != NULL) {
            printf("mmap share memory failed[errno=%s].\n", tmp_str);
        } else {
            printf("mmap share memory failed[errno=%d].\n", errno);
        }
        close(shm_fd);
        /* if mmap failed, do not unlink share memory, because other threads will use the share memory. */
        return -1;
    }

    close(shm_fd);
    return 0;
}

static unsigned int get_dev_nr(void)
{
    unsigned int nr = 0;
    unsigned int i = 0;
    unsigned int j = 0;
    struct libstorage_bdev_io_stat *ptmp_io_stat_map = NULL;
    int rc = 0;

    ptmp_io_stat_map = (struct libstorage_bdev_io_stat *)calloc(STAT_MAX_NUM, sizeof(struct libstorage_bdev_io_stat));
    if (ptmp_io_stat_map == NULL) {
        printf("not enough memory!\n");
        return 0;
    }

    /* copy g_io_stat_map[i].bdev_name to ptmp_io_stat_map[i].bdev_name */
    for (i = 0; i < STAT_MAX_NUM; i++) {
        if (g_io_stat_map[i].bdev_name[0] != 0) {
            rc = memcpy_s(ptmp_io_stat_map[i].bdev_name, STAT_NAME_LEN, g_io_stat_map[i].bdev_name, STAT_NAME_LEN);
        }
        if (rc != 0) {
            free(ptmp_io_stat_map);
            return 0;
        }
    }

    for (i = 0; i < STAT_MAX_NUM; i++) {
        if (0 == strlen(ptmp_io_stat_map[i].bdev_name)) {
            continue;
        }
        nr++;
        /* if device name duplicate, ignore it */
        for (j = i + 1; j < STAT_MAX_NUM; j++) {
            if (strncmp(ptmp_io_stat_map[j].bdev_name, ptmp_io_stat_map[i].bdev_name, STAT_NAME_LEN) != 0) {
                continue;
            }
            rc = memset_s(ptmp_io_stat_map[j].bdev_name, STAT_NAME_LEN, 0, STAT_NAME_LEN);
            if (rc != 0) {
                *(ptmp_io_stat_map[j].bdev_name) = 0;
            }
        }
    }

    free(ptmp_io_stat_map);
    return nr;
}

static void salloc_device(unsigned int nr)
{
    int i;

    if (nr == 0) {
        printf("You cannot get iostat info for nvme device no deliver io!\n");
        exit(1);
    }
    for (i = 0; i < 2; i++) { /* IO statistics require 2 statistical values to be subtracted */
        st_iodev[i] = (struct io_stats *)calloc(nr, sizeof(struct io_stats));
        if (st_iodev[i] == NULL) {
            perror("calloc");
            exit(1);
        }
    }
}

/* Allocate and init structures */
static void io_sys_init(void)
{
    dev_nr = get_dev_nr();

    salloc_device(STAT_MAX_NUM);
}

static void io_sys_free(void)
{
    int i;

    for (i = 0; i < 2; i++) { /* IO statistics require 2 statistical values to be subtracted */
        if (st_iodev[i]) {
            free(st_iodev[i]);
            st_iodev[i] = NULL;
        }
    }

    (void) munmap(g_io_stat_map, sizeof(struct libstorage_bdev_io_stat) * STAT_MAX_NUM);
    g_io_stat_map = NULL;
}

/**
 * Get local date and time.
 *
 * OUT:
 * @rectime Current local date and time.
 *
 * RETURNS:
 * Value of time in seconds since the Epoch.
 * */
static time_t get_localtime(struct tm *rectime)
{
    time_t timer;
    struct tm *ltm = NULL;
    struct tm ttm; /* save time */

    (void)time(&timer);
    ltm = localtime_r(&timer, &ttm);
    if (rectime == NULL || ltm == NULL) {
        return timer;
    }

    *rectime = *ltm;

    return timer;
}

static void print_header(const struct tm *rectime, const char *sysname, const char *release,
                         const char *nodename, const char *machine)
{
    char cur_date[64]; /* 64 bytes tmp buf for printing */

    if (rectime == NULL || sysname == NULL || release == NULL || nodename == NULL || machine == NULL) {
        return;
    }

    strftime(cur_date, sizeof(cur_date), "%x", rectime);

    printf("%s %s (%s) \t%s \t_%s_\n", sysname, release, nodename, cur_date, machine);
    return;
}

/**
 * Save state for current device.
 *
 * IN:
 * @curr  Index in array for current sample statistics.
 * @sdev  Structure with device.
 * */
static void save_stats(int curr, const struct io_stats *sdev)
{
    unsigned int i;
    struct io_stats *st_iodev_i = NULL;
    int rc = 0;

    if (sdev == NULL) {
        return;
    }

    for (i = 0; i < STAT_MAX_NUM; i++) {
        st_iodev_i = st_iodev[curr] + i;
        if (st_iodev_i->dev_name[0] != 0 && !strcmp(st_iodev_i->dev_name, sdev->dev_name)) {
            /* add the same device sample statistics */
            st_iodev_i->rd_ios += sdev->rd_ios;
            st_iodev_i->wr_ios += sdev->wr_ios;
            st_iodev_i->rd_bytes += sdev->rd_bytes;
            st_iodev_i->wr_bytes += sdev->wr_bytes;
            st_iodev_i->rd_ticks += sdev->rd_ticks;
            st_iodev_i->wr_ticks += sdev->wr_ticks;
            st_iodev_i->io_outstanding += sdev->io_outstanding;
            if (st_iodev_i->tot_ticks < sdev->tot_ticks) {
                st_iodev_i->tot_ticks = sdev->tot_ticks;
            }
            st_iodev_i->num_poll_timeout += sdev->num_poll_timeout;
            st_iodev_i->poll_time_used |= sdev->poll_time_used;

            break;
        }
    }

    if (i != STAT_MAX_NUM) {
        return;
    }
    /* This is a new device,look for an unused entry of st_iodev[curr] to store it. */
    for (i = 0; i < STAT_MAX_NUM; i++) {
        st_iodev_i = st_iodev[curr] + i;
        if (0 == strlen(st_iodev_i->dev_name)) {
            rc = strncpy_s(st_iodev_i->dev_name, sizeof(st_iodev_i->dev_name), sdev->dev_name, STAT_NAME_LEN - 1);
            if (rc == 0) {
                st_iodev_i->rd_ios = sdev->rd_ios;
                st_iodev_i->wr_ios = sdev->wr_ios;
                st_iodev_i->rd_bytes = sdev->rd_bytes;
                st_iodev_i->wr_bytes = sdev->wr_bytes;
                st_iodev_i->rd_ticks = sdev->rd_ticks;
                st_iodev_i->wr_ticks = sdev->wr_ticks;
                st_iodev_i->io_outstanding = sdev->io_outstanding;
                st_iodev_i->tot_ticks = sdev->tot_ticks;
                st_iodev_i->poll_time_used = sdev->poll_time_used;
                st_iodev_i->num_poll_timeout = sdev->num_poll_timeout;
            }
            break;
        }
    }
}

/**
 * Refresh device map.
 *
 * IN:
 * @curr  Index in array for current sample statistics.
 * */
static void refresh_device(int curr)
{
    int i = 0;
    int j = 0;
    bool  found = false;
    int rc = 0;
    struct io_stats *st_iodev_i = NULL;

    for (i = 0; i < STAT_MAX_NUM; i++) {
        st_iodev_i = st_iodev[curr] + i;
        found = false;
        if (st_iodev_i->dev_name[0] == 0) {
            continue;
        }
        for (j = 0; j < STAT_MAX_NUM; j++) {
            if (strncmp(st_iodev_i->dev_name, g_io_stat_map[j].bdev_name, STAT_NAME_LEN - 1) == 0) {
                found = true;
            }
        }
        if (!found) {
            rc = memset_s(st_iodev_i, sizeof(struct io_stats), 0, sizeof(struct io_stats));
            if (rc != 0) {
                st_iodev_i->dev_name[0] = 0;
            }
        }
    }
}

/**
 * Read stats of all devices from share memory.
 *
 * IN:
 * @curr  Index in array for current sample statistics.
 * */
static void read_all_diskstats_stat(int curr)
{
    int i;
    struct io_stats sdev;
    int rc = 0;

    refresh_device(curr);

    for (i = 0; i < STAT_MAX_NUM; i++) {
        if (g_io_stat_map[i].bdev_name[0] != 0) {
            rc = strncpy_s(sdev.dev_name, sizeof(sdev.dev_name), g_io_stat_map[i].bdev_name, STAT_NAME_LEN - 1);
            if (rc == 0) {
                sdev.rd_ios = g_io_stat_map[i].num_read_ops;
                sdev.wr_ios = g_io_stat_map[i].num_write_ops;
                sdev.rd_bytes = g_io_stat_map[i].bytes_read;
                sdev.wr_bytes = g_io_stat_map[i].bytes_written;
                sdev.rd_ticks = g_io_stat_map[i].read_latency_ticks;
                sdev.wr_ticks = g_io_stat_map[i].write_latency_ticks;
                sdev.io_outstanding = g_io_stat_map[i].io_outstanding;
                sdev.tot_ticks = g_io_stat_map[i].io_ticks;
                sdev.poll_time_used = g_io_stat_map[i].poll_time_used;
                sdev.num_poll_timeout = g_io_stat_map[i].num_poll_timeout;

                save_stats(curr, &sdev);
            }
        }
    }
}

static void clear_st_iodev(int idx)
{
    unsigned int i;
    struct io_stats *st_iodev_i = NULL;

    for (i = 0; i < STAT_MAX_NUM; i++) {
        st_iodev_i = st_iodev[idx] + i;
        st_iodev_i->rd_ios = 0;
        st_iodev_i->wr_ios = 0;
        st_iodev_i->rd_bytes = 0;
        st_iodev_i->wr_bytes = 0;
        st_iodev_i->rd_ticks = 0;
        st_iodev_i->wr_ticks = 0;
        st_iodev_i->io_outstanding = 0;
        st_iodev_i->tot_ticks = 0;
        st_iodev_i->poll_time_used = false;
        st_iodev_i->num_poll_timeout = 0;
    }
}

/**
 * Read machine uptime, independently of the number of processors.
 *
 * OUT:
 * @uptime   Uptime value in seconds.
 * */
static void read_uptime(unsigned long long *uptime_t)
{
    FILE *fp = NULL;
    char line[128]; /* 128 bytes tmp buf for input data */
    unsigned long long up_sec;
    unsigned long long up_cent;
    int rc;

    fp = fopen("/proc/uptime", "r");
    if (fp == NULL) {
        return;
    }

    if (fgets(line, 128, fp) == NULL) { /* 128 bytes tmp buf for input data */
        fclose(fp);
        return;
    }

    rc = sscanf_s(line, "%llu.%llu", &up_sec, &up_cent);
    if (rc == 2 && uptime_t != NULL) { /* 2 variable */
        *uptime_t = (unsigned long long)up_sec * cpu_hz + (unsigned long long)up_cent * cpu_hz / 100; /* 100 percent */
    }

    fclose(fp);
}

#define S_VALUE(m, n, p) (((double)((n) - (m))) / (p) * cpu_hz)

static double ll_s_value(unsigned long long value1, unsigned long long value2, unsigned long long itv)
{
    if ((value2 < value1) && (value1 <= 0xffffffff)) {
        /* Counter's type was unsigned long and has overflown */
        return ((double)((value2 - value1) & 0xffffffff)) / itv * cpu_hz;
    } else {
        return S_VALUE(value1, value2, itv);
    }
}

static void write_disk_stat_header(void)
{
    printf("Device:          r/s       w/s      rkB/s      wkB/s     avgrq-sz "
        "avgqu-sz     r_await     w_await       await       svctm  %%util  poll-n\n");
}

static uint64_t check_value(uint64_t prev, uint64_t current)
{
    return (prev > current) ? current : prev;
}

/**
 * Display stats.
 *
 * IN:
 * @itv     Interval of time.
 * @current Current sample statistics.
 * @prev    Previous sample statistics.
 * */
static void write_stat(unsigned long long itv, const struct io_stats *current, struct io_stats *prev)
{
    uint64_t cpu_ticks;
    double arqsz = 0.0;
    double io_outstanding = 0.0;
    double rd_latency = 0.0;
    double wr_latency = 0.0;
    double rw_latency = 0.0;
    bool rd_latency_zero = true;
    bool wr_latency_zero = true;
    double svctm = 0.0;
    double util = 0.0;
    double read_s = 0.0;
    double write_s = 0.0;
    double read_kb_s = 0.0;
    double write_kb_s = 0.0;
    double tput = 0.0;
    double num_poll_timeout = 0.0;

    /* Get cpu frequency per second */
    cpu_ticks = get_tsc_freq_local();

    /* Valid data current must be lager than prev. Otherwise it means that the
     * residual data in the last shared memory is read, reset the prev data */
    prev->rd_ios = check_value(prev->rd_ios, current->rd_ios);
    prev->wr_ios = check_value(prev->wr_ios, current->wr_ios);
    prev->rd_ticks = check_value(prev->rd_ticks, current->rd_ticks);
    prev->wr_ticks = check_value(prev->wr_ticks, current->wr_ticks);
    prev->rd_bytes = check_value(prev->rd_bytes, current->rd_bytes);
    prev->wr_bytes = check_value(prev->wr_bytes, current->wr_bytes);
    prev->tot_ticks = check_value(prev->tot_ticks, current->tot_ticks);
    prev->num_poll_timeout = check_value(prev->num_poll_timeout, current->num_poll_timeout);

    if (((current->rd_ios + current->wr_ios) - (prev->rd_ios + prev->wr_ios)) != 0) {
        arqsz = ((current->rd_bytes - prev->rd_bytes) + (current->wr_bytes - prev->wr_bytes)) /
                 ((double)((current->rd_ios + current->wr_ios) - (prev->rd_ios + prev->wr_ios)));
    }

    /* Calculate read IO latency and write IO latency (use microseconds) */
    if ((current->rd_ios - prev->rd_ios) != 0 && cpu_ticks != 0) {
        rd_latency = (double)(current->rd_ticks - prev->rd_ticks) / (current->rd_ios - prev->rd_ios) / (double)
                        cpu_ticks * 1000000.0; /* 1000000.0 means the microseconds in one second */
        rd_latency_zero = false;
    }

    if ((current->wr_ios - prev->wr_ios) != 0 && cpu_ticks != 0) {
        wr_latency = (double)(current->wr_ticks - prev->wr_ticks) / (current->wr_ios - prev->wr_ios) / (double)
                        cpu_ticks * 1000000.0; /* 1000000.0 means the microseconds in one second */
        wr_latency_zero = false;
    }

    if (!rd_latency_zero || !wr_latency_zero) {
        rw_latency = ((current->rd_ios - prev->rd_ios) * rd_latency + (current->wr_ios - prev->wr_ios) *
                      wr_latency) /
                     ((current->rd_ios - prev->rd_ios) + (current->wr_ios - prev->wr_ios));
        io_outstanding = (double)current->io_outstanding;
        read_s = S_VALUE(prev->rd_ios, current->rd_ios, itv);
        write_s = S_VALUE(prev->wr_ios, current->wr_ios, itv);
        read_kb_s = ll_s_value(prev->rd_bytes, current->rd_bytes, itv) / 1024.0; /* 1 kB = 1024.0 bytes */
        write_kb_s = ll_s_value(prev->wr_bytes, current->wr_bytes, itv) / 1024.0; /* 1 kB = 1024.0 bytes */
        tput = (double)((current->wr_ios + current->rd_ios) - (prev->wr_ios + prev->rd_ios)) * cpu_hz / itv;
        if (cpu_ticks != 0) {
            /* util is the device usage */
            util = (((double)(current->tot_ticks - prev->tot_ticks) / cpu_ticks)) /
                                          ((double)itv / cpu_hz) * 100;  /* 100 means 100 persent */
        } else {
            util = 0.0;
        }
        /* svctm is single io usage time  */
        svctm = (bool)tput ? ((util / 100) * 1000000) / tput : 0.0;  /* /100*1000000 converted to milliseconds  */
        if (util > 100) {    /* if device usage large than 100, make it reset as 100% */
            util = 100.0;    /* 100.0 indicates 100% use */
        }
        if (current->poll_time_used) {
            num_poll_timeout = (double)(current->num_poll_timeout - prev->num_poll_timeout);
        }
    }

    /*      DEV   r/s   w/s  rKB/s  wKB/s  rqsz  qusz r_await(usec) w_await(usec) svctm util(%) poll/s     */
    if (current->poll_time_used) {
        printf("%-10s%10.2f%10.2f %10.2f %10.2f%13.2f%9.2f %11.2f %11.2f %11.2f %11.2f%7.2f %7.0f\n",
           &(current->dev_name[0]),
           read_s,
           write_s,
           read_kb_s,
           write_kb_s,
           arqsz,
           io_outstanding,
           rd_latency,
           wr_latency,
           rw_latency,
           svctm,
           util,
           num_poll_timeout);
    } else {
        printf("%-10s%10.2f%10.2f %10.2f %10.2f%13.2f%9.2f %11.2f %11.2f %11.2f %11.2f%7.2f\n",
           &(current->dev_name[0]),
           read_s,
           write_s,
           read_kb_s,
           write_kb_s,
           arqsz,
           io_outstanding,
           rd_latency,
           wr_latency,
           rw_latency,
           svctm,
           util);
    }
}

static void display_all_iostat(int curr, unsigned long long itv)
{
    unsigned int i;
    struct io_stats *ioi = NULL;
    struct io_stats *ioj = NULL;
    unsigned int tmpcurr;

    for (i = 0; i < STAT_MAX_NUM; i++) {
        if (0 != strlen((st_iodev[curr] + i)->dev_name)) {
            ioi = st_iodev[curr] + i;
            tmpcurr = (curr == 0 ? 1 : 0);
            ioj = st_iodev[tmpcurr] + i;

            write_stat(itv, ioi, ioj);
        }
    }
    printf("\n");
}

static void display_onedev_iostat(int curr, unsigned long long itv)
{
    unsigned int i;
    int dev;
    struct io_stats *ioi = NULL;
    struct io_stats *ioj = NULL;
    unsigned int tmpcurr;

    for (i = 0; i < STAT_MAX_NUM; i++) {
        for (dev = 0; dev < dlist_idx; dev++) {
            if (!strcmp(dev_list[dev], (st_iodev[curr] + i)->dev_name)) {
                break;
            }
        }
        if (dev == dlist_idx) {
            /* Device not found in list: Do not display it. */
            continue;
        }

        /* if found the device in list, get the current sample statistics and the previous sample statistics. */
        ioi = st_iodev[curr] + i;
        tmpcurr = (curr == 0 ? 1 : 0);
        ioj = st_iodev[tmpcurr] + i;

        write_stat(itv, ioi, ioj);
    }

    printf("\n");
}

/*
 * Print I/O statistics.
 *
 * IN:
 * @curr     Index in array for current sample statistics.
 * @rectime  Current date and time. */
static void write_stats(int curr, struct tm *rectime)
{
    unsigned long long itv;
    unsigned int tmpcurr;
    char timestamp[64]; /* 64 bytes of time stamp tmp buf */

    if (rectime == NULL) {
        return;
    }
    /* Print time stamp */
    strftime(timestamp, sizeof(timestamp), "%x %X", rectime);
    printf("%s\n", timestamp);

    /* Get interval. If first time, uptime[!curr]=0 when displaying stats since system startup. */
    tmpcurr = (curr == 0 ? 1 : 0);
    itv = uptime[curr] - uptime[tmpcurr];
    if (itv == 0) {
        itv = 1;
    }

    /* Display disk stats header */
    write_disk_stat_header();

    if (!(flags & I_D_DEVICENAME)) {
        /* Do not entered device name on the command line, display all devices I/O stats. */
        display_all_iostat(curr, itv);
        return;
    }
    /* A device name was entered on the command line, display the device I/O stats. */
    display_onedev_iostat(curr, itv);
}

/**
 * Main loop: Read I/O stats from share memory and display them.
 *
 * IN:
 * @count    Number of lines of stats to print.
 * @rectime  Current date and time.
 *
 **/
static void io_stat_loop(long count_t, struct tm *rectime)
{
    int curr = 1;
    long tmpCount = count_t;

    setbuf(stdout, NULL);

    do {
        /* Get dev_nr. */
        dev_nr = get_dev_nr();
        if (dev_nr == 0) {
            printf("You cannot get iostat info for nvme device no deliver io!\n");
            return;
        }

        /* Clear last data. */
        clear_st_iodev(curr);

        /* Read system uptime. */
        read_uptime(&(uptime[curr]));

        /* read all devices I/O stats from share memory. */
        read_all_diskstats_stat(curr);

        /* Get time */
        (void)get_localtime(rectime);

        /* Print results */
        write_stats(curr, rectime);

        if (tmpCount > 0) {
            tmpCount--;
        }
        if (tmpCount != 0) {
            curr ^= 1;
            if (interval >= SLEEP_MIN && interval <= SLEEP_MAX) {
                sleep((unsigned int)interval);
            } else {
                sleep(SLEEP_MAX);
            }
        }
    } while (tmpCount != 0);
}

static void parse_arg_d(const char *cmd_name)
{
    char *t = NULL;
    char *nextstr = NULL;
    int rc;

    if (cmd_name == NULL) {
        return;
    }

    dlist_idx = 0;
    for (t = strtok_s(optarg, ",", &nextstr); t; t = strtok_s(NULL, ",", &nextstr)) {
        if (strncasecmp(t, "nvme", 4) != 0) { /* 4 is length of nvme */
            usage(cmd_name);
        }
        rc = strncpy_s(dev_list[dlist_idx], sizeof(dev_list[dlist_idx]), t,
                       sizeof(dev_list[dlist_idx]) - 1);
        if (rc != 0) {
            return;
        }
        dlist_idx++;
    }
}

static void parse_args(int argc, char * const * argv)
{
    int opt;
    const char *op_str = "t:i:d:";

    if (argv == NULL) {
        return;
    }

    opt = getopt(argc, argv, op_str);
    for (; opt != -1; opt = getopt(argc, argv, op_str)) {
        switch (opt) {
            case 't':
                interval = atoi(optarg);
                if (interval <= 0) {
                    usage(argv[0]);
                }
                break;

            case 'i':
                count = atol(optarg);
                if (count <= 0) {
                    usage(argv[0]);
                }
                break;

            case 'd':
                flags |= I_D_DEVICENAME;
                parse_arg_d(argv[0]);
                break;

            default:
                usage(argv[0]);
        }
    }
}

/**
 * Main entry to the libstorage iostat program.
 * Display IO statistics information for libstorage Userspace IO stack.
 */
int main(int argc, char **argv)
{
    struct tm starttime;
    struct utsname header;

    /* mmap share memory */
    if (mmap_sharemem() < 0) {
        exit(1);
    }

    /* Get CPU HZ */
    get_cpu_hz();

    /* parse parameter */
    parse_args(argc, argv);

    /* initial iostat struct */
    io_sys_init();

    /* show statistics data */
    (void)get_localtime(&starttime);

    /* Get system name, release number and hostname */
    (void)uname(&header);

    /* print banner */
    print_header(&starttime, header.sysname, header.release, header.nodename, header.machine);
    printf("\n");

    /* main loop */
    io_stat_loop(count, &starttime);

    /* free structures */
    io_sys_free();

    return 0;
}
