// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    int calls = !strcmp(argv[1], "syscalls");
    if (!calls && strcmp(argv[1], "cpu")) return 2;
    unsigned long seconds = strtoul(argv[2], NULL, 10);
    if (!seconds || seconds > 1100) return 2;
    if (signal(SIGTERM, stop) == SIG_ERR) return 2;
    uint64_t start = strtoull(argv[3], NULL, 10);
    struct timespec ts = {start / 1000000000ULL, start % 1000000000ULL};
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {}
    uint64_t begin = cis_now_ns(), end = begin + seconds * 1000000000ULL, operations = 0;
    volatile uint64_t value = 1;
    do {
        for (unsigned int i = 0; i < 1024; i++) {
            if (calls) {
                if (syscall(SYS_getpid) <= 0) return 3;
            } else value = value * 6364136223846793005ULL + 1;
            operations++;
        }
    } while (!stopped && cis_now_ns() < end);
    printf("CIS_ROUTE_WORK mode=%s begin_ns=%" PRIu64 " end_ns=%" PRIu64
           " operations=%" PRIu64 " value=%" PRIu64 "\n",
           argv[1], begin, cis_now_ns(), operations, value);
    return 0;
}
