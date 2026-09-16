// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct utsname un;
    char cg[512] = {0}, link[128];
    int fd = open("/proc/self/cgroup", O_RDONLY);
    if (fd < 0 || read(fd, cg, sizeof(cg)-1) < 0) return 1;
    close(fd);
    if (uname(&un)) return 1;
    ssize_t n = readlink("/proc/self/ns/mnt", link, sizeof(link)-1);
    if (n < 0) return 1;
    link[n] = 0;
    if (getpid() != 1 || strcmp(un.nodename, "cis-container")) return 2;
    fd = open("/must-not-write", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0 || errno != EROFS) return 3;
    printf("CIS_CONTAINER pid=%d host=%s mnt=%s cgroup=%s", getpid(), un.nodename, link, cg);
    fflush(stdout);
    if (argc < 2 || !strcmp(argv[1], "identity")) return 0;
    unsigned seconds = argc > 2 ? strtoul(argv[2], NULL, 10) : 2;
    if (!seconds || seconds > 300) return 4;
    uint64_t start = cis_now_ns(), end = start + seconds * 1000000000ULL, ops = 0;
    do {
        for (unsigned i = 0; i < 256; i++) {
            struct stat st;
            fd = open("/sample", O_RDONLY | O_CLOEXEC);
            if (fd < 0 || fstat(fd, &st) || close(fd)) return 5;
            ops++;
        }
    } while (cis_now_ns() < end);
    uint64_t finish = cis_now_ns();
    printf("CIS_RESULT operations=%" PRIu64 " start_ns=%" PRIu64 " end_ns=%" PRIu64 " errors=0\n", ops, start, finish);
    return 0;
}
