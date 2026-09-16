// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    const char *cg = "/sys/fs/cgroup/cis-s0";
    if (mkdir(cg, 0700)) { perror("mkdir cgroup"); return 1; }
    char *args[] = { "/workload", "identity", NULL };
    pid_t pid = cis_container_start(cg, "/container-root", args, 1);
    int rc = cis_container_wait(pid);
    if (rmdir(cg)) { perror("rmdir cgroup"); rc = 1; }
    printf("CIS_S0_CONTAINER %s\n", rc ? "FAIL" : "PASS");
    return rc;
}
