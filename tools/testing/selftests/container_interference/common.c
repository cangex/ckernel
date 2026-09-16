// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

uint64_t cis_now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

int cis_write_text(const char *path, const char *text)
{
    size_t n = strlen(text);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t written = write(fd, text, n);
    int err = written == (ssize_t)n ? 0 : -(written < 0 ? errno : EIO);
    close(fd);
    return err;
}

struct child_args { int read_fd, write_fd, cpu, output; const char *root; char *const *argv; };
static int child_main(void *ptr)
{
    struct child_args *a = ptr;
    char ch;
    if(a->output>=0 && (dup2(a->output,STDOUT_FILENO)<0 || dup2(a->output,STDERR_FILENO)<0)) return 124;
    close(a->write_fd);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || read(a->read_fd, &ch, 1) != 1) return 120;
    close(a->read_fd);
    if (a->cpu >= 0) {
        cpu_set_t cpus;
        CPU_ZERO(&cpus); CPU_SET(a->cpu, &cpus);
        if (sched_setaffinity(0, sizeof(cpus), &cpus)) return 121;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(a->root, a->root, NULL, MS_BIND, NULL) ||
        mount(NULL, a->root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) ||
        chdir(a->root) || chroot(".") || chdir("/") ||
        mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m") ||
        sethostname("cis-container", 13)) {
        perror("container setup"); return 122;
    }
    execv(a->argv[0], a->argv);
    perror("container exec");
    return 123;
}

pid_t cis_container_start_output(const char *cg, const char *root, char *const argv[], int cpu,int output)
{
    char path[PATH_MAX], pidbuf[32];
    int pipes[2];
    void *stack = malloc(1024 * 1024);
    if (!stack) return -1;
    if (pipe2(pipes, O_CLOEXEC)) { free(stack); return -1; }
    struct child_args a = { pipes[0], pipes[1], cpu, output, root, argv };
    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC |
                CLONE_NEWNET | CLONE_NEWCGROUP | SIGCHLD;
    pid_t pid = clone(child_main, (char *)stack + 1024 * 1024, flags, &a);
    close(pipes[0]);
    if (pid > 0) {
        snprintf(path, sizeof(path), "%s/cgroup.procs", cg);
        snprintf(pidbuf, sizeof(pidbuf), "%d\n", pid);
        if (cis_write_text(path, pidbuf) || write(pipes[1], "!", 1) != 1) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            pid = -1;
        }
    }
    close(pipes[1]);
    free(stack);
    return pid;
}

pid_t cis_container_start(const char *cg, const char *root, char *const argv[], int cpu)
{
    return cis_container_start_output(cg,root,argv,cpu,-1);
}

int cis_container_wait(pid_t pid)
{
    int status;
    if (pid <= 0) return 1;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return 1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
