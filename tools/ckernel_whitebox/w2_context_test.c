// SPDX-License-Identifier: GPL-2.0-only
/* Isolated-guest context conversion regression, not a performance benchmark. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define FILES 384
#define THREADS 16
static char names[FILES][96];
static char *expected[FILES];
static pthread_barrier_t barrier;
static int active_files;

static void *reader(void *argument)
{
    unsigned long seed = (unsigned long)argument;
    pthread_barrier_wait(&barrier);
    for (int i = 0; i < 3000; i++) {
        unsigned int n = (i * 17 + seed) % active_files;
        char *context = NULL;
        int rc = getfilecon_raw(names[n], &context);
        int bad = rc < 0 || !context || strcmp(context, expected[n]);
        freecon(context);
        if (bad) return (void *)1;
    }
    return NULL;
}

static int phase(int count, int reload)
{
    pthread_t threads[THREADS];
    active_files = count;
    if (pthread_barrier_init(&barrier, NULL, THREADS + 1)) return 1;
    for (unsigned long i = 0; i < THREADS; i++)
        if (pthread_create(&threads[i], NULL, reader, (void *)i)) _exit(2);
    pthread_barrier_wait(&barrier);
    int failed = 0;
    if (reload) {
        pid_t child = fork();
        if (child == 0) { execl("/sbin/load_policy", "load_policy", NULL); _exit(127); }
        int status = 0;
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status)) failed = 1;
    }
    for (int i = 0; i < THREADS; i++) {
        void *status;
        if (pthread_join(threads[i], &status) || status) failed = 1;
    }
    pthread_barrier_destroy(&barrier);
    printf("W2_CONTEXT phase=%s result=%s reads=%d contexts=%d\n",
           reload ? "policy_reload" : count == FILES ? "churn" : "hits",
           failed ? "FAIL" : "PASS", THREADS * 3000, count);
    return failed;
}

int main(void)
{
    if (security_getenforce() != 1) return 1;
    if (mkdir("/tmp/ckwb-context", 0700)) return 1;
    for (int i = 0; i < FILES; i++) {
        snprintf(names[i], sizeof(names[i]), "/tmp/ckwb-context/file-%d", i);
        int fd = open(names[i], O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0) return 1;
        close(fd);
        char label[96];
        snprintf(label, sizeof(label), "system_u:object_r:container_file_t:s0:c%d", i);
        if (setfilecon_raw(names[i], label) || getfilecon_raw(names[i], &expected[i]) < 0) {
            perror("context setup"); return 1;
        }
    }
    errno = 0;
    if (security_check_context_raw("invalid-context") != -1 || errno != EINVAL) return 1;
    /* Native privileged relabel can preserve an unmapped context. It must not
     * become a cached permission allow or a silently different output. */
    if (setfilecon_raw(names[0], "invalid-context")) return 1;
    char *check = NULL;
    if (getfilecon_raw(names[0], &check) < 0 || strcmp(check, "invalid-context")) return 1;
    freecon(check);
    if (setfilecon_raw(names[0], expected[0])) return 1;
    puts("W2_CONTEXT invalid_context=PASS native_privileged_unmapped_roundtrip=1");
    int failed = phase(4, 0);
    failed |= phase(FILES, 0);
    failed |= phase(FILES, 1);
    for (int i = 0; i < FILES; i++) {
        freecon(expected[i]);
        if (unlink(names[i])) failed = 1;
    }
    if (rmdir("/tmp/ckwb-context") || security_getenforce() != 1) failed = 1;
    printf("W2_CONTEXT_END failures=%d\n", failed);
    return failed;
}
