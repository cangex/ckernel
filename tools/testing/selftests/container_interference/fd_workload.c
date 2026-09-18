// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "fixture/uapi.h"

#define OPERATIONS 16
struct worker {
	int cpu, fd, native, error;
	uint64_t start;
	struct cis_fixture_fd truth[OPERATIONS];
};

static void *run(void *arg)
{
	struct worker *w = arg;
	cpu_set_t cpus;
	struct timespec deadline = { .tv_sec = w->start / 1000000000,
		.tv_nsec = w->start % 1000000000 };
	CPU_ZERO(&cpus); CPU_SET(w->cpu, &cpus);
	if (sched_setaffinity(0, sizeof(cpus), &cpus)) {
		w->error = errno; return NULL;
	}
	int rc;
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (rc == EINTR);
	if (rc) { w->error = rc; return NULL; }
	for (int i = 0; i < OPERATIONS; i++) {
		if (w->native) {
			int fd = open("/dev/null", O_RDONLY | O_CLOEXEC), copy;
			if (fd < 0) { w->error = errno; return NULL; }
			copy = dup(fd);
			if (copy < 0) { w->error = errno; close(fd); return NULL; }
			if (fcntl(copy, F_SETFD, FD_CLOEXEC) || close(copy) || close(fd)) {
				w->error = errno; return NULL;
			}
		} else {
			w->truth[i].hold_us = 100;
			if (ioctl(w->fd, CIS_FIXTURE_FD, &w->truth[i])) {
				w->error = errno; return NULL;
			}
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc != 5) return 2;
	int threads = atoi(argv[1]), cpu = atoi(argv[2]), native = atoi(argv[4]);
	uint64_t start = strtoull(argv[3], NULL, 10);
	if (threads < 1 || threads > 2 || cpu < 0 || cpu + threads > 8 ||
	    !start || (native != 0 && native != 1)) return 2;
	int fd = native ? -1 : open("/dev/cis-fixture", O_RDWR | O_CLOEXEC);
	if (!native && fd < 0) { perror("fixture"); return 1; }
	struct worker workers[2] = {0}; pthread_t ids[2];
	for (int i = 0; i < threads; i++) {
		workers[i] = (struct worker){ .cpu = cpu+i, .fd = fd, .native = native, .start = start };
		if (pthread_create(&ids[i], NULL, run, &workers[i])) return 1;
	}
	int failed = 0;
	for (int i = 0; i < threads; i++) {
		if (pthread_join(ids[i], NULL)) return 1;
		if (workers[i].error) { fprintf(stderr,"worker error=%d\n",workers[i].error); failed = 1; }
		if (!native && !workers[i].error) for (int j = 0; j < OPERATIONS; j++) {
			struct cis_fixture_fd *q = &workers[i].truth[j];
			printf("CIS_FD_TRUTH {\"object\":%llu,\"files\":%llu,\"tid\":%llu,\"tgid\":%llu,\"cgroup_id\":%llu,\"begin_ns\":%llu,\"acquired_ns\":%llu,\"release_begin_ns\":%llu,\"released_ns\":%llu}\n",
			       q->object,q->files,q->tid,q->tgid,q->cgroup_id,q->begin_ns,q->acquired_ns,q->release_begin_ns,q->released_ns);
		}
	}
	if (fd >= 0 && close(fd)) failed = 1;
	printf("CIS_FD_DONE {\"threads\":%d,\"operations_per_thread\":%d,\"native\":%d,\"failed\":%d}\n", threads, OPERATIONS, native, failed);
	return failed;
}
