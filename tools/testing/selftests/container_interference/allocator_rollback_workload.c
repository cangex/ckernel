// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "allocator_fixture/rollback_uapi.h"

static int mark_task(int fd, int armed)
{
	char value = armed ? '1' : '0', actual[16] = {};
	if (pwrite(fd, &value, 1, 0) != 1 || pread(fd, actual, sizeof(actual)-1, 0) < 1)
		return -1;
	return atoi(actual) == armed ? 0 : -1;
}

int main(int argc, char **argv)
{
	struct timespec deadline;
	unsigned long long start;
	int fd, mark, actor, action, rc;
	if (argc != 4 || (strcmp(argv[1], "partial") && strcmp(argv[1], "unmarked"))) return 2;
	start = strtoull(argv[2], NULL, 10); actor = atoi(argv[3]);
	if (!start || actor < 0 || actor > 1) return 2;
	fd = open("/dev/cis-alloc-test", O_RDWR | O_CLOEXEC);
	mark = open("/proc/self/make-it-fail", O_RDWR | O_CLOEXEC);
	if (fd < 0 || mark < 0 || mark_task(mark, 0)) return 3;
	deadline.tv_sec = start / 1000000000ULL; deadline.tv_nsec = start % 1000000000ULL;
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (rc == EINTR);
	if (rc) return 3;
	/* PREPARE, first bulk, unmarked recovery bulk, DRAIN. */
	for (action = 0; action < 4; action++) {
		struct cis_alloc_rollback q = { .version = 1, .action = action == 0 ? 1 : action == 3 ? 3 : 2,
			.cache = actor };
		int armed = !strcmp(argv[1], "partial") && actor == 0 && action == 1;
		unsigned int j;
		if (mark_task(mark, armed)) return 4;
		rc = ioctl(fd, CIS_ALLOC_ROLLBACK, &q);
		if (mark_task(mark, 0) || rc) return 5;
		printf("CIS_ALLOC_ROLLBACK index=%d action=%u cache=%u armed=%d returned=%u populated=%u cpu=%u cache_address=%llu begin_ns=%llu end_ns=%llu",
			action, q.action, q.cache, armed, q.returned, q.populated, q.cpu,
			(unsigned long long)q.cache_address, (unsigned long long)q.begin_ns, (unsigned long long)q.end_ns);
		for (j = 0; j < CIS_AR_COUNT; j++) printf(" object%u=%llu", j, (unsigned long long)q.objects[j]);
		putchar('\n'); fflush(stdout);
		if (q.action == 2 && (armed ? q.returned || !q.populated || q.populated >= CIS_AR_COUNT :
			q.returned != CIS_AR_COUNT || q.populated != CIS_AR_COUNT)) return 6;
	}
	if (mark_task(mark, 0) || close(mark) || close(fd)) return 7;
	return 0;
}
