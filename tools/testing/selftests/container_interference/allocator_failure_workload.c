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
#include "../../../../include/uapi/linux/cis_alloc_test.h"

static int mark_task(int fd, int armed)
{
	char value = armed ? '1' : '0', actual[16] = {};
	if (pwrite(fd, &value, 1, 0) != 1 || pread(fd, actual, sizeof(actual) - 1, 0) < 1)
		return -1;
	return atoi(actual) == armed ? 0 : -1;
}

int main(int argc, char **argv)
{
	struct timespec deadline;
	unsigned long long start;
	int actor, fd, mark, bulk, cache, i, rc;
	if (argc != 4) return 2;
	start = strtoull(argv[2], NULL, 10);
	actor = atoi(argv[3]);
	if (!start || actor < 0 || actor > 1 ||
	    (strcmp(argv[1], "single") && strcmp(argv[1], "bulk") &&
	     strcmp(argv[1], "private") && strcmp(argv[1], "bystander") &&
	     strcmp(argv[1], "recovery"))) return 2;
	bulk = !strcmp(argv[1], "bulk");
	cache = !strcmp(argv[1], "private") && actor == 1;
	fd = open("/dev/cis-alloc-test", O_RDWR | O_CLOEXEC);
	mark = open("/proc/self/make-it-fail", O_RDWR | O_CLOEXEC);
	if (fd < 0 || mark < 0 || mark_task(mark, 0)) { perror("failure setup"); return 3; }
	deadline.tv_sec = start / 1000000000ULL;
	deadline.tv_nsec = start % 1000000000ULL;
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); }
	while (rc == EINTR);
	if (rc) return 3;
	for (i = 0; i < 8; i++) {
		struct cis_alloc_test_request q = { .action = CIS_AT_ALLOC, .cache = cache,
			.count = bulk ? 8 : 1, .bulk = bulk };
		struct cis_alloc_test_request freeq = { .action = CIS_AT_FREE, .cache = cache, .bulk = bulk };
		int armed = strcmp(argv[1], "bystander") || actor == 0;
		unsigned int j;
		if (!strcmp(argv[1], "recovery")) armed = !(i & 1);
		if (mark_task(mark, armed)) return 4;
		rc = ioctl(fd, CIS_ALLOC_TEST_RUN, &q);
		/* Restore this task before output, cleanup, or the next operation. */
		if (mark_task(mark, 0) || rc) { perror("failure allocation"); return 5; }
		if (q.returned && ioctl(fd, CIS_ALLOC_TEST_RUN, &freeq)) return 6;
		printf("CIS_ALLOC_FAILURE index=%d armed=%d cache=%d bulk=%d count=%u returned=%u result=%d cpu=%u cache_address=%llu begin_ns=%llu end_ns=%llu release_begin_ns=%llu release_end_ns=%llu\n",
		       i, armed, cache, bulk, q.count, q.returned, rc, q.cpu,
		       (unsigned long long)q.cache_address, (unsigned long long)q.begin_ns,
		       (unsigned long long)q.end_ns, (unsigned long long)freeq.begin_ns,
		       (unsigned long long)freeq.end_ns);
		for (j = 0; j < q.returned && j < CIS_AT_MAX; j++)
			printf("CIS_ALLOC_FAILURE_OBJECT index=%d ordinal=%u object=%llu\n",
			       i, j, (unsigned long long)q.objects[j]);
		if (q.returned != ((armed && !cache) ? 0 : q.count) ||
		    freeq.returned != q.returned) return 7;
		usleep(5000);
	}
	if (mark_task(mark, 0) || close(mark) || close(fd)) return 8;
	return 0;
}
