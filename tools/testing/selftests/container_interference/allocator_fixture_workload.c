// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/cis_alloc_test.h"

static int select_cpu(unsigned int cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	return sched_setaffinity(0, sizeof(mask), &mask);
}

static int action(int fd, unsigned int operation, unsigned int cache,
		  unsigned int count, unsigned int bulk, unsigned int index)
{
	struct cis_alloc_test_request r = { .action = operation, .cache = cache,
		.count = count, .bulk = bulk };
	int error = ioctl(fd, CIS_ALLOC_TEST_RUN, &r);
	if (error < 0) { perror("allocator fixture"); return 1; }
	printf("CIS_ALLOC_TRUTH index=%u action=%u cache=%u count=%u bulk=%u begin_ns=%llu end_ns=%llu cache_address=%llu returned=%u cpu=%u result=%d\n",
		index, operation, cache, count, bulk, (unsigned long long)r.begin_ns,
		(unsigned long long)r.end_ns, (unsigned long long)r.cache_address,
		r.returned, r.cpu, error);
	return operation == CIS_AT_ALLOC && r.returned != count;
}

int main(int argc, char **argv)
{
	struct timespec deadline;
	unsigned long long start;
	unsigned int cache, cpu, i, count, bulk, cold, migration;
	int fd, error;
	if (argc != 5) return 2;
	start = strtoull(argv[2], NULL, 10);
	cache = strtoul(argv[3], NULL, 10);
	cpu = strtoul(argv[4], NULL, 10);
	cold = !strcmp(argv[1], "cold");
	migration = !strcmp(argv[1], "migration");
	bulk = !strcmp(argv[1], "bulk") || migration;
	if (!cold && !migration && !bulk && strcmp(argv[1], "warm") && strcmp(argv[1], "private")) return 2;
	if (cache > 1 || cpu > 1 || select_cpu(cpu)) return 2;
	count = bulk ? 8 : cold ? 1 : 4;
	fd = open("/dev/cis-alloc-test", O_RDWR | O_CLOEXEC);
	if (fd < 0) { perror("open fixture"); return 3; }
	deadline.tv_sec = start / 1000000000ULL;
	deadline.tv_nsec = start % 1000000000ULL;
	do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); }
	while (error == EINTR);
	if (error) return 3;
	for (i = 0; i < 4; i++) {
		if (cold && action(fd, CIS_AT_SHRINK, cache, 0, 0, i)) return 4;
		if (select_cpu(cpu) || action(fd, CIS_AT_ALLOC, cache, count, bulk, i)) return 5;
		if (migration && select_cpu(cpu + 2)) return 6;
		if (action(fd, CIS_AT_FREE, cache, 0, bulk, i)) return 7;
		usleep(5000);
	}
	return close(fd) ? 8 : 0;
}
