// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../../../../include/uapi/linux/cis_counter_test.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct cis_counter_test_request r = {0};
	unsigned int i, count;
	unsigned long long start;
	struct timespec deadline;
	int fd;
	if (argc != 8) return 2;
	r.slot = atoi(argv[1]); r.leaf = atoi(argv[2]); r.operation = atoi(argv[3]);
	r.pages = strtoull(argv[4], NULL, 10); count = atoi(argv[5]);
	start = strtoull(argv[6], NULL, 10);
	if (!count || count > 32 || atoi(argv[7]) < 0 || atoi(argv[7]) > 1) return 2;
	fd = open("/dev/cis-counter-test", O_RDWR | O_CLOEXEC);
	if (fd < 0) { perror("counter fixture"); return 3; }
	deadline.tv_sec = start / 1000000000ULL; deadline.tv_nsec = start % 1000000000ULL;
	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL) == EINTR) { }
	for (i = 0; i < count; i++) {
		if (atoi(argv[7])) {
			cpu_set_t mask;
			CPU_ZERO(&mask); CPU_SET(i % 2 ? 2 : 3, &mask);
			if (sched_setaffinity(0, sizeof(mask), &mask)) return 4;
		}
		if (ioctl(fd, CIS_COUNTER_TEST_RUN, &r)) { perror("counter ioctl"); return 5; }
		printf("CIS_COUNTER_TRUTH begin_ns=%llu end_ns=%llu leaf=%llu parent=%llu failed=%llu success=%u final_leaf=%lld final_parent=%lld operation=%u pages=%llu cpu=%d\n",
			(unsigned long long)r.begin_ns, (unsigned long long)r.end_ns,
			(unsigned long long)r.leaf_address, (unsigned long long)r.parent_address,
			(unsigned long long)r.failed_address, r.success, (long long)r.final_leaf,
			(long long)r.final_parent, r.operation, (unsigned long long)r.pages, sched_getcpu());
		usleep(1000);
	}
	close(fd);
	return 0;
}
