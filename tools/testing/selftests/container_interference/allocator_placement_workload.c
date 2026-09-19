// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "allocator_fixture/placement_uapi.h"

int main(int argc, char **argv)
{
	struct timespec deadline;
	unsigned long long start;
	int node, fd, i, rc;
	if (argc != 3) return 2;
	start = strtoull(argv[1], NULL, 10);
	node = atoi(argv[2]);
	if (!start || node < 0 || node > 1) return 2;
	fd = open("/dev/cis-alloc-test", O_RDWR | O_CLOEXEC);
	if (fd < 0) { perror("fixture"); return 3; }
	deadline.tv_sec = start / 1000000000ULL;
	deadline.tv_nsec = start % 1000000000ULL;
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); }
	while (rc == EINTR);
	if (rc) return 3;
	for (i = 0; i < 8; i++) {
		struct cis_alloc_placement q = { .version = 1, .requested_node = node };
		if (ioctl(fd, CIS_ALLOC_PLACEMENT, &q)) { perror("placement"); return 4; }
		printf("CIS_ALLOC_PLACEMENT index=%d requested_node=%d actual_node=%d allowed_node=%u cpu=%u result=%d object=%llu cache=%llu begin_ns=%llu allocated_ns=%llu release_begin_ns=%llu end_ns=%llu\n",
		       i, q.requested_node, q.actual_node, q.allowed_node, q.cpu, q.result,
		       q.object, q.cache_address, q.begin_ns, q.allocated_ns,
		       q.release_begin_ns, q.end_ns);
		if (q.result || !q.object) return 5;
		usleep(5000);
	}
	return close(fd) ? 6 : 0;
}
