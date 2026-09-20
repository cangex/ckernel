// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "page_fixture/uapi.h"

int main(int argc, char **argv)
{
	uint64_t start, pages = CIS_PAGE_SMALL + (CIS_PAGE_LARGE << CIS_PAGE_ORDER);
	struct timespec deadline;
	unsigned int i;
	int err, fd;
	if (argc != 2) return 2;
	start = strtoull(argv[1], NULL, 10);
	deadline.tv_sec = start / 1000000000ULL;
	deadline.tv_nsec = start % 1000000000ULL;
	fd = open("/dev/cis-page-test", O_RDWR | O_CLOEXEC);
	if (fd < 0) return 3;
	do { err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (err == EINTR);
	if (err) return 4;
	for (i = 0; i < 4; i++) {
		struct cis_page_test q = { .version = 1, .node = 0 };
		if (ioctl(fd, CIS_PAGE_TEST, &q) || q.failed || q.wrong_node ||
		    q.pages_allocated != pages || q.pages_freed != pages) return 5;
		printf("CIS_MEM_OP index=%u begin_ns=%llu end_ns=%llu bytes=%llu success=1\n",
			i, (unsigned long long)q.begin_ns, (unsigned long long)q.end_ns,
			(unsigned long long)(pages * sysconf(_SC_PAGESIZE)));
		printf("CIS_PAGE_TRUTH index=%u node=%u allocated=%llu freed=%llu failed=%u wrong_node=%u\n",
			i, q.node, (unsigned long long)q.pages_allocated, (unsigned long long)q.pages_freed,
			q.failed, q.wrong_node);
		usleep(2000);
	}
	return close(fd) ? 6 : 0;
}
