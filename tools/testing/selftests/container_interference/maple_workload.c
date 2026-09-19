// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "maple_fixture/uapi.h"

int main(int argc, char **argv)
{
	unsigned int cycle, action, cpu;
	unsigned long long start;
	struct timespec deadline;
	int fd, error;
	if (argc != 3) return 2;
	start = strtoull(argv[1], NULL, 10); cpu = strtoul(argv[2], NULL, 10);
	if (cpu > 1) return 2;
	fd = open("/dev/cis-maple-test", O_RDWR | O_CLOEXEC);
	if (fd < 0) return 3;
	deadline.tv_sec = start / 1000000000ULL; deadline.tv_nsec = start % 1000000000ULL;
	do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); } while (error == EINTR);
	if (error) return 4;
	for (cycle = 0; cycle < 2; cycle++) {
		for (action = 1; action <= 4; action++) {
			struct cis_maple_truth q = { .version = 1, .action = action };
			cpu_set_t mask;
			CPU_ZERO(&mask); CPU_SET(cpu + (action == 3 ? 2 : 0), &mask);
			if (sched_setaffinity(0, sizeof(mask), &mask)) return 5;
			if (ioctl(fd, CIS_MAPLE_TRUTH, &q)) { perror("maple truth"); return 6; }
			printf("CIS_MAPLE_TRUTH cycle=%u action=%u begin_ns=%llu end_ns=%llu tree0=%llu tree1=%llu generation=%llu cpu=%u verified=%u\n",
				cycle, action, (unsigned long long)q.begin_ns, (unsigned long long)q.end_ns,
				(unsigned long long)q.tree[0], (unsigned long long)q.tree[1],
				(unsigned long long)q.generation, q.cpu, q.verified);
		}
	}
	return close(fd) ? 7 : 0;
}
