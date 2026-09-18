// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static uint64_t now(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(3);
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

int main(int argc, char **argv)
{
	struct timespec deadline;
	uint64_t start;
	long page = sysconf(_SC_PAGESIZE);
	unsigned int i, j;
	int err;
	if (argc != 2 || page <= 0) return 2;
	start = strtoull(argv[1], NULL, 10);
	deadline.tv_sec = start / 1000000000ULL;
	deadline.tv_nsec = start % 1000000000ULL;
	do { err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); }
	while (err == EINTR);
	if (err) return 3;
	for (i = 0; i < 8; i++) {
		uint64_t begin = now();
		size_t bytes = (size_t)page * 256;
		char *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) return 4;
		for (j = 0; j < 256; j += 2)
			if (mprotect(p + j * page, page, PROT_READ)) return 5;
		for (j = 0; j < 256; j += 2)
			if (mprotect(p + j * page, page, PROT_READ | PROT_WRITE)) return 6;
		p[0] = (char)i;
		if (p[0] != (char)i || munmap(p, bytes)) return 7;
		printf("CIS_ALLOC_OP index=%u begin_ns=%llu end_ns=%llu split_regions=128 success=1\n",
			i, (unsigned long long)begin, (unsigned long long)now());
		usleep(2000);
	}
	return 0;
}
