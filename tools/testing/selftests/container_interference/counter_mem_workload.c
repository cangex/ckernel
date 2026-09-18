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
	const size_t bytes = 8UL << 20;
	uint64_t start;
	struct timespec deadline;
	long page = sysconf(_SC_PAGESIZE);
	unsigned int i;
	int err;
	if (argc != 2 || page <= 0 || bytes % page) return 2;
	start = strtoull(argv[1], NULL, 10);
	deadline.tv_sec = start / 1000000000ULL;
	deadline.tv_nsec = start % 1000000000ULL;
	do { err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL); }
	while (err == EINTR);
	if (err) return 3;
	for (i = 0; i < 16; i++) {
		uint64_t begin = now(), end;
		size_t j;
		volatile unsigned char *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) return 4;
		for (j = 0; j < bytes; j += page) p[j] = (unsigned char)(i + 1);
		for (j = 0; j < bytes; j += page)
			if (p[j] != (unsigned char)(i + 1)) return 5;
		if (munmap((void *)p, bytes)) return 6;
		end = now();
		printf("CIS_MEM_OP index=%u begin_ns=%llu end_ns=%llu bytes=%zu success=1\n",
			i, (unsigned long long)begin, (unsigned long long)end, bytes);
		usleep(2000);
	}
	return 0;
}
