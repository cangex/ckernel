// SPDX-License-Identifier: GPL-2.0
/* Opt-in VM mechanism probe; no syscall or workload source is replaced. */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 64
static uint64_t ns(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t))
		abort();
	return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static uint64_t cpu_us(struct timeval t)
{
	return (uint64_t)t.tv_sec * 1000000 + t.tv_usec;
}

static int cycle(char *p, size_t page, unsigned int pages)
{
	unsigned int n;

	for (n = 0; n < pages; n += 2)
		if (mprotect(p + n * page, page, PROT_READ))
			return -1;
	return mprotect(p, pages * page, PROT_READ | PROT_WRITE);
}

static int compare(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

int main(void)
{
	const char *mode = getenv("CKM_PROBE_MODE");
	const char *scenario = getenv("CKM_PROBE_SCENARIO");
	const char *round = getenv("CKM_PROBE_ROUND");
	uint64_t samples[ROUNDS], begin, cold, duration;
	struct rusage before, after;
	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	unsigned int pages = 256, n;
	cpu_set_t cpus;
	char *p;
	int rc = 1;

	if (!getenv("CKM_ISOLATED_GUEST") || !mode || !scenario || !round)
		return 4;
	if (!strcmp(scenario, "exhaust"))
		pages = 1024;
	else if (strcmp(scenario, "steady"))
		return 1;
	CPU_ZERO(&cpus);
	CPU_SET(0, &cpus);
	if (sched_setaffinity(0, sizeof(cpus), &cpus))
		return 1;
	p = mmap(NULL, pages * page, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 1;
	begin = ns();
	if (cycle(p, page, pages))
		goto out;
	cold = ns() - begin;
	getrusage(RUSAGE_SELF, &before);
	begin = ns();
	for (n = 0; n < ROUNDS; n++) {
		uint64_t start = ns();

		if (cycle(p, page, pages))
			goto out;
		samples[n] = ns() - start;
	}
	duration = ns() - begin;
	getrusage(RUSAGE_SELF, &after);
	qsort(samples, ROUNDS, sizeof(samples[0]), compare);
	printf("CKM_PROBE mode=%s scenario=%s round=%s cycles=%d pages=%u "
	       "duration_ns=%llu cold_ns=%llu p50_ns=%llu p95_ns=%llu p99_ns=%llu "
	       "user_us=%llu system_us=%llu\n", mode, scenario, round, ROUNDS, pages,
	       (unsigned long long)duration, (unsigned long long)cold,
	       (unsigned long long)samples[ROUNDS / 2 - 1],
	       (unsigned long long)samples[(ROUNDS * 95 + 99) / 100 - 1],
	       (unsigned long long)samples[(ROUNDS * 99 + 99) / 100 - 1],
	       (unsigned long long)(cpu_us(after.ru_utime) - cpu_us(before.ru_utime)),
	       (unsigned long long)(cpu_us(after.ru_stime) - cpu_us(before.ru_stime)));
	rc = 0;
out:
	munmap(p, pages * page);
	return rc;
}
