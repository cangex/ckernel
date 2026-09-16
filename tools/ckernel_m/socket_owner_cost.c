// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../../include/uapi/linux/ckernel_m.h"

#define OPS 20000
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "owner_cost:%d %s errno=%d\n", \
	__LINE__, #x, errno); return 1; } } while (0)
static uint64_t samples[OPS];

static uint64_t ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t)) abort();
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static int compare(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static long cpu_us(struct rusage *r)
{
	return (r->ru_utime.tv_sec + r->ru_stime.tv_sec) * 1000000L +
		r->ru_utime.tv_usec + r->ru_stime.tv_usec;
}

int main(void)
{
	const int counts[] = { 0, 16, 128 };
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_NET };
	int handles[128], round, selected, n, k, j, ctl;
	cpu_set_t cpus;

	CHECK(getenv("CKM_ISOLATED_GUEST"));
	CPU_ZERO(&cpus); CPU_SET(0, &cpus);
	CHECK(!sched_setaffinity(0, sizeof(cpus), &cpus));
	ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	CHECK(ctl >= 0);
	for (round = 1; round <= 3; round++)
	for (selected = 0; selected < 3; selected++) {
		uint64_t start, end, management = 0;
		struct rusage before, after;
		n = counts[round & 1 ? selected : 2 - selected];
		for (k = 0; k < n; k++) {
			struct ckm_net_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
			handles[k] = ioctl(ctl, CKM_IOC_CREATE, &r);
			CHECK(handles[k] >= 0 && !ioctl(handles[k], CKM_IOC_NET_QUERY, &q));
			management += q.management_bytes;
		}
		/* Deliberately never BIND: measure a nonparticipant's native sockets. */
		CHECK(!getrusage(RUSAGE_SELF, &before));
		start = ns();
		for (j = 0; j < OPS; j++) {
			uint64_t a = ns();
			int fd = socket(AF_INET, SOCK_DGRAM, 0);
			CHECK(fd >= 0 && !close(fd));
			samples[j] = ns() - a;
		}
		end = ns();
		CHECK(!getrusage(RUSAGE_SELF, &after));
		qsort(samples, OPS, sizeof(samples[0]), compare);
		printf("CKM_NET_OWNER_COST round=%d idle_instances=%d operations=%d duration_ns=%llu p50_ns=%llu p95_ns=%llu p99_ns=%llu max_ns=%llu cpu_us=%ld management_bytes=%llu\n",
		       round, n, OPS, (unsigned long long)(end-start),
		       (unsigned long long)samples[OPS/2], (unsigned long long)samples[OPS*95/100],
		       (unsigned long long)samples[OPS*99/100], (unsigned long long)samples[OPS-1],
		       cpu_us(&after)-cpu_us(&before), (unsigned long long)management);
		for (k = 0; k < n; k++) {
			CHECK(!ioctl(handles[k], CKM_IOC_REVOKE, 0));
			for (j = 0; j < 1000; j++) {
				struct ckm_net_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
				CHECK(!ioctl(handles[k], CKM_IOC_NET_QUERY, &q));
				CHECK(!q.live && !q.retiring);
				if (q.stopped) break;
				usleep(10000);
			}
			CHECK(j < 1000 && !close(handles[k]));
		}
		/* A delay is not proof of complete background reclamation. */
		sleep(1);
	}
	CHECK(!close(ctl));
	puts("CKM_NET_OWNER_END failures=0");
	return 0;
}
