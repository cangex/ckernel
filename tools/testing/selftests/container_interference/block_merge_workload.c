// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include "block_fixture/merge_uapi.h"

static unsigned long long now(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) exit(3);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	struct cis_merge_test job = {};
	unsigned long long start, begin, end;
	int fd, rc;
	if (argc != 6) return 2;
	fd = atoi(argv[1]); job.role = atoi(argv[2]); start = strtoull(argv[3], NULL, 10);
	job.count = atoi(argv[4]); job.pattern = atoi(argv[5]);
	struct timespec ts = { .tv_sec = start / 1000000000ULL, .tv_nsec = start % 1000000000ULL };
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL); } while (rc == EINTR);
	if (rc) return 3;
	begin = now(); rc = ioctl(fd, CIS_MERGE_RUN, &job); end = now();
	printf("CIS_MERGE_JOB role=%u count=%u pattern=%u begin_ns=%llu end_ns=%llu rc=%d requests=%u completed=%u errors=%u verified=%u\n",
	       job.role, job.count, job.pattern, begin, end, rc, job.requests, job.completed, job.errors, job.verified);
	if (rc || job.requests > CIS_MERGE_MAX || job.completed != job.count || job.errors || !job.verified) return 4;
	for (unsigned i = 0; i < job.requests; i++) {
		struct cis_merge_truth *t = &job.truth[i];
		printf("CIS_MERGE_RQ request=%llu begin_ns=%llu end_ns=%llu bytes=%u bios=%u\n",
		       (unsigned long long)t->request, (unsigned long long)t->begin_ns,
		       (unsigned long long)t->end_ns, t->bytes, t->bios);
	}
	return 0;
}
