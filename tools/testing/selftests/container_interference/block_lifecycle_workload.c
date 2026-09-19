// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include "block_fixture/lifecycle_uapi.h"

static unsigned long long now(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) exit(3);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	struct cis_lifecycle_test job = {};
	unsigned long long start, begin, end;
	int rc;
	if (argc != 5) return 2;
	job.role = atoi(argv[2]); start = strtoull(argv[3], NULL, 10);
	job.scenario = atoi(argv[4]);
	struct timespec ts = { .tv_sec = start / 1000000000ULL, .tv_nsec = start % 1000000000ULL };
	do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL); } while (rc == EINTR);
	if (rc) return 3;
	begin = now(); rc = ioctl(atoi(argv[1]), CIS_LIFECYCLE_RUN, &job); end = now();
	printf("CIS_LIFECYCLE_JOB role=%u scenario=%u begin_ns=%llu end_ns=%llu rc=%d original_bio=%llu bytes=%u requests=%u completed=%u io_errors=%u canceled=%u verified=%u\n",
	       job.role, job.scenario, begin, end, rc, (unsigned long long)job.original_bio,
	       job.bytes, job.requests, job.completed, job.io_errors, job.canceled, job.verified);
	if (rc || job.requests > CIS_LIFECYCLE_MAX || !job.verified) return 4;
	if (job.scenario >= 4)
		printf("CIS_LIFECYCLE_INFLIGHT submit_return_ns=%llu finish_begin_ns=%llu finish_end_ns=%llu pending_seen=%u started_seen=%u\n",
		       (unsigned long long)job.submit_return_ns, (unsigned long long)job.finish_begin_ns,
		       (unsigned long long)job.finish_end_ns, job.pending_seen, job.started_seen);
	for (unsigned int i = 0; i < job.requests; i++) {
		struct cis_lifecycle_truth *t = &job.truth[i];
		printf("CIS_LIFECYCLE_RQ request=%llu bio=%llu begin_ns=%llu end_ns=%llu sector=%llu bytes=%u status=%u\n",
		       (unsigned long long)t->request, (unsigned long long)t->bio,
		       (unsigned long long)t->begin_ns, (unsigned long long)t->end_ns,
		       (unsigned long long)t->sector, t->bytes, t->status);
	}
	return 0;
}
