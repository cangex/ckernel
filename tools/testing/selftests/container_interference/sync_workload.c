// SPDX-License-Identifier: GPL-2.0
/* Executed only through session_launch inside a disposable VM container. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "fixture/uapi.h"

int main(int argc,char **argv)
{
	struct cis_fixture_sync q={0};
	unsigned long family,slot,operation,hold,iterations,i;
	uint64_t start;
	struct timespec deadline;
	int fd,ret;
	if(argc!=7) return 2;
	family=strtoul(argv[1],NULL,10); slot=strtoul(argv[2],NULL,10);
	operation=strtoul(argv[3],NULL,10); hold=strtoul(argv[4],NULL,10);
	iterations=strtoul(argv[5],NULL,10); start=strtoull(argv[6],NULL,10);
	if(family<1 || family>2 || slot>1 || operation>3 || hold>(family==1?100UL:2000UL) ||
	   iterations<1 || iterations>128 || (operation==3 && iterations!=1)) return 2;
	fd=open("/cis-fixture",O_RDWR|O_CLOEXEC); if(fd<0) { perror("open"); return 1; }
	deadline.tv_sec=start/1000000000ULL; deadline.tv_nsec=start%1000000000ULL;
	printf("CIS_SYNC_READY family=%lu slot=%lu operation=%lu iterations=%lu\n",family,slot,operation,iterations);
	fflush(stdout);
	do { ret=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&deadline,NULL); } while(ret==EINTR);
	if(ret) { close(fd); return 1; }
	for(i=0;i<iterations;i++) {
		q=(struct cis_fixture_sync){.family=family,.slot=slot,.operation=operation,.hold_us=hold};
		if(ioctl(fd,CIS_FIXTURE_SYNC,&q)) { perror("ioctl"); close(fd); return 1; }
		printf("CIS_SYNC_TRUTH {\"family\":%u,\"slot\":%u,\"operation\":%u,\"result\":%d,"
		       "\"object\":%" PRIu64 ",\"generation\":%" PRIu64 ",\"tid\":%" PRIu64 ",\"cgroup_id\":%" PRIu64 ","
		       "\"begin_ns\":%" PRIu64 ",\"acquired_ns\":%" PRIu64 ",\"release_begin_ns\":%" PRIu64 ",\"released_ns\":%" PRIu64 "}\n",
		       q.family,q.slot,q.operation,q.result,(uint64_t)q.object,(uint64_t)q.generation,
		       (uint64_t)q.tid,(uint64_t)q.cgroup_id,(uint64_t)q.begin_ns,(uint64_t)q.acquired_ns,
		       (uint64_t)q.release_begin_ns,(uint64_t)q.released_ns);
	}
	close(fd); return 0;
}
