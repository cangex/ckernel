// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include "fixture/uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static int move_cpu(int cpu)
{
	cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu,&set);
	return sched_setaffinity(0,sizeof(set),&set);
}
static uint64_t process_ns(void)
{
	struct timespec t; if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t)) abort();
	return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}
int main(int argc,char **argv)
{
	uint64_t start,begin,end,cpu_begin,ops=0,turn=0,x=17;
	int actor,background,migration,fd=-1;
	struct timespec at;
	if(argc!=4 || getpid()!=1) return 2;
	actor=atoi(argv[1]); start=strtoull(argv[3],NULL,10);
	background=!strcmp(argv[2],"background"); migration=!strcmp(argv[2],"migration") && !actor;
	if(actor<0 || actor>1 || !start) return 2;
	if(background) { fd=open("/dev/cis-fixture",O_RDWR|O_CLOEXEC); if(fd<0) return 3; }
	at=(struct timespec){start/1000000000ULL,start%1000000000ULL};
	while(clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&at,NULL)==EINTR) {}
	begin=cis_now_ns(); cpu_begin=process_ns();
	if(background) {
		unsigned int i;
		for(i=0;i<40;i++) {
			struct cis_fixture_async q={.requeue=i%2};
			if(ioctl(fd,CIS_FIXTURE_QUEUE,&q) || ioctl(fd,CIS_FIXTURE_WAIT,&q)) return 4;
			printf("CPU_WORK_TRUTH object=%llu owner=%llu executor=%llu queued=%llu start=%llu end=%llu\n",
				(unsigned long long)q.object,(unsigned long long)q.owner_cgroup,
				(unsigned long long)q.executor_cgroup,(unsigned long long)q.queued_ns,
				(unsigned long long)q.start_ns,(unsigned long long)q.end_ns);
			usleep(5000);
		}
	}
	while(cis_now_ns()<start+1000000000ULL) {
		unsigned int i;
		for(i=0;i<4096;i++) { x=x*2862933555777941757ULL+3037000493ULL; __asm__ volatile("" : "+r"(x)); }
		ops+=4096;
		if(migration && cis_now_ns()>=start+(turn+1)*100000000ULL) {
			if(move_cpu((++turn)&1)) return 5;
		}
	}
	end=cis_now_ns();
	printf("CPU_WORKLOAD actor=%d begin=%llu end=%llu cpu_ns=%llu ops=%llu checksum=%llu migrations=%llu\n",
		actor,(unsigned long long)begin,(unsigned long long)end,(unsigned long long)(process_ns()-cpu_begin),
		(unsigned long long)ops,(unsigned long long)x,(unsigned long long)turn);
	if(fd>=0) close(fd);
	return ops ? 0 : 6;
}
