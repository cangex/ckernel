// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include "fixture/uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static void until(uint64_t ns)
{
	struct timespec t={ns/1000000000ULL,ns%1000000000ULL};
	while(clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL)==EINTR) {}
}
int main(int argc,char **argv)
{
	unsigned int slot;
	uint64_t start,end,calls=0;
	int fd;
	char cg[512]={0};
	struct utsname un;
	struct cis_fixture_storm q={.iterations=256};
	if(argc!=3 || getpid()!=1) return 2;
	slot=strtoul(argv[1],NULL,10); start=strtoull(argv[2],NULL,10); end=start+3000000000ULL;
	if(slot>7) return 2;
	fd=open("/proc/self/cgroup",O_RDONLY|O_CLOEXEC);
	if(fd<0) return 2;
	ssize_t count=read(fd,cg,sizeof(cg)-1);
	close(fd);
	if(count<=0 || uname(&un) || strcmp(un.nodename,"cis-container")) return 2;
	fd=open("/must-not-write",O_CREAT|O_WRONLY,0600);
	if(fd>=0 || errno!=EROFS) return 2;
	printf("CIS_ENTRY_CONTAINER slot=%u pid=%d host=%s readonly_root=1 cgroup=%.*s\n",
		slot,getpid(),un.nodename,(int)strcspn(cg,"\n"),cg);
	fd=open("/cis-fixture",O_RDWR|O_CLOEXEC); if(fd<0) return 3;
	until(start);
	if(!slot) until(end);
	else do {
		if(ioctl(fd,CIS_FIXTURE_STORM,&q)) { close(fd); return 4; }
		calls++;
	} while(cis_now_ns()<end);
	close(fd);
	printf("CIS_ENTRY_WORKLOAD slot=%u calls=%" PRIu64 " loops_per_call=256 start_ns=%" PRIu64 " end_ns=%" PRIu64 " errors=0\n",
		slot,calls,start,cis_now_ns());
	return 0;
}
