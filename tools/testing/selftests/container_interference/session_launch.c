// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc,char **argv)
{
	if(argc<5) return 2;
	cpu_set_t original,allocation;
	int local=getenv("CIS_FD_ALLOCATE_LOCAL")!=NULL;
	if(local) {
		int cpu=atoi(argv[2]);
		if(access("/cis-disposable-vm",F_OK) || cpu<0 || cpu>=8 ||
		   sched_getaffinity(0,sizeof(original),&original)) return 3;
		CPU_ZERO(&allocation);CPU_SET(cpu,&allocation);
		if(sched_setaffinity(0,sizeof(allocation),&allocation)) return 3;
	}
	pid_t pid=cis_container_start(argv[1],"/container-root",&argv[3],atoi(argv[2]));
	if(getenv("CIS_NET_RELEASE_CLOSE_PARENT_FD")) {
		char *end; long fd=strtol(argv[4],&end,10);
		if(pid<=0 || access("/cis-disposable-vm",F_OK) || *end || fd<3 || fd>1048576 || close((int)fd)) {
			if(pid>0) {kill(pid,SIGKILL);cis_container_wait(pid);} return 5;
		}
		printf("CIS_NET_PARENT_FD_CLOSED fd=%ld\n",fd);
	}
	if(local && sched_setaffinity(0,sizeof(original),&original)) {
		if(pid>0) {kill(pid,SIGKILL);cis_container_wait(pid);} return 4;
	}
	printf("CIS_SESSION_CONTAINER host_pid=%d\n",pid); fflush(stdout);
	if(local) printf("CIS_FD_REUSE_SETUP allocation_cpu=%d helper_affinity_restored=1\n",atoi(argv[2]));
	return cis_container_wait(pid);
}
