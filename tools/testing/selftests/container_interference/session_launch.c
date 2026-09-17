// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char **argv)
{
	if(argc<5) return 2;
	pid_t pid=cis_container_start(argv[1],"/container-root",&argv[3],atoi(argv[2]));
	printf("CIS_SESSION_CONTAINER host_pid=%d\n",pid); fflush(stdout);
	return cis_container_wait(pid);
}
