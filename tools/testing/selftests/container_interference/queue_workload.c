// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int main(int argc,char **argv)
{
	struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(19001)};
	struct stat ns,pidns,mntns;
	unsigned char payload[1024];
	unsigned long long start,first=0,last=0;
	unsigned int actor,i,sent=0,errors=0;
	int fd,netfd;
	if(argc!=5 || getpid()!=1) return 2;
	netfd=atoi(argv[1]); actor=atoi(argv[2]); start=strtoull(argv[4],NULL,10);
	if(netfd<3 || actor>1 || !start || inet_pton(AF_INET,argv[3],&peer.sin_addr)!=1 ||
	   setns(netfd,CLONE_NEWNET) || fstat(netfd,&ns) ||
	   stat("/proc/self/ns/pid",&pidns) || stat("/proc/self/ns/mnt",&mntns)) return 3;
	close(netfd);
	fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
	if(fd<0) return 4;
	for(i=0;i<1000;i++) {
		uint32_t *header=(void*)payload;
		uint64_t at=start+i*1000000ULL;
		struct timespec wake={at/1000000000ULL,at%1000000000ULL};
		while(clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&wake,NULL)==EINTR) {}
		if(!first) first=cis_now_ns();
		memset(payload,0x40+actor,sizeof(payload));
		header[0]=htonl(0x43495335); header[1]=htonl(actor); header[2]=htonl(i);
		if(sendto(fd,payload,sizeof(payload),0,(void*)&peer,sizeof(peer))==(ssize_t)sizeof(payload)) sent++;
		else errors++;
	}
	last=cis_now_ns(); close(fd);
	printf("CIS_QUEUE_WORK actor=%u sent=%u errors=%u first=%llu last=%llu netns=%lu pidns=%lu mntns=%lu pid=%d\n",
		actor,sent,errors,first,last,(unsigned long)ns.st_ino,(unsigned long)pidns.st_ino,
		(unsigned long)mntns.st_ino,getpid());
	return errors?5:0;
}
