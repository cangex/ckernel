// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define COUNT 4500
#define PERIOD 2000000ULL
#define TIMEOUT 100000000ULL
#define MAGIC 0x43495337
static uint64_t latencies[COUNT];
static unsigned char seen[COUNT];
static int compare(const void *a,const void *b)
{
	uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;
	return (x>y)-(x<y);
}
static void payload(unsigned char *p,unsigned int actor,unsigned int seq)
{
	uint32_t header[3]={htonl(MAGIC),htonl(actor),htonl(seq)};
	memset(p,0x40+actor,1024);memcpy(p,header,sizeof(header));
}
static int valid(const unsigned char *p,unsigned int actor,unsigned int *seq)
{
	uint32_t header[3];unsigned char expected[1024];
	memcpy(header,p,sizeof(header));*seq=ntohl(header[2]);
	if(ntohl(header[0])!=MAGIC || ntohl(header[1])!=actor || *seq>=COUNT) return 0;
	payload(expected,actor,*seq);return !memcmp(p,expected,1024);
}
int main(int argc,char **argv)
{
	struct sockaddr_in peer={.sin_family=AF_INET};
	struct timeval timeout={.tv_sec=0,.tv_usec=100000};
	uint64_t start,begin=0,end=0,total=0,timeouts=0;
	unsigned int actor,completed=0,errors=0,duplicates=0;
	unsigned char data[1024],reply[1024];
	int serve,netfd,fd;
	if(argc!=6 || getpid()!=1 || (strcmp(argv[1],"client") && strcmp(argv[1],"serve"))) return 2;
	serve=!strcmp(argv[1],"serve");netfd=atoi(argv[2]);actor=atoi(argv[3]);start=strtoull(argv[5],NULL,10);
	if(netfd<3 || actor>3 || !start || inet_pton(AF_INET,argv[4],&peer.sin_addr)!=1 || setns(netfd,CLONE_NEWNET)) return 3;
	close(netfd);peer.sin_port=htons(19010+actor);
	fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
	if(fd<0 || setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) return 4;
	if(serve) {
		peer.sin_addr.s_addr=INADDR_ANY;
		if(bind(fd,(void*)&peer,sizeof(peer))) return 5;
		printf("Y7_QUEUE_READY actor=%u\n",actor);fflush(stdout);
		while(cis_now_ns()<start+11000000000ULL) {
			struct sockaddr_in from;socklen_t length=sizeof(from);unsigned int seq=0;
			ssize_t n=recvfrom(fd,data,sizeof(data),MSG_TRUNC,(void*)&from,&length);
			if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) continue;
			if(n!=1024 || !valid(data,actor,&seq)) {errors++;continue;}
			if(seen[seq]) duplicates++;
			else {seen[seq]=1;completed++;}
			if(sendto(fd,data,sizeof(data),0,(void*)&from,length)!=1024) errors++;
		}
		printf("Y7_QUEUE_SERVER actor=%u received=%u errors=%u duplicates=%u\n",actor,completed,errors,duplicates);
		close(fd);return errors || duplicates || completed!=COUNT ? 6 : 0;
	}
	if(connect(fd,(void*)&peer,sizeof(peer))) return 7;
	for(unsigned int i=0;i<COUNT;i++) {
		uint64_t due=start+i*PERIOD;unsigned int seq=0;
		struct timespec when={due/1000000000ULL,due%1000000000ULL};int ret;
		do {ret=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&when,NULL);} while(ret==EINTR);
		if(ret || cis_now_ns()>start+10000000000ULL) {errors++;break;}
		if(!i) begin=cis_now_ns();
		payload(data,actor,i);
		if(send(fd,data,sizeof(data),0)!=1024 || recv(fd,reply,sizeof(reply),MSG_TRUNC)!=1024 ||
		   !valid(reply,actor,&seq) || seq!=i) {errors++;break;}
		end=cis_now_ns();latencies[completed++]=end-due;total+=end-due;timeouts+=end-due>TIMEOUT;
	}
	qsort(latencies,completed,sizeof(*latencies),compare);
	printf("Y7_QUEUE_CLIENT actor=%u due=%" PRIu64 " begin=%" PRIu64 " end=%" PRIu64
	       " offered=%u completed=%u errors=%u timeouts=%" PRIu64 " period=%llu timeout=%llu p99=%" PRIu64
	       " max=%" PRIu64 " sum=%" PRIu64 "\n",actor,start,begin,end,COUNT,completed,errors,timeouts,PERIOD,TIMEOUT,
	       completed?latencies[(completed*99+99)/100-1]:0,completed?latencies[completed-1]:0,total);
	printf("Y7_QUEUE_LATENCIES ");
	for(unsigned int i=0;i<completed;i++) printf("%s%" PRIu64,i?",":"",latencies[i]);
	putchar('\n');close(fd);return errors || completed!=COUNT ? 8 : 0;
}
