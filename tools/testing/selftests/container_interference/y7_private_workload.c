// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define COUNT 6000
#define PERIOD 3000000ULL
#define TIMEOUT 100000000ULL
static uint64_t latency[COUNT];
static int compare(const void *a,const void *b)
{
	uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;
	return (x>y)-(x<y);
}
static int operation(int dir,unsigned int seq)
{
	char data[4096],back[4096];
	struct stat st;
	int fd,ret=0;
	size_t page=sysconf(_SC_PAGESIZE),size=32*page;
	char *p=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(p==MAP_FAILED) return 1;
	for(size_t j=0;j<32;j++) p[j*page]=(char)j;
	for(size_t j=0;j<32;j+=2) if(mprotect(p+j*page,page,PROT_READ)) ret=1;
	for(size_t j=0;j<32;j++) if(p[j*page]!=(char)j) ret=1;
	if(munmap(p,size)) ret=1;
	memset(data,(unsigned char)seq,sizeof(data));
	fd=openat(dir,"active",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
	if(fd<0) return 1;
	if(write(fd,data,sizeof(data))!=(ssize_t)sizeof(data) ||
	   pread(fd,back,sizeof(back),0)!=(ssize_t)sizeof(back) ||
	   memcmp(data,back,sizeof(data)) || fstat(fd,&st) || st.st_size!=(off_t)sizeof(data)) ret=1;
	if(!(seq%16) && fdatasync(fd)) ret=1;
	if(renameat(dir,"active",dir,"finished") || unlinkat(dir,"finished",0)) ret=1;
	if(close(fd)) ret=1;
	return ret;
}
int main(int argc,char **argv)
{
	uint64_t start,errors=0,timeouts=0,first=0,last=0,total=0;
	int dir,actor;
	struct stat directory;
	if(argc!=4 || getpid()!=1) return 2;
	dir=atoi(argv[1]);actor=atoi(argv[2]);start=strtoull(argv[3],NULL,10);
	if(dir<3 || actor<0 || actor>3 || !start || fstat(dir,&directory) || !S_ISDIR(directory.st_mode)) return 2;
	for(unsigned int i=0;i<COUNT;i++) {
		uint64_t due=start+i*PERIOD;
		struct timespec when={due/1000000000ULL,due%1000000000ULL};
		int ret;
		do {ret=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&when,NULL);} while(ret==EINTR);
		if(ret) return 3;
		if(!i) first=cis_now_ns();
		errors+=operation(dir,i);last=cis_now_ns();
		latency[i]=last-due;total+=latency[i];timeouts+=latency[i]>TIMEOUT;
	}
	qsort(latency,COUNT,sizeof(*latency),compare);
	printf("Y7_PRIVATE actor=%d dev=%ju inode=%ju due=%" PRIu64 " begin=%" PRIu64 " end=%" PRIu64
	       " offered=%u completed=%u errors=%" PRIu64 " timeouts=%" PRIu64
	       " period=%llu timeout=%llu p99=%" PRIu64 " max=%" PRIu64 " sum=%" PRIu64 "\n",
	       actor,(uintmax_t)directory.st_dev,(uintmax_t)directory.st_ino,start,first,last,COUNT,COUNT,
	       errors,timeouts,PERIOD,TIMEOUT,latency[COUNT*99/100-1],latency[COUNT-1],total);
	printf("Y7_LATENCIES ");
	for(unsigned int i=0;i<COUNT;i++) printf("%s%" PRIu64,i?",":"",latency[i]);
	putchar('\n');
	return errors?4:0;
}
