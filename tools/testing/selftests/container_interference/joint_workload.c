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

#define COUNT 1500
#define PERIOD 2000000ULL
#define TIMEOUT 100000000ULL
static uint64_t latency[COUNT];
static int compare(const void *a,const void *b)
{
    uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;
    return (x>y)-(x<y);
}

static int file_operation(void)
{
    char data[64]; struct stat st;
    int fd=open("/sample",O_RDONLY|O_CLOEXEC);
    if(fd<0) return 1;
    int ret=fstat(fd,&st); ssize_t n=read(fd,data,sizeof(data));
    return close(fd) || ret || n<=0 || st.st_size<=0;
}

static int vma_operation(void)
{
    size_t page=sysconf(_SC_PAGESIZE), size=page*32;
    char *p=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) return 1;
    for(size_t j=0;j<32;j++) p[j*page]=(char)j;
    for(size_t j=0;j<32;j+=2) {
        if(mprotect(p+j*page,page,PROT_READ)) {munmap(p,size);return 1;}
    }
    for(size_t j=0;j<32;j++) {
        if(p[j*page]!=(char)j) {munmap(p,size);return 1;}
    }
    return munmap(p,size)!=0;
}

int main(int argc,char **argv)
{
    if(argc!=3 || (strcmp(argv[1],"file") && strcmp(argv[1],"vma"))) return 2;
    int vma=!strcmp(argv[1],"vma");
    uint64_t start=strtoull(argv[2],NULL,10), errors=0,timeouts=0,first=0,last=0,total=0,max=0;
    for(unsigned int i=0;i<COUNT;i++) {
        uint64_t due=start+i*PERIOD;
        struct timespec when={due/1000000000ULL,due%1000000000ULL};
        int ret;
        do {ret=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&when,NULL);} while(ret==EINTR);
        if(ret) return 3;
        uint64_t begin=cis_now_ns(); if(!i) first=begin;
        errors+=vma?vma_operation():file_operation(); last=cis_now_ns();
        latency[i]=last-due; total+=latency[i]; if(latency[i]>max) max=latency[i];
        timeouts+=latency[i]>TIMEOUT;
    }
    qsort(latency,COUNT,sizeof(*latency),compare);
    printf("CIS_JOINT_WORK mode=%s due_start_ns=%" PRIu64 " begin_ns=%" PRIu64 " end_ns=%" PRIu64
           " offered=%u completed=%u errors=%" PRIu64 " timeouts=%" PRIu64
           " period_ns=%llu timeout_ns=%llu p99_ns=%" PRIu64 " max_ns=%" PRIu64 " latency_sum_ns=%" PRIu64 "\n",
           argv[1],start,first,last,COUNT,COUNT,errors,timeouts,PERIOD,TIMEOUT,latency[COUNT*99/100-1],max,total);
    printf("CIS_JOINT_LATENCIES ");
    for(unsigned int i=0;i<COUNT;i++) printf("%s%" PRIu64,i?",":"",latency[i]);
    putchar('\n');
    return errors?4:0;
}
