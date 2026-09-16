// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "fixture/uapi.h"

static void until(uint64_t ns)
{
    struct timespec ts = {ns/1000000000ULL, ns%1000000000ULL};
    while (clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&ts,NULL)==EINTR) {}
}

static int order(const void *a,const void *b)
{
    uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;
    return (x>y)-(x<y);
}

static int one_operation(void)
{
    struct stat st;
    int fd=open("/sample",O_RDONLY|O_CLOEXEC);
    if(fd<0) return 1;
    int ret=fstat(fd,&st);
    return close(fd) || ret;
}

static int fixture(int argc,char **argv)
{
    struct cis_fixture_request q={.slot=argc>2?strtoul(argv[2],NULL,10):0,.hold_us=1000};
    int fd=open("/cis-fixture",O_RDWR|O_CLOEXEC);
    uint64_t start=argc>3?strtoull(argv[3],NULL,10):cis_now_ns();
    if(fd<0) { perror("fixture"); return 6; }
    until(start);
    for(unsigned int i=0;i<200;i++) {
        if(ioctl(fd,CIS_FIXTURE_LOCK,&q)) { perror("ioctl"); close(fd); return 7; }
        char line[384];
        int size=snprintf(line,sizeof(line),"CIS_TRUTH slot=%u object=0x%" PRIx64 " begin_ns=%" PRIu64 " acquired_ns=%" PRIu64 " released_ns=%" PRIu64 " cgroup_id=%" PRIu64 "\n",
               q.slot,(uint64_t)q.object,(uint64_t)q.begin_ns,(uint64_t)q.acquired_ns,(uint64_t)q.released_ns,(uint64_t)q.cgroup_id);
        if(size<0 || size>=(int)sizeof(line) || write(STDOUT_FILENO,line,size)!=size) { close(fd); return 10; }
    }
    close(fd); return 0;
}

static int async_fixture(int argc,char **argv)
{
    uint64_t start=argc>3?strtoull(argv[3],NULL,10):cis_now_ns();
    until(start);
    for(unsigned int action=0;action<4;action++) {
        struct cis_fixture_async result={.requeue=action==2};
        int fd=open("/cis-fixture",O_RDWR|O_CLOEXEC);
        if(fd<0 || ioctl(fd,CIS_FIXTURE_QUEUE,&result)) return 6;
        if(action!=3 && ioctl(fd,action==1?CIS_FIXTURE_CANCEL:CIS_FIXTURE_WAIT,&result)) { close(fd); return 7; }
        char line[512];
        int n=snprintf(line,sizeof(line),"CIS_ASYNC action=%u object=0x%" PRIx64 " owner=%" PRIu64 " executor=%" PRIu64 " queued_ns=%" PRIu64 " start_ns=%" PRIu64 " end_ns=%" PRIu64 " cancelled=%u\n",
                       action,(uint64_t)result.object,(uint64_t)result.owner_cgroup,(uint64_t)result.executor_cgroup,
                       (uint64_t)result.queued_ns,(uint64_t)result.start_ns,(uint64_t)result.end_ns,result.cancelled);
        if(n<0 || n>=(int)sizeof(line) || write(STDOUT_FILENO,line,n)!=n) { close(fd); return 10; }
        close(fd);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct utsname un;
    char cg[512] = {0}, link[128];
    int fd = open("/proc/self/cgroup", O_RDONLY);
    if (fd < 0 || read(fd, cg, sizeof(cg)-1) < 0) return 1;
    close(fd);
    if (uname(&un)) return 1;
    ssize_t n = readlink("/proc/self/ns/mnt", link, sizeof(link)-1);
    if (n < 0) return 1;
    link[n] = 0;
    if (getpid() != 1 || strcmp(un.nodename, "cis-container")) return 2;
    fd = open("/must-not-write", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0 || errno != EROFS) return 3;
    printf("CIS_CONTAINER pid=%d host=%s mnt=%s cgroup=%s", getpid(), un.nodename, link, cg);
    fflush(stdout);
    if (argc < 2 || !strcmp(argv[1], "identity")) return 0;
    if (!strcmp(argv[1],"fixture")) return fixture(argc,argv);
    if (!strcmp(argv[1],"async-fixture")) return async_fixture(argc,argv);
    unsigned seconds = argc > 2 ? strtoul(argv[2], NULL, 10) : 2;
    if (!seconds || seconds > 300) return 4;
    uint64_t start = argc>3?strtoull(argv[3],NULL,10):cis_now_ns();
    uint64_t end = start + seconds * 1000000000ULL, ops = 0;
    until(start);
    if(!strcmp(argv[1],"reclaim")) {
        const size_t bytes=64ULL<<20;
        do {
            volatile unsigned char *p=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            if(p==MAP_FAILED) return 11;
            for(size_t i=0;i<bytes;i+=4096) p[i]=1;
            if(munmap((void*)p,bytes)) return 12;
            ops++;
        } while(cis_now_ns()<end);
        printf("CIS_RECLAIM_RESULT cgroup=%.*s allocations=%" PRIu64 " bytes_each=%zu start_ns=%" PRIu64 " end_ns=%" PRIu64 "\n",
               (int)strcspn(cg,"\n"),cg,ops,bytes,start,cis_now_ns());
        return 0;
    }
    if(!strcmp(argv[1],"open-loop")) {
        unsigned int rate=argc>4?strtoul(argv[4],NULL,10):2000;
        uint64_t count=(uint64_t)rate*seconds,timeouts=0,max=0;
        if(!rate || count>1000000) return 8;
        uint64_t *latency=calloc(count,sizeof(*latency));
        if(!latency) return 9;
        for(uint64_t i=0;i<count;i++) {
            uint64_t due=start+i*1000000000ULL/rate;
            until(due);
            if(one_operation()) { free(latency); return 5; }
            latency[i]=cis_now_ns()-due;
            if(latency[i]>100000000) timeouts++;
            if(latency[i]>max) max=latency[i];
        }
        qsort(latency,count,sizeof(*latency),order);
        printf("CIS_LATENCY cgroup=%.*s count=%" PRIu64 " p99_ns=%" PRIu64 " max_ns=%" PRIu64 " timeouts=%" PRIu64 " rate=%u start_ns=%" PRIu64 " end_ns=%" PRIu64 "\n",
               (int)strcspn(cg,"\n"),cg,count,latency[(count*99+99)/100-1],max,timeouts,rate,start,cis_now_ns());
        free(latency); return 0;
    }
    do {
        for (unsigned i = 0; i < 256; i++) {
            if(one_operation()) return 5;
            ops++;
        }
    } while (cis_now_ns() < end);
    uint64_t finish = cis_now_ns();
    printf("CIS_RESULT cgroup=%.*s operations=%" PRIu64 " start_ns=%" PRIu64 " end_ns=%" PRIu64 " errors=0\n", (int)strcspn(cg,"\n"),cg,ops,start,finish);
    return 0;
}
