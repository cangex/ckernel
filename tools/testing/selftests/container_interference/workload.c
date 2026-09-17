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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
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

static void cpu_until(uint64_t end)
{
    volatile uint64_t value=1;
    do {
        for(unsigned int i=0;i<1024;i++) value=value*6364136223846793005ULL+1;
    } while(cis_now_ns()<end);
}

static int internal_phase(uint64_t start,unsigned int seconds)
{
    uint64_t span=(uint64_t)seconds*1000000000ULL/3;
    pid_t children[3]={0};
    if(seconds<9) return 13;
    until(start);
    printf("CIS_PHASE begin_ns=%" PRIu64 " concurrency=1 relation=container_internal\n",cis_now_ns());
    cpu_until(start+span);
    printf("CIS_PHASE begin_ns=%" PRIu64 " concurrency=4 relation=container_internal\n",cis_now_ns());
    fflush(stdout);
    for(unsigned int i=0;i<3;i++) {
        children[i]=fork();
        if(!children[i]) { cpu_until(start+2*span); _exit(0); }
        if(children[i]<0) return 14;
    }
    cpu_until(start+2*span);
    for(unsigned int i=0;i<3;i++) {
        int status;
        if(waitpid(children[i],&status,0)!=children[i] || !WIFEXITED(status) || WEXITSTATUS(status)) return 15;
    }
    printf("CIS_PHASE begin_ns=%" PRIu64 " concurrency=1 relation=container_internal\n",cis_now_ns());
    cpu_until(start+3*span);
    printf("CIS_PHASE_DONE end_ns=%" PRIu64 "\n",cis_now_ns());
    return 0;
}

static int fixture(int argc,char **argv)
{
    struct cis_fixture_request q={.slot=argc>2?strtoul(argv[2],NULL,10):0,.hold_us=1000};
    int fd=open("/cis-fixture",O_RDWR|O_CLOEXEC);
    uint64_t start=argc>3?strtoull(argv[3],NULL,10):cis_now_ns();
    int busy=argc>4 && !strcmp(argv[4],"preempt");
    pid_t competitor=0;
    if(busy) q.hold_us=10000;
    if(fd<0) { perror("fixture"); return 6; }
    until(start);
    if(busy) {
        competitor=fork();
        if(!competitor) { cpu_until(start+1500000000ULL); _exit(0); }
        if(competitor<0) return 6;
    }
    for(unsigned int i=0;i<(busy?40U:200U);i++) {
        if(i==100 && argc>4 && !strcmp(argv[4],"reuse")) {
            if(ioctl(fd,CIS_FIXTURE_RESET,&q)) { close(fd); return 7; }
            printf("CIS_RESET object=0x%" PRIx64 " generation=%" PRIu64 " time_ns=%" PRIu64 " fixture_reinitialization=1\n",
                   (uint64_t)q.object,(uint64_t)q.object_generation,(uint64_t)q.begin_ns);
            fflush(stdout);
        }
        if(ioctl(fd,busy?CIS_FIXTURE_BUSY:CIS_FIXTURE_LOCK,&q)) { perror("ioctl"); close(fd); return 7; }
        char line[448];
        int size=snprintf(line,sizeof(line),"CIS_TRUTH slot=%u object=0x%" PRIx64 " begin_ns=%" PRIu64 " acquired_ns=%" PRIu64 " released_ns=%" PRIu64 " cgroup_id=%" PRIu64 " generation=%" PRIu64 " host_tid=%" PRIu64 " busy=%d\n",
               q.slot,(uint64_t)q.object,(uint64_t)q.begin_ns,(uint64_t)q.acquired_ns,(uint64_t)q.released_ns,(uint64_t)q.cgroup_id,(uint64_t)q.object_generation,(uint64_t)q.tid,busy);
        if(size<0 || size>=(int)sizeof(line) || write(STDOUT_FILENO,line,size)!=size) { close(fd); return 10; }
    }
    if(competitor>0) { int status; if(waitpid(competitor,&status,0)!=competitor || status) return 8; }
    close(fd); return 0;
}

static void interrupted(int sig) { (void)sig; }

static int attempt_fixture(int argc,char **argv)
{
    unsigned int role=argc>2?strtoul(argv[2],NULL,10):0;
    uint64_t start=strtoull(argv[3],NULL,10);
    int fd=open("/cis-fixture",O_RDWR|O_CLOEXEC);
    struct sigaction sa={.sa_handler=interrupted};
    int killable=argc>4 && !strcmp(argv[4],"killable");
    int ww=argc>4 && !strcmp(argv[4],"ww");
    if(fd<0 || sigaction(SIGALRM,&sa,NULL)) return 6;
    for(unsigned int i=0;i<4;i++) {
        uint64_t base=start+i*250000000ULL;
        struct cis_fixture_attempt a={.mode=role?1:0,.hold_us=role?0:120000};
        struct itimerval alarm={.it_value={0,20000}},cancel={0};
        until(base+(role?20000000:0));
        if(role && killable) {
            int identity_pipe[2];
            struct cis_fixture_attempt child_identity={0};
            if(pipe2(identity_pipe,O_CLOEXEC)) return 10;
            pid_t child=fork();
            int status;
            if(!child) {
                close(identity_pipe[0]); a.mode=6;
                if(ioctl(fd,CIS_FIXTURE_ATTEMPT,&a) ||
                   write(identity_pipe[1],&a,sizeof(a))!=(ssize_t)sizeof(a)) _exit(98);
                close(identity_pipe[1]); a.mode=2;
                ioctl(fd,CIS_FIXTURE_ATTEMPT,&a); _exit(99);
            }
            if(child<0) return 10;
            close(identity_pipe[1]);
            if(read(identity_pipe[0],&child_identity,sizeof(child_identity))!=(ssize_t)sizeof(child_identity)) return 10;
            close(identity_pipe[0]);
            until(base+40000000ULL);
            if(kill(child,SIGKILL) || waitpid(child,&status,0)!=child ||
               !WIFSIGNALED(status) || WTERMSIG(status)!=SIGKILL) return 10;
            printf("CIS_KILLABLE iteration=%u aborted_child=1 object=0x%" PRIx64 " host_tid=%" PRIu64 " begin_ns=%" PRIu64 " end_ns=%" PRIu64 " result=-4 endpoint=waitpid_upper_bound\n",
                   i,(uint64_t)child_identity.object,(uint64_t)child_identity.tid,(uint64_t)child_identity.begin_ns,cis_now_ns());
            until(base+180000000ULL);a.mode=3;
            if(ioctl(fd,CIS_FIXTURE_ATTEMPT,&a) || a.result) return 9;
            printf("CIS_RETRY object=0x%" PRIx64 " host_tid=%" PRIu64 " begin_ns=%" PRIu64 " end_ns=%" PRIu64 " acquired_ns=%" PRIu64 " result=%d iteration=%u\n",
                   (uint64_t)a.object,(uint64_t)a.tid,(uint64_t)a.begin_ns,(uint64_t)a.end_ns,(uint64_t)a.acquired_ns,a.result,i);
            fflush(stdout);continue;
        }
        if(ww) a.mode=role?4:5;
        if(role && !ww && setitimer(ITIMER_REAL,&alarm,NULL)) return 6;
        if(ioctl(fd,CIS_FIXTURE_ATTEMPT,&a)) return 7;
        if(role && setitimer(ITIMER_REAL,&cancel,NULL)) return 6;
        printf("CIS_ATTEMPT object=0x%" PRIx64 " host_tid=%" PRIu64 " begin_ns=%" PRIu64 " end_ns=%" PRIu64 " acquired_ns=%" PRIu64 " result=%d role=%u iteration=%u\n",
               (uint64_t)a.object,(uint64_t)a.tid,(uint64_t)a.begin_ns,(uint64_t)a.end_ns,(uint64_t)a.acquired_ns,a.result,role,i);
        if(a.result!=(role?(ww?-EDEADLK:-EINTR):0)) return 8;
        if(role && !ww) {
            until(base+180000000ULL); a.mode=3;
            if(ioctl(fd,CIS_FIXTURE_ATTEMPT,&a) || a.result) return 9;
            printf("CIS_RETRY object=0x%" PRIx64 " host_tid=%" PRIu64 " begin_ns=%" PRIu64 " end_ns=%" PRIu64 " acquired_ns=%" PRIu64 " result=%d iteration=%u\n",
                   (uint64_t)a.object,(uint64_t)a.tid,(uint64_t)a.begin_ns,(uint64_t)a.end_ns,(uint64_t)a.acquired_ns,a.result,i);
        }
        fflush(stdout);
    }
    close(fd); return 0;
}

static int dentry_fixture(int argc,char **argv)
{
    struct cis_fixture_dentry q={.seed=1};
    int dev=open("/cis-fixture",O_RDWR|O_CLOEXEC);
    int private=argc>4 && !strcmp(argv[4],"private");
    q.fd=open(private?"/tmp/private-object":"/sample",private?O_CREAT|O_RDWR:O_RDONLY,0600);
    if(dev<0 || q.fd<0) return 6;
    until(argc>3?strtoull(argv[3],NULL,10):cis_now_ns());
    if(ioctl(dev,CIS_FIXTURE_DENTRY,&q)) { perror("dentry ioctl"); return 7; }
    printf("CIS_DENTRY object=0x%" PRIx64 " cgroup_id=%" PRIu64 " host_tid=%" PRIu64 " begin_ns=%" PRIu64 " end_ns=%" PRIu64 " slowpaths=%" PRIu64 " private=%d real_dentry=1 injected_delay_us=40\n",
           (uint64_t)q.object,(uint64_t)q.cgroup_id,(uint64_t)q.tid,(uint64_t)q.begin_ns,(uint64_t)q.end_ns,(uint64_t)q.slowpaths,private);
    close(q.fd); close(dev); return 0;
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
    if (!strcmp(argv[1],"attempt")) return attempt_fixture(argc,argv);
    if (!strcmp(argv[1],"dentry")) return dentry_fixture(argc,argv);
    if (!strcmp(argv[1],"async-fixture")) return async_fixture(argc,argv);
    unsigned seconds = argc > 2 ? strtoul(argv[2], NULL, 10) : 2;
    if (!seconds || seconds > 300) return 4;
    uint64_t start = argc>3?strtoull(argv[3],NULL,10):cis_now_ns();
    uint64_t end = start + seconds * 1000000000ULL, ops = 0;
    if(!strcmp(argv[1],"internal-phase")) return internal_phase(start,seconds);
    if(!strcmp(argv[1],"reclaim")) {
        until(start);
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
        int timeline=argc>5 && !strcmp(argv[5],"timeline");
        /* Bound diagnostic output before allocating buffers or starting work. */
        if(timeline && count>20000) return 8;
        uint64_t *latency=calloc(count,sizeof(*latency));
        uint64_t *waiting=calloc(count,sizeof(*waiting)), *service=calloc(count,sizeof(*service));
        uint64_t *sorted=calloc(count,sizeof(*sorted));
        if(!latency || !waiting || !service || !sorted) return 9;
        /* Fault in the result buffers before the common measurement barrier. */
        for(uint64_t i=0;i<count;i++) latency[i]=waiting[i]=service[i]=sorted[i]=1;
        unsigned long slack=prctl(PR_GET_TIMERSLACK,0,0,0,0);
        until(start);
        for(uint64_t i=0;i<count;i++) {
            uint64_t due=start+i*1000000000ULL/rate;
            until(due);
            uint64_t begin=cis_now_ns();
            if(one_operation()) return 5;
            uint64_t finish=cis_now_ns();
            waiting[i]=begin-due; service[i]=finish-begin; latency[i]=finish-due;
            if(latency[i]>100000000) timeouts++;
            if(latency[i]>max) max=latency[i];
        }
        uint64_t finish=cis_now_ns();
        memcpy(sorted,latency,count*sizeof(*latency)); qsort(sorted,count,sizeof(*sorted),order);
        uint64_t p99=sorted[(count*99+99)/100-1],tail_count=0,tail_wait=0,tail_service=0;
        for(uint64_t i=0;i<count;i++) if(latency[i]>=p99) {
            tail_count++; tail_wait+=waiting[i]; tail_service+=service[i];
        }
        /* Optional diagnosis exports existing timestamps only after measurement.
         * It is not enabled in the frozen performance acceptance batches. */
        if(timeline) {
            printf("CIS_LATENCY_TIMELINE count=%" PRIu64 " post_window_export=1 clock=guest_monotonic\n",count);
            for(uint64_t i=0;i<count;i++) {
                uint64_t due=start+i*1000000000ULL/rate;
                printf("CIS_LATENCY_SAMPLE index=%" PRIu64 " due_ns=%" PRIu64 " begin_ns=%" PRIu64 " finish_ns=%" PRIu64 "\n",
                       i,due,due+waiting[i],due+latency[i]);
            }
        }
        printf("CIS_LATENCY cgroup=%.*s count=%" PRIu64 " p99_ns=%" PRIu64 " max_ns=%" PRIu64 " timeouts=%" PRIu64 " rate=%u start_ns=%" PRIu64 " end_ns=%" PRIu64 "\n",
               (int)strcspn(cg,"\n"),cg,count,p99,max,timeouts,rate,start,finish);
        qsort(waiting,count,sizeof(*waiting),order); qsort(service,count,sizeof(*service),order);
        printf("CIS_LATENCY_PARTS cgroup=%.*s wait_p99_ns=%" PRIu64 " execution_p99_ns=%" PRIu64 " tail_count=%" PRIu64 " tail_wait_mean_ns=%" PRIu64 " tail_execution_mean_ns=%" PRIu64 " timerslack_ns=%lu percentiles_not_additive=1 execution_includes_blocking=1\n",
               (int)strcspn(cg,"\n"),cg,waiting[(count*99+99)/100-1],service[(count*99+99)/100-1],tail_count,
               tail_wait/tail_count,tail_service/tail_count,slack);
        free(latency);free(waiting);free(service);free(sorted); return 0;
    }
    until(start);
    do {
        for (unsigned i = 0; i < 256; i++) {
            if(one_operation()) return 5;
            ops++;
        }
    } while (cis_now_ns() < end);
    uint64_t finish = cis_now_ns();
    printf("CIS_RESULT cgroup=%.*s operations=%" PRIu64 " start_ns=%" PRIu64 " end_ns=%" PRIu64 " scheduled_end_ns=%" PRIu64 " last_batch_ops=256 errors=0\n", (int)strcspn(cg,"\n"),cg,ops,start,finish,end);
    return 0;
}
