// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../../../container_interference/include/cis.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static uint64_t now=10000000000ULL;
int __wrap_clock_gettime(clockid_t clock,struct timespec *t)
{
    (void)clock; t->tv_sec=now/1000000000ULL; t->tv_nsec=now%1000000000ULL; return 0;
}
void cis_report(struct cis_context *ctx,const char *kind,const struct cis_root *r,const char *detail)
{ (void)ctx; (void)kind; (void)r; (void)detail; }
int cis_capture_diagnostic(struct cis_context *ctx,struct cis_root *r,int start)
{ (void)ctx; (void)r; (void)start; return 0; }
static void content(int fd,const char *text)
{
    size_t n=strlen(text);
    assert(!ftruncate(fd,0)); assert(pwrite(fd,text,n,0)==(ssize_t)n);
}
int main(void)
{
    struct cis_root r={0}; struct cis_metric m;
    const char *initial[]={"usage_usec 100\nthrottled_usec 0\n", "some total=20\n",
        "some total=30\n","16384\n","high 0\noom 0\n","populated 0\n"};
    for(unsigned int i=0;i<6;i++) {
        r.metric_fd[i]=memfd_create("cis-metric-test",MFD_CLOEXEC);
        assert(r.metric_fd[i]>=0); content(r.metric_fd[i],initial[i]);
    }
    assert(!cis_metrics_read(&r,&m) && m.usage_us==100 && r.full_metrics_ns==now);
    now+=1000000000ULL;
    int cpu_fd=r.metric_fd[0]; r.metric_fd[0]=-1;
    content(r.metric_fd[3],"32768\n");
    assert(cis_metrics_read(&r,&m)==1 && !m.populated && m.memory_current==32768);
    content(r.metric_fd[5],"populated 1\n");
    assert(cis_metrics_read(&r,&m)<0);
    r.metric_fd[0]=cpu_fd;
    assert(!cis_metrics_read(&r,&m) && m.populated);
    content(r.metric_fd[5],"populated 0\n");
    now+=5000000000ULL;
    assert(!cis_metrics_read(&r,&m) && !m.populated);
    for(unsigned int i=0;i<6;i++) close(r.metric_fd[i]);
    puts("CIS_METRICS_TEST empty_deferred_memory_current_active_immediate PASS");
    return 0;
}
