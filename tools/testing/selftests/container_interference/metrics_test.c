// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../../../container_interference/include/cis.h"
#include "../../../container_interference/include/cis_metrics_schedule.h"
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
	unsigned int buckets[40]={0};
	for(unsigned int i=1;i<=256;i++) {
		uint64_t due=cis_metric_first(12345678901ULL,i);
		assert(due>12345678901ULL && due<=13345678901ULL);
		assert(!(due%25000000ULL));
		buckets[(due%1000000000ULL)/25000000ULL]++;
		assert(cis_metric_next(due,due+1000)==due+1000000000ULL);
		assert(cis_metric_next(due,due+3100000000ULL)==due+4000000000ULL);
	}
	for(unsigned int i=0;i<40;i++) assert(buckets[i]>=6 && buckets[i]<=7);
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
    {
        struct cis_context ctx={0};
        struct cis_root root={0};
        int fds[4];
        const char *values[]={"max 100000\n","max\n","1-4\n","0\n"};
        root.epoch=9; root.state=CIS_AMBIENT;
        for(unsigned int i=0;i<6;i++) root.metric_fd[i]=-1;
        for(unsigned int i=0;i<4;i++) {
            fds[i]=root.config_fd[i]=memfd_create("cis-config-test",MFD_CLOEXEC);
            assert(fds[i]>=0); content(fds[i],values[i]);
        }
        assert(!cis_config_epoch(&ctx,&root,now) && root.config_hash);
        uint64_t old=root.config_hash;
        now+=5000000000ULL;content(fds[0],"20000 100000\n");
        assert(!cis_config_epoch(&ctx,&root,now) && root.config_hash!=old);
        assert(root.epoch==10 && root.state==CIS_WARMUP);
        for(unsigned int i=0;i<4;i++) assert(root.config_fd[i]==fds[i]);
        root.state=CIS_DIAGNOSING;ctx.diagnostic=1;
        root.pending=1;root.samples=9;root.previous.time_ns=now;
        now+=5000000000ULL;content(fds[0],"");
        assert(cis_config_epoch(&ctx,&root,now)<0);
        assert(!root.config_hash && !root.config_due_ns && !root.samples && !root.pending);
        assert(!root.previous.time_ns && !ctx.diagnostic && root.state==CIS_WARMUP);
        assert(root.config_fd[0]==-1 && root.epoch==11);
        cis_metrics_close(&root);
        for(unsigned int i=0;i<4;i++) assert(root.config_fd[i]==-1);
    }
    puts("CIS_METRICS_TEST empty_deferred_memory_current_active_immediate PASS");
    puts("CIS_METRICS_TEST bounded_buckets_no_frequency_reduction PASS");
    puts("CIS_METRICS_TEST persistent_configuration_fds_fresh_values_epoch_cleanup PASS");
    return 0;
}
