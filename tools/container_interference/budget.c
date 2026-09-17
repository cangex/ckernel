// SPDX-License-Identifier: GPL-2.0
#include "include/cis.h"
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>
static void stop_fast(struct cis_context *ctx)
{
	unsigned int i;
	if(!ctx->fast_alert) return;
	for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used) cis_fast_close(ctx,&ctx->roots[i]);
	ctx->fast_alert=0;
	cis_report(ctx,"fast_budget_disable",NULL,"PSI trigger FDs closed; kernel trigger work no longer requested");
}
void cis_budget_tick(struct cis_context *ctx,uint64_t now)
{
	struct timespec t;
	unsigned long rss=0,unused;
	uint64_t cpu,elapsed,delta;
	struct rusage usage;
	int known=0;
	FILE *f;
	char detail[640];
	if (now<ctx->last_budget_ns) goto unavailable;
	if (now-ctx->last_budget_ns<1000000000ULL) return;
	if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t)) goto unavailable;
	cpu=(uint64_t)t.tv_sec*1000000000+t.tv_nsec;
	if(cpu<ctx->last_process_ns || getrusage(RUSAGE_SELF,&usage)) goto unavailable;
	delta=cpu-ctx->last_process_ns;
	elapsed=ctx->last_budget_ns?now-ctx->last_budget_ns:0;
	f=fopen("/proc/self/statm","r");
	if (f) { known=fscanf(f,"%lu %lu",&unused,&rss)==2; fclose(f); }
	if(!known || sysconf(_SC_PAGESIZE)<=0) goto unavailable;
	snprintf(detail,sizeof(detail),"process_cpu_ns=%llu interval_ns=%llu process_cpu_ns_per_second=%.0f phase=%s process_user_total_ns=%llu process_system_total_ns=%llu rss_bytes=%llu errors=%u drops=%u unmeasured_kernel_reserve_bytes=16777216 memory_accounting_complete=0",
		(unsigned long long)delta,(unsigned long long)elapsed,
		elapsed?(double)delta*1000000000.0/elapsed:0.0,elapsed?"steady":"startup",
		(unsigned long long)usage.ru_utime.tv_sec*1000000000ULL+(unsigned long long)usage.ru_utime.tv_usec*1000,
		(unsigned long long)usage.ru_stime.tv_sec*1000000000ULL+(unsigned long long)usage.ru_stime.tv_usec*1000,
		(unsigned long long)rss*sysconf(_SC_PAGESIZE),ctx->errors,ctx->dropped);
	cis_report(ctx,"budget",NULL,detail);
	if ((rss*(uint64_t)sysconf(_SC_PAGESIZE)+(16ULL<<20)>ctx->memory_limit) ||
	    (elapsed && (double)delta/elapsed>(double)ctx->user_cpu_limit_ns/1000000000.0)) {
		cis_report(ctx,"budget_disable",NULL,"collectors detached, not merely output suppressed; coverage degraded");
		if(!ctx->capture) {
			ctx->mode=0;
			cis_report(ctx,"metrics_budget_disable",NULL,"resource polling stopped; control plane remains available, no active coverage");
		}
		cis_capture_stop(ctx);
		stop_fast(ctx);
	}
	ctx->last_process_ns=cpu; ctx->last_budget_ns=now;
	return;
unavailable:
	ctx->errors++;
	cis_report(ctx,"budget_unavailable",NULL,"CPU/RSS unavailable, not zero; all sampling and metrics stopped");
	cis_capture_stop(ctx); ctx->mode=0; ctx->last_budget_ns=now;
	stop_fast(ctx);
}
