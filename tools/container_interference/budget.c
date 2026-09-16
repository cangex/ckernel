// SPDX-License-Identifier: GPL-2.0
#include "include/cis.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
void cis_budget_tick(struct cis_context *ctx,uint64_t now)
{
	struct timespec t;
	unsigned long rss=0,unused;
	uint64_t cpu;
	FILE *f;
	char detail[256];
	if (now-ctx->last_budget_ns<1000000000ULL) return;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t);
	cpu=(uint64_t)t.tv_sec*1000000000+t.tv_nsec;
	f=fopen("/proc/self/statm","r");
	if (f) { if(fscanf(f,"%lu %lu",&unused,&rss)!=2) rss=0; fclose(f); }
	snprintf(detail,sizeof(detail),"user_cpu_ns=%llu rss_bytes=%llu errors=%u drops=%u maps_and_perf_budget_reserved_bytes=16777216",
		(unsigned long long)(cpu-ctx->last_process_ns),(unsigned long long)rss*sysconf(_SC_PAGESIZE),ctx->errors,ctx->dropped);
	cis_report(ctx,"budget",NULL,detail);
	if ((rss*(uint64_t)sysconf(_SC_PAGESIZE)+(16ULL<<20)>ctx->memory_limit) ||
	    (ctx->last_process_ns && cpu-ctx->last_process_ns>ctx->user_cpu_limit_ns)) {
		cis_report(ctx,"budget_disable",NULL,"collectors detached, not merely output suppressed; coverage degraded");
		if(!ctx->capture) {
			ctx->mode=0;
			cis_report(ctx,"metrics_budget_disable",NULL,"resource polling stopped; control plane remains available, no active coverage");
		}
		cis_capture_stop(ctx);
	}
	ctx->last_process_ns=cpu; ctx->last_budget_ns=now;
}
