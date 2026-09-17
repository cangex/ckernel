// SPDX-License-Identifier: GPL-2.0
#include "../../../container_interference/include/cis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
static unsigned int stopped, unavailable, failed;
static int have_rss;
static uint64_t process_ns;
FILE *__wrap_fopen(const char *path,const char *mode)
{
	FILE *f;
	(void)path; (void)mode;
	if(!have_rss) return NULL;
	f=tmpfile();
	if(f) { fputs("200 100\n",f); rewind(f); }
	return f;
}
int __wrap_clock_gettime(clockid_t id,struct timespec *t)
{ (void)id; t->tv_sec=process_ns/1000000000ULL; t->tv_nsec=process_ns%1000000000ULL; return 0; }
int __wrap_getrusage(int who,struct rusage *r)
{ (void)who; memset(r,0,sizeof(*r)); return 0; }
void cis_capture_stop(struct cis_context *ctx) { stopped++; ctx->capture=NULL; }
void cis_fast_close(struct cis_context *ctx,struct cis_root *r) { (void)ctx; r->psi_fd[0]=r->psi_fd[1]=-1; }
void cis_report(struct cis_context *ctx,const char *kind,const struct cis_root *r,const char *detail)
{ (void)ctx; (void)r; (void)detail; unavailable+=!strcmp(kind,"budget_unavailable"); }
int main(void)
{
	struct cis_context *ctx=calloc(1,sizeof(*ctx));
	if(!ctx) return 1;
	ctx->mode=2; ctx->capture=ctx; ctx->memory_limit=64ULL<<20;
	ctx->fast_alert=1; ctx->roots[0].used=1; ctx->roots[0].psi_fd[0]=5;
	cis_budget_tick(ctx,2000000000ULL);
	failed=ctx->mode!=0 || ctx->capture || ctx->errors!=1 || stopped!=1 || unavailable!=1 || ctx->fast_alert || ctx->roots[0].psi_fd[0]!=-1;
	printf("CIS_BUDGET_TEST missing_rss_fails_closed %s\n",failed?"FAIL":"PASS");
	have_rss=1;
	for(unsigned int i=0;i<4;i++) {
		memset(ctx,0,sizeof(*ctx)); stopped=unavailable=0;
		ctx->mode=2;ctx->capture=ctx;ctx->memory_limit=64ULL<<20;ctx->user_cpu_limit_ns=20000000;
		ctx->last_budget_ns=1000000000;ctx->last_process_ns=10000000;
		process_ns=i==0?40000000:i==1?55000000:i==2?90000000:1;
		if(i==2) {ctx->last_budget_ns=0;ctx->last_process_ns=0;}
		cis_budget_tick(ctx,3000000000);
		int bad=!!stopped!=(i==1 || i==3);
		failed+=bad;
		printf("CIS_BUDGET_TEST case=%u interval_normalized %s\n",i,bad?"FAIL":"PASS");
	}
	free(ctx); return !!failed;
}
