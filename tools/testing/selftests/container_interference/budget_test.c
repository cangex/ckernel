// SPDX-License-Identifier: GPL-2.0
#include "../../../container_interference/include/cis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned int stopped, unavailable, failed;
FILE *__wrap_fopen(const char *path,const char *mode)
{ (void)path; (void)mode; return NULL; }
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
	free(ctx); return !!failed;
}
