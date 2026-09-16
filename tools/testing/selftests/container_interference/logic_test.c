// SPDX-License-Identifier: GPL-2.0
#include "../../../container_interference/include/cis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t now;
static unsigned int failures, checks, starts, stops;
uint64_t cis_clock_ns(void) { return now; }
void cis_report(struct cis_context *c,const char *kind,const struct cis_root *r,const char *d)
{ (void)c; (void)kind; (void)r; (void)d; }
int cis_capture_diagnostic(struct cis_context *c,struct cis_root *r,int enable)
{ (void)c; (void)r; if(enable) starts++; else stops++; return 0; }
#define CHECK(n,x) do { int ok=!!(x); checks++; failures+=!ok; printf("CIS_LOGIC %s %s\n",n,ok?"PASS":"FAIL"); } while(0)
int main(void)
{
	struct cis_context *c=calloc(1,sizeof(*c));
	struct cis_root *r;
	struct cis_metric m={.populated=1};
	unsigned int i;
	if(!c) return 1;
	c->epoch=1; c->warmup=5; c->cooldown_s=30; c->window_ms=2000; c->max_diagnostics=2; c->capture=c;
	r=&c->roots[0]; r->used=1; r->policy_epoch=1;
	for(i=0;i<6;i++) {
		now+=1000000000; m.time_ns=now; m.usage_us+=100000;
		cis_baseline_update(c,r,&m);
	}
	CHECK("warmup_enters_ambient",r->state==CIS_AMBIENT);
	for(i=0;i<3;i++) {
		now+=1000000000; m.time_ns=now; m.cpu_wait_us+=300000;
		cis_baseline_update(c,r,&m);
	}
	CHECK("persistent_anomaly_freezes_learning",r->pending && r->baseline_wait==0);
	cis_diagnostics_tick(c,now);
	CHECK("auto_starts_one_window",starts==1 && c->diagnostic==1 && r->state==CIS_DIAGNOSING);
	now+=2000000000; cis_diagnostics_tick(c,now);
	CHECK("deadline_detaches",stops==1 && c->diagnostic==0 && r->state==CIS_COOLDOWN);
	r->pending=1; cis_diagnostics_tick(c,now);
	CHECK("cooldown_rejects_reentry",starts==1);
	now+=31000000000ULL; cis_diagnostics_tick(c,now);
	CHECK("cooldown_eventually_releases",starts==2);
	r->previous.time_ns=0; r->manual_diagnostic=1; m.time_ns=now;
	cis_baseline_update(c,r,&m);
	CHECK("first_metric_does_not_erase_manual_window",r->state==CIS_DIAGNOSING);
	now+=1000000000; m.time_ns=now; m.populated=0;
	cis_baseline_update(c,r,&m);
	CHECK("empty_root_detaches",r->state==CIS_COOLDOWN && c->diagnostic==0);
	memset(c->roots,0,sizeof(c->roots)); c->queue_cursor=0;
	for(i=0;i<256;i++) { c->roots[i].used=1; c->roots[i].pending=1; }
	cis_diagnostics_tick(c,now); cis_diagnostics_tick(c,now); cis_diagnostics_tick(c,now);
	CHECK("storm_respects_two_target_capacity",c->diagnostic==2);
	CHECK("round_robin_selects_distinct_targets",c->roots[0].state==CIS_DIAGNOSING && c->roots[1].state==CIS_DIAGNOSING);
	now+=2000000000; cis_diagnostics_tick(c,now); cis_diagnostics_tick(c,now);
	CHECK("queue_progresses_after_expiry",c->roots[2].state==CIS_DIAGNOSING && c->roots[3].state==CIS_DIAGNOSING);
	printf("CIS_LOGIC_RESULT checks=%u failures=%u\n",checks,failures);
	free(c); return !!failures;
}
