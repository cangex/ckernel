// SPDX-License-Identifier: GPL-2.0
#include "include/cis.h"
#include <stdio.h>

const char *cis_state_name(enum cis_state s)
{
	static const char *names[] = { "WARMUP", "AMBIENT", "SUSPECT", "DIAGNOSING", "COOLDOWN" };
	return (unsigned int)s < 5 ? names[s] : "INVALID";
}

void cis_baseline_idle(struct cis_context *ctx,struct cis_root *r,const struct cis_metric *m,int deferred)
{
	char detail[384];
	int n;
	if(r->state==CIS_DIAGNOSING) {
		cis_capture_diagnostic(ctx,r,0); r->state=CIS_COOLDOWN;
		r->last_diag_ns=cis_clock_ns(); if(ctx->diagnostic) ctx->diagnostic--;
		cis_report(ctx,"diagnostic_stop",r,"container has no remaining tasks");
	}
	if(r->state!=CIS_COOLDOWN) r->state=CIS_WARMUP;
	r->pending=0; r->samples=r->deviations=0; r->previous.time_ns=0;
	r->ip_samples=r->lock_samples=r->reclaim_samples=0;
	n=snprintf(detail,sizeof(detail),"populated=0 memory_bytes=%llu memory_high=%llu memory_oom=%llu cpu_psi_fresh=%d cpu_psi_age_ns=%llu empty_full_interval_ms=5000 no_business_baseline_update=1",
		(unsigned long long)m->memory_current,(unsigned long long)m->memory_high,
		(unsigned long long)m->memory_oom,!deferred,
		(unsigned long long)(m->time_ns-r->full_metrics_ns));
	if(!deferred && n>0 && (size_t)n<sizeof(detail))
		snprintf(detail+n,sizeof(detail)-n," usage_us=%llu throttle_us=%llu cpu_wait_us=%llu memory_wait_us=%llu",
			(unsigned long long)m->usage_us,(unsigned long long)m->throttle_us,
			(unsigned long long)m->cpu_wait_us,(unsigned long long)m->memory_wait_us);
	cis_report(ctx,"metric_idle",r,detail);
}

void cis_baseline_update(struct cis_context *ctx, struct cis_root *r, const struct cis_metric *m)
{
	double wait, usage;
	uint64_t elapsed;
	char detail[256];
	if (!r->previous.time_ns || r->policy_epoch != ctx->epoch ||
	    m->usage_us < r->previous.usage_us || m->cpu_wait_us < r->previous.cpu_wait_us) {
		r->previous = *m; r->samples = 0; r->deviations = 0;
		r->policy_epoch = ctx->epoch;
		if(r->state != CIS_DIAGNOSING && r->state != CIS_COOLDOWN) r->state = CIS_WARMUP;
		return;
	}
	elapsed = m->time_ns - r->previous.time_ns;
	if (!elapsed) return;
	wait = (m->cpu_wait_us - r->previous.cpu_wait_us) * 1000.0 / elapsed;
	usage = (m->usage_us - r->previous.usage_us) * 1000.0 / elapsed;
	snprintf(detail, sizeof(detail), "cpu_wait_ratio=%.6f cpu_usage=%.6f throttle_us=%llu memory_wait_us=%llu memory_bytes=%llu",
		 wait, usage, (unsigned long long)(m->throttle_us-r->previous.throttle_us),
		 (unsigned long long)(m->memory_wait_us-r->previous.memory_wait_us),
		 (unsigned long long)m->memory_current);
	cis_report(ctx, "metric", r, detail);
	if (r->state == CIS_DIAGNOSING || r->state == CIS_COOLDOWN) {
		if(r->state==CIS_DIAGNOSING && (!m->populated ||
		   (!r->manual_diagnostic && ((r->diagnostic_kind&16)?!r->lock_samples:
		    (wait<.01 && m->memory_wait_us-r->previous.memory_wait_us<10000))))) {
			cis_capture_diagnostic(ctx,r,0); r->state=CIS_COOLDOWN;
			r->last_diag_ns=cis_clock_ns(); if(ctx->diagnostic) ctx->diagnostic--;
			cis_report(ctx,"diagnostic_stop",r,m->populated?"anomaly receded":"container has no remaining tasks");
		}
		r->previous = *m;
		r->ip_samples=r->lock_samples=r->reclaim_samples=0;
		return;
	}
	if (r->samples++ < ctx->warmup) {
		r->baseline_wait += (wait-r->baseline_wait)/r->samples;
		r->baseline_usage += (usage-r->baseline_usage)/r->samples;
		if (r->samples == ctx->warmup) r->state = CIS_AMBIENT;
	} else if (r->state == CIS_AMBIENT || r->state == CIS_SUSPECT) {
		int anomaly = wait > 0.02 && (wait > r->baseline_wait * 2 + 0.01 || wait>.2);
		int pressure = m->memory_wait_us > r->previous.memory_wait_us + 20000;
		if (anomaly || pressure) {
			r->deviations++;
			r->state = CIS_SUSPECT;
			if (r->deviations >= 3) {
				r->pending = 1;
				r->manual_diagnostic = 0;
				r->requested_start_ns = 0;
				r->diagnostic_kind = pressure ? 4 : r->lock_samples>=4 && r->ip_samples>=8 ? (ctx->fast_alert?16:2) : 1;
			}
			cis_report(ctx, "E0", r, "sustained deviation; demand/phase/external cause unresolved");
		} else {
			r->deviations = 0; r->pending = 0; r->state = CIS_AMBIENT;
			/* Never train through a sustained anomaly. */
			r->baseline_wait = .98*r->baseline_wait + .02*wait;
			r->baseline_usage = .98*r->baseline_usage + .02*usage;
		}
	}
	r->previous = *m;
	r->ip_samples=r->lock_samples=r->reclaim_samples=0;
}

void cis_diagnostics_tick(struct cis_context *ctx, uint64_t now)
{
	unsigned int i;
	for (i = 0; i < CIS_MAX_ROOTS; i++) {
		struct cis_root *r = &ctx->roots[i];
		if (!r->used) continue;
		if (r->state == CIS_DIAGNOSING && now >= r->deadline_ns) {
			cis_capture_diagnostic(ctx, r, 0);
			r->state = CIS_COOLDOWN; r->last_diag_ns = now;
			if (ctx->diagnostic) ctx->diagnostic--;
			cis_report(ctx, "diagnostic_stop", r, "window expired; incomplete pairs retained as incomplete");
		}
		if (r->state == CIS_COOLDOWN && now-r->last_diag_ns >= ctx->cooldown_s*1000000000ULL)
			r->state = CIS_AMBIENT;
	}
	for (i = 0; i < CIS_MAX_ROOTS && ctx->diagnostic < ctx->max_diagnostics; i++) {
		unsigned int k = (ctx->queue_cursor+i)%CIS_MAX_ROOTS;
		struct cis_root *r = &ctx->roots[k];
		if (!r->used || !r->pending || r->state == CIS_COOLDOWN || r->state == CIS_DIAGNOSING) continue;
		r->pending = 0;
		if (!ctx->capture || cis_capture_diagnostic(ctx, r, 1)) {
			cis_report(ctx, "diagnostic_unavailable", r, "capture unavailable; no evidence fabricated"); continue;
		}
		r->state = CIS_DIAGNOSING;
		ctx->diagnostic++; ctx->queue_cursor = (k+1)%CIS_MAX_ROOTS;
		{
			char detail[192];
			snprintf(detail,sizeof(detail),"start_ns=%llu deadline_ns=%llu ready_ns=%llu bounded_target_window=1 collector_mask=%u owner_protocol=2",
				(unsigned long long)r->diagnostic_start_ns,(unsigned long long)r->deadline_ns,
				(unsigned long long)cis_clock_ns(),r->diagnostic_kind);
			cis_report(ctx, "diagnostic_start", r, detail);
		}
		break;
	}
}
