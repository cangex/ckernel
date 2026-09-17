// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

void cis_fast_close(struct cis_context *ctx, struct cis_root *r)
{
	unsigned int i;
	for(i=0;i<2;i++) if(r->psi_fd[i]>=0) {
		if(ctx->psi_epoll>=0) epoll_ctl(ctx->psi_epoll,EPOLL_CTL_DEL,r->psi_fd[i],NULL);
		close(r->psi_fd[i]); r->psi_fd[i]=-1;
	}
}

int cis_fast_open(struct cis_context *ctx, struct cis_root *r)
{
	static const char *names[]={"cpu.pressure","memory.pressure"};
	const char trigger[]="some 20000 500000";
	unsigned int i;
	if(!ctx->fast_alert) return 0;
	for(i=0;i<2;i++) {
		struct epoll_event e={.events=EPOLLPRI|EPOLLERR};
		/* Slot+generation is checked again; a reused FD is never an identity. */
		e.data.u64=(r->generation<<10)|((r-ctx->roots)<<1)|i;
		r->psi_fd[i]=openat(r->fd,names[i],O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW);
		if(r->psi_fd[i]<0 || write(r->psi_fd[i],trigger,sizeof(trigger)-1)!=(ssize_t)sizeof(trigger)-1 ||
		   epoll_ctl(ctx->psi_epoll,EPOLL_CTL_ADD,r->psi_fd[i],&e)) {
			cis_fast_close(ctx,r); return -EIO;
		}
	}
	return 0;
}

void cis_fast_poll(struct cis_context *ctx)
{
	struct epoll_event events[16];
	int n,j;
	if(!ctx->fast_alert || !ctx->mode || ctx->psi_epoll<0) return;
	n=epoll_wait(ctx->psi_epoll,events,16,0);
	if(n<0) { if(errno!=EINTR) ctx->errors++; return; }
	for(j=0;j<n;j++) {
		unsigned int slot=(events[j].data.u64>>1)&255,kind=events[j].data.u64&1;
		struct cis_root *r=&ctx->roots[slot];
		uint64_t now=cis_clock_ns();
		char detail[256],buf[512];
		if(!r->used || !r->ready || (r->generation&((1ULL<<54)-1))!=(events[j].data.u64>>10)) continue;
		if(events[j].events&EPOLLERR) {
			cis_report(ctx,"fast_source_error",r,"PSI source closed or invalid; fast coverage unavailable");
			cis_fast_close(ctx,r); continue;
		}
		/* Reading acknowledges the poll event; the kernel enforces trigger rate limits. */
		if(pread(r->psi_fd[kind],buf,sizeof(buf)-1,0)<0) {ctx->errors++;continue;}
		if(now-r->fast_alert_ns<500000000ULL) continue;
		r->fast_alert_ns=now;
		snprintf(detail,sizeof(detail),"resource=%s window_us=500000 stall_us=20000 received_ns=%llu baseline_ready=%d candidate_only=1 cause=unresolved",
			kind?"memory":"cpu",(unsigned long long)now,r->samples>=ctx->warmup);
		cis_report(ctx,"FAST_ALERT",r,detail);
		if(r->state!=CIS_DIAGNOSING && r->state!=CIS_COOLDOWN) {
			int owner_pending=r->pending && (r->diagnostic_kind&16);
			r->pending=1; r->manual_diagnostic=0; r->requested_start_ns=0;
			if(!owner_pending) r->diagnostic_kind=kind?4:1;
			/* Early suspicion is not a learned-baseline or external-cause claim. */
			r->state=CIS_SUSPECT;
		}
	}
}
