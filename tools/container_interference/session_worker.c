// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include "include/cis_recursion_snapshot.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t cancelled;
static void stop_signal(int sig) { (void)sig; cancelled=1; }
static int notify(int fd,const char *text)
{
	return send(fd,text,strlen(text),MSG_NOSIGNAL|MSG_DONTWAIT)==(ssize_t)strlen(text)?0:-1;
}
static uint64_t cpu_ns(void)
{
	struct timespec ts; clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&ts);
	return ts.tv_sec*1000000000ULL+ts.tv_nsec;
}

static int recursion_snapshot(struct cis_recursion_snapshot *s)
{
	FILE *file=fopen("/sys/kernel/debug/cis_recursion","r");
	int rc;
	if(!file) return -1;
	rc=cis_recursion_read(file,s);
	fclose(file);
	return rc;
}

/* No shell, process-name cleanup, pins, or reused BPF objects. Inherited FDs are
 * supplied only by the administrator controller, with immutable identities. */
int main(int argc,char **argv)
{
	struct cis_context *ctx=calloc(1,sizeof(*ctx));
	struct pollfd control;
	struct rusage usage;
	struct cis_recursion_snapshot recursion_before,recursion_after;
	char packet[4096],inventory[3072];
	const char *reason="COMPLETE";
	uint64_t begin=cis_clock_ns(),prepared=0,start=0,end=0,stopped=0,cpu_begin=cpu_ns(),budget_cpu=0,budget_time=0;
	uint64_t prepared_cpu=0,capture_cpu=0,stop_cpu=0;
	uint64_t recursion_skipped=0;
	int recursion_started=0,recursion_valid=0;
	int i,targets=0,err=0,stop_error=0,capture_error=0,channel,window,parent=getppid();
	if(!ctx || argc<9 || argc>8+CIS_MAX_ROOTS) return 2;
	channel=atoi(argv[1]); ctx->output_fd=atoi(argv[2]);
	ctx->session_id=strtoull(argv[3],NULL,10); window=atoi(argv[5]);
	ctx->session_collector=!strcmp(argv[4],"ip")?1:!strcmp(argv[4],"owner")?2:
		!strcmp(argv[4],"sched")?3:!strcmp(argv[4],"reclaim")?4:!strcmp(argv[4],"sync")?5:!strcmp(argv[4],"fd")?6:!strcmp(argv[4],"counter")?7:!strcmp(argv[4],"allocator")?8:!strcmp(argv[4],"net")?9:0;
	if(!ctx->session_id || !ctx->session_collector || window<100 || window>10000) return 2;
	ctx->output_limit=16ULL<<20; ctx->identity_only=1; ctx->psi_epoll=-1;
	ctx->window_ms=window; ctx->ip_hz=1000; ctx->entry_rate_limit=200000;
	ctx->max_diagnostics=2; ctx->memory_limit=64ULL<<20;
	if(!strncmp(argv[7],"fail_",5)) ctx->fault_stage=argv[7]+5;
	signal(SIGTERM,stop_signal); signal(SIGINT,stop_signal);
	if(prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent) return 3;
	control=(struct pollfd){.fd=channel,.events=POLLIN};
	if(!strncmp(argv[7],"fd_limit_",9)) {
		char *tail;
		unsigned long value=strtoul(argv[7]+9,&tail,10);
		struct rlimit nofile={value,value};
		if(*tail || value<4 || value>24 || setrlimit(RLIMIT_NOFILE,&nofile)) {
			err=1; reason="FD_LIMIT_INJECTION"; goto drain;
		}
		{
			struct rlimit actual;
			char detail[160];
			if(getrlimit(RLIMIT_NOFILE,&actual)) { err=1; reason="FD_LIMIT_READBACK"; goto drain; }
			snprintf(detail,sizeof(detail),"stage=fd_limit requested=%lu soft=%llu hard=%llu",
				value,(unsigned long long)actual.rlim_cur,(unsigned long long)actual.rlim_max);
			cis_report(ctx,"fault_injection",NULL,detail);
		}
	}
	for(i=8;i<argc;i++) {
		unsigned long long id,gen; int fd,n=0; char role; struct cis_root *r;
		if(sscanf(argv[i],"%c:%d:%llu:%llu%n",&role,&fd,&id,&gen,&n)!=4 || argv[i][n] ||
		   !id || !gen || (role!='t' && role!='i') ||
		   (role=='i' && ctx->session_collector!=2 && ctx->session_collector!=6 && ctx->session_collector!=9) ||
		   cis_registry_add(ctx,fd,role=='t'?"target":"identity-only",&r) || r->id!=id) {
			err=1; reason="IDENTITY"; goto drain;
		}
		r->generation=gen; r->session_target=role=='t'; targets+=r->session_target; close(fd);
	}
	if(targets<1 || targets>2) { err=1; reason="TARGETS"; goto drain; }
	if(ctx->session_collector>=2) {
		if(recursion_snapshot(&recursion_before)) { err=1; reason="RECURSION_BASELINE"; goto drain; }
		recursion_started=1;
	}
	if(cis_symbols_load(ctx)) { err=1; reason="SYMBOLS"; goto drain; }
	if(cis_capture_prepare(ctx,argv[6])) { err=1; reason="PREPARE"; goto drain; }
	if(cis_capture_inventory(ctx,inventory,sizeof(inventory))) { err=1; reason="INVENTORY"; goto drain; }
	prepared=cis_clock_ns();
	prepared_cpu=cpu_ns();
	snprintf(packet,sizeof(packet),"{\"state\":\"ARMED\",\"time_ns\":%llu,\"inventory\":%s}",(unsigned long long)prepared,inventory);
	if(notify(channel,packet)) { err=1; reason="CONTROL_LOST"; goto drain; }
	/* The parent journals ownership before authorizing the first active probe. */
	if(poll(&control,1,10000)<=0 || recv(channel,packet,sizeof(packet)-1,0)!=3 || memcmp(packet,"ARM",3) || cancelled) {
		reason="CANCELLED"; goto drain;
	}
	if(!strcmp(argv[7],"after_prepare")) { err=1; reason="INJECTED_PREPARE"; goto drain; }
	/* Load the bounded identity universe before the timed arm interval. The
	 * controller pins these roots and disallows registration changes meanwhile. */
	for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used) {
		struct cis_root *r=&ctx->roots[i];
		if(cis_capture_root(ctx,r,1)) { err=1; reason="ROOT_MAP"; goto drain; }
	}
	start=cis_clock_ns()+100000000ULL; end=start+window*1000000ULL;
	for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used && ctx->roots[i].session_target) {
		struct cis_root *r=&ctx->roots[i];
		if(ctx->session_collector>=2) {
			r->diagnostic_kind=(ctx->session_collector==2 || ctx->session_collector==6)?16:ctx->session_collector==3?1:ctx->session_collector==5?2:ctx->session_collector==7?32:ctx->session_collector==8?64:ctx->session_collector==9?128:4;
			r->requested_start_ns=start;
			if(cis_capture_diagnostic(ctx,r,1)) { err=1; reason="DIAGNOSTIC_ATTACH"; goto drain; }
			r->state=CIS_DIAGNOSING; ctx->diagnostic++;
		}
	}
	if(cis_capture_arm(ctx,start,end) || cis_clock_ns()>=start) { err=1; reason="ARM_LATE"; goto drain; }
	snprintf(packet,sizeof(packet),"{\"state\":\"CAPTURING\",\"start_ns\":%llu,\"end_ns\":%llu}",(unsigned long long)start,(unsigned long long)end);
	if(notify(channel,packet)) { err=1; reason="CONTROL_LOST"; goto drain; }
	budget_time=start; budget_cpu=cpu_ns();
	capture_cpu=budget_cpu;
	while(!cancelled && cis_clock_ns()<end) {
		uint64_t now=cis_clock_ns();
		int p=poll(&control,1,10);
		if(p>0) { reason="CANCELLED"; break; }
		if(p<0 && errno!=EINTR) { err=1; reason="POLL"; break; }
		capture_error=cis_capture_poll(ctx);
		if(capture_error<0) {
			err=1; reason=capture_error==-E2BIG?"ENTRY_RATE_LIMIT":"CAPTURE_ERROR"; break;
		}
		if(ctx->output_error) { err=1; reason=ctx->output_error==EFBIG?"DATA_LIMIT":"OUTPUT_ERROR"; break; }
		if(now>budget_time+1000000000ULL) {
			uint64_t cpu=cpu_ns();
			if(cpu-budget_cpu>20000000ULL) { err=1; reason="WORKER_CPU_LIMIT"; break; }
			budget_time=now; budget_cpu=cpu;
		}
	}
	if(cancelled) reason="CANCELLED";
drain:
	notify(channel,"{\"state\":\"DRAIN\"}");
	stop_error=cis_capture_quiesce(ctx);
	if(ctx->session_collector>=2 && recursion_started) {
		if(!recursion_snapshot(&recursion_after) &&
		   !cis_recursion_delta(&recursion_before,&recursion_after,&recursion_skipped)) {
			recursion_valid=1;
			if(recursion_skipped) { err=1; reason="RECURSION_GAP"; }
		} else { err=1; reason="RECURSION_TERMINAL"; }
	}
	/* Source snapshot v3 waits out raw-tp callbacks before map/ring teardown.
	 * A failed barrier cannot produce a valid terminal capture receipt. */
	if(ctx->session_collector>=2 && recursion_started && !recursion_valid && !stop_error)
		stop_error=-EIO;
	stopped=cis_clock_ns(); stop_cpu=cpu_ns();
	cis_capture_stop(ctx);
	/* A skip after the last emitted event cannot be recovered from BPF's last
	 * observed source counter. Preserve that counter and audit the producer too. */
	{
		char detail[256];
		snprintf(detail,sizeof(detail),"required=%u valid=%u skipped=%llu scope=quiescent_raw_tp_session",
			ctx->session_collector>=2,recursion_valid,(unsigned long long)recursion_skipped);
		cis_report(ctx,"producer_recursion",NULL,detail);
	}
	cis_registry_destroy(ctx); cis_symbols_free(ctx);
	if(ctx->errors || ctx->dropped || ctx->output_error) err=1;
	if(err && !strcmp(reason,"COMPLETE")) reason="QUALITY";
	if(close(ctx->output_fd)) { err=1; reason="OUTPUT_CLOSE"; }
	getrusage(RUSAGE_SELF,&usage);
	snprintf(packet,sizeof(packet),"{\"state\":\"VERIFY\",\"result\":\"%s\",\"reason\":\"%s\",\"begin_ns\":%llu,\"prepared_ns\":%llu,\"start_ns\":%llu,\"end_ns\":%llu,\"producers_stopped_ns\":%llu,\"destroyed_ns\":%llu,\"cpu_ns\":%llu,\"maxrss_kib\":%ld,\"errors\":%u,\"dropped\":%u,\"output_error\":%d,\"bytes\":%llu,\"stop_error\":%d,\"capture_error\":%d,\"prepare_cpu_ns\":%llu,\"armed_capture_cpu_ns\":%llu,\"drain_cpu_ns\":%llu,\"terminal\":{\"valid\":%s,\"received\":%llu,\"emitted\":%llu,\"rejected\":%llu,\"lost\":%llu,\"owner_skipped\":%llu}}",
		!strcmp(reason,"CANCELLED")?"CANCELLED":err?"PARTIAL":"COMPLETE",reason,
		(unsigned long long)begin,(unsigned long long)prepared,(unsigned long long)start,(unsigned long long)end,
		(unsigned long long)stopped,(unsigned long long)cis_clock_ns(),(unsigned long long)(cpu_ns()-cpu_begin),
		usage.ru_maxrss,ctx->errors,ctx->dropped,ctx->output_error,(unsigned long long)ctx->output_bytes,stop_error,capture_error,
		(unsigned long long)(prepared_cpu?prepared_cpu-cpu_begin:0),
		(unsigned long long)(capture_cpu?stop_cpu-capture_cpu:0),(unsigned long long)(cpu_ns()-stop_cpu),
		ctx->terminal_valid?"true":"false",(unsigned long long)ctx->terminal_received,
		(unsigned long long)ctx->terminal_emitted,(unsigned long long)ctx->terminal_rejected,
		(unsigned long long)ctx->terminal_lost,(unsigned long long)ctx->terminal_owner_skipped);
	/* Append without enlarging the hot-path event schema. */
	{
		size_t n=strlen(packet);
		if(n && packet[n-1]=='}')
			snprintf(packet+n-1,sizeof(packet)-n+1,",\"producer_recursion\":{\"required\":%s,\"valid\":%s,\"skipped\":%llu}}",
				ctx->session_collector>=2?"true":"false",recursion_valid?"true":"false",
				(unsigned long long)recursion_skipped);
	}
	notify(channel,packet); close(channel); free(ctx);
	return stop_error?4:err?1:0;
}
