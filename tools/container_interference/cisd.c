// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t quitting;
static void stop_signal(int sig) { (void)sig; quitting = 1; }

static uint64_t profile_cpu(void)
{
	struct timespec t;
	if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t)) return 0;
	return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}

static int server(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;
	if (strlen(path) >= sizeof(addr.sun_path)) return -1;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
	if (fd < 0) return -1;
	/* Never unlink a socket potentially owned by another daemon. */
	if (bind(fd, (void *)&addr, sizeof(addr)) || chmod(path, 0600) || listen(fd, 8)) {
		close(fd); return -1;
	}
	return fd;
}

static void request(struct cis_context *ctx, int fd)
{
	struct cis_request req = { 0 };
	struct cis_reply rep = { .error = -EINVAL, .size = sizeof(rep) };
	char control[CMSG_SPACE(sizeof(int)*8)] = { 0 };
	struct iovec iov = { &req, sizeof(req) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *cm;
	struct ucred cred;
	socklen_t size = sizeof(cred);
	struct cis_root *r = NULL;
	int passed[8], nfds = 0;
	unsigned int i;
	ssize_t n;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &size) || cred.uid) goto done;
	n = recvmsg(fd, &msg, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
			size_t count = (cm->cmsg_len-CMSG_LEN(0))/sizeof(int);
			int *p = (void *)CMSG_DATA(cm);
			for (i = 0; i < count; i++) { if (nfds < 8) passed[nfds++] = p[i]; else close(p[i]); }
		}
	}
	if (n != sizeof(req) || (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) || req.version != CIS_VERSION ||
	    req.size != sizeof(req) || req.reserved || !memchr(req.name, 0, sizeof(req.name))) goto done;
	if (req.command != CIS_REGISTER && nfds) goto done;
	if (req.command != CIS_DIAGNOSE && req.start_ns) goto done;
	switch (req.command) {
	case CIS_REGISTER:
		if (nfds != 1) break;
		rep.error = cis_registry_add(ctx, passed[0], req.name, &r);
		if (!rep.error) {
			rep.id = r->id; rep.generation = r->generation;
			cis_report(ctx, "register", r, "host cgroup2 root; bounded ancestor lookup includes descendants");
		}
		break;
	case CIS_UNREGISTER:
		rep.error = cis_registry_remove(ctx, req.id, req.generation); break;
	case CIS_STATUS:
		rep.error = 0;
		snprintf(rep.text, sizeof(rep.text), "roots=%u diagnostics=%u mode=%d capture=%d errors=%u dropped=%u epoch=%llu",
			 ctx->active, ctx->diagnostic, ctx->mode, !!ctx->capture, ctx->errors, ctx->dropped,
			 (unsigned long long)ctx->epoch); break;
	case CIS_DIAGNOSE:
		if(strcmp(req.name,"sched") && strcmp(req.name,"lock") && strcmp(req.name,"reclaim") && strcmp(req.name,"work") && strcmp(req.name,"owner")) break;
		{
			uint64_t now=cis_clock_ns();
			if(req.start_ns && (req.start_ns<=now || req.start_ns-now>2000000000ULL)) break;
		}
		rep.error = -ENOENT;
		for (i = 0; i < CIS_MAX_ROOTS; i++) {
			r = &ctx->roots[i];
			if (r->used && r->id == req.id && r->generation == req.generation) {
				if (!ctx->capture) { rep.error = -EOPNOTSUPP; break; }
				if (r->state == CIS_COOLDOWN || r->state == CIS_DIAGNOSING) { rep.error = -EAGAIN; break; }
				r->diagnostic_kind = !strcmp(req.name,"owner")?16:!strcmp(req.name,"lock")?2:!strcmp(req.name,"reclaim")?4:!strcmp(req.name,"work")?8:1;
				r->manual_diagnostic = 1;
				r->requested_start_ns = req.start_ns;
				r->pending = 1; rep.error = 0; break;
			}
		}
		break;
	case CIS_STOP: ctx->stopping = 1; rep.error = 0; break;
	default: rep.error = -EOPNOTSUPP;
	}
done:
	for (i = 0; i < (unsigned int)nfds; i++) close(passed[i]);
	if (send(fd, &rep, sizeof(rep), MSG_DONTWAIT|MSG_NOSIGNAL) < 0) ctx->errors++;
}

int main(int argc, char **argv)
{
	struct cis_context *ctx = calloc(1, sizeof(*ctx));
	const char *socket_path = CIS_SOCKET, *object = "bpf/cis.bpf.o", *output = NULL;
	int i, status = 1, ready_fd = -1;
	uint64_t end = 0, next_control_ns = 0;
	uint64_t profile_totals[4]={0}, profile_loops=0, profile_requests=0, profile_due=0;
	if (!ctx || geteuid()) { fprintf(stderr, "root in host namespaces required\n"); return 1; }
	umask(077);
	ctx->warmup=5; ctx->max_diagnostics=2; ctx->cooldown_s=30; ctx->window_ms=2000;
	ctx->ip_hz=1000; ctx->memory_limit=64ULL<<20; ctx->user_cpu_limit_ns=20000000;
	ctx->entry_rate_limit=200000;
	ctx->epoch=1; ctx->mode=1; ctx->socket_fd=-1; ctx->output_fd=STDOUT_FILENO;
	ctx->psi_epoll=-1;
	if (getrandom(&ctx->boot_generation, sizeof(ctx->boot_generation), 0) != sizeof(ctx->boot_generation)) goto out;
	ctx->boot_generation &= 0x7fffffffffff0000ULL;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--socket") && i+1 < argc) socket_path=argv[++i];
		else if (!strcmp(argv[i], "--output") && i+1 < argc) output=argv[++i];
		else if (!strcmp(argv[i], "--bpf") && i+1 < argc) object=argv[++i];
		else if (!strcmp(argv[i], "--mode") && i+1 < argc) {
			const char *m=argv[++i]; ctx->mode=!strcmp(m,"off")?0:!strcmp(m,"metrics")?1:!strcmp(m,"ip")?2:-1;
		} else if (!strcmp(argv[i], "--seconds") && i+1 < argc) end=cis_clock_ns()+strtoul(argv[++i],NULL,10)*1000000000ULL;
		else if (!strcmp(argv[i], "--profile-loop")) ctx->profile_loop=1;
		else if (!strcmp(argv[i], "--fast-alert")) ctx->fast_alert=1;
		else if (!strcmp(argv[i], "--ready-fd") && i+1 < argc) ready_fd=atoi(argv[++i]);
		else if (!strcmp(argv[i], "--entry-rate-limit") && i+1 < argc) {
			char *endp;
			unsigned long value=strtoul(argv[++i],&endp,10);
			if(*endp || !value || value>200000) goto out;
			ctx->entry_rate_limit=value;
		}
		else { fprintf(stderr, "invalid option: %s\n", argv[i]); goto out; }
	}
	if (ctx->mode < 0) goto out;
	if(ctx->fast_alert) {
		if(!ctx->mode || (ctx->psi_epoll=epoll_create1(EPOLL_CLOEXEC))<0) goto out;
	}
	{
		struct rlimit limit;
		if(getrlimit(RLIMIT_NOFILE,&limit)) goto out;
		if(limit.rlim_cur<8192) {
			limit.rlim_cur=limit.rlim_max<8192?limit.rlim_max:8192;
			if(limit.rlim_cur<4096 || setrlimit(RLIMIT_NOFILE,&limit)) {
				fprintf(stderr,"CIS requires at least 4096 file descriptors for bounded capacity\n"); goto out;
			}
		}
	}
	if (output) {
		ctx->output_fd=open(output,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NONBLOCK,0600);
		if (ctx->output_fd < 0) { perror("output"); goto out; }
	}
	ctx->socket_fd=server(socket_path);
	if (ctx->socket_fd < 0) { perror("socket"); goto out; }
	signal(SIGTERM,stop_signal); signal(SIGINT,stop_signal); signal(SIGPIPE,SIG_IGN);
	if(ctx->mode==2 && cis_symbols_load(ctx)) cis_report(ctx,"symbols_unavailable",NULL,"numeric IP only; automatic lock selection unavailable");
	if (ctx->mode == 2 && cis_capture_start(ctx,object)) {
		cis_report(ctx,"capture_failure",NULL,"requested IP mode did not start; no silent metrics fallback"); goto out;
	}
	cis_report(ctx,"start",NULL,"no workload interference percentage inferred; report files host-admin only");
	{
		char budget[96];
		snprintf(budget,sizeof(budget),"entry_rate_limit=%u ip_hz=%u",ctx->entry_rate_limit,ctx->ip_hz);
		cis_report(ctx,"capture_policy",NULL,budget);
		cis_report(ctx,"metric_policy",NULL,"populated_full_interval_ms=1000 empty_presence_memory_interval_ms=1000 empty_cpu_psi_interval_ms=5000 empty_samples_never_train_business_baseline=1");
	}
	if (ready_fd >= 0) { if (write(ready_fd,"R",1)!=1) goto out; close(ready_fd); }
	while (!quitting && !ctx->stopping && (!end || cis_clock_ns()<end)) {
		struct pollfd fds[3]={{ctx->socket_fd,POLLIN,0},{ctx->mode?ctx->psi_epoll:-1,POLLIN,0},{cis_capture_fd(ctx),POLLIN,0}};
		uint64_t now=cis_clock_ns(),wake=now+(ctx->capture?100000000:1000000000);
		int timeout;
		uint64_t segment=0;
		/* Backpressure only administrator requests, never business execution. */
		if(now<next_control_ns) {
			fds[0].events=0;
			if(next_control_ns<wake) wake=next_control_ns;
		}
		/* Wake for actual deadlines, not a perpetual 100-Hz metrics-only poll. */
		for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used) {
			struct cis_root *r=&ctx->roots[i];
			if(ctx->mode && r->next_ns<wake) wake=r->next_ns;
			if(r->state==CIS_DIAGNOSING && r->deadline_ns<wake) wake=r->deadline_ns;
		}
		if(end && end<wake) wake=end;
		timeout=wake<=now?0:(int)((wake-now+999999)/1000000);
		if (poll(fds,3,timeout)>0 && (fds[0].revents&POLLIN)) {
			if(ctx->profile_loop) { segment=profile_cpu(); profile_requests++; }
			next_control_ns=cis_clock_ns()+31250000;
			int client=accept4(ctx->socket_fd,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);
			if (client>=0) {
				struct pollfd cp={client,POLLIN,0};
				if (poll(&cp,1,10)>0) request(ctx,client);
				close(client);
			}
			if(ctx->profile_loop) profile_totals[0]+=profile_cpu()-segment;
		}
		now=cis_clock_ns();
		if(ctx->profile_loop) { segment=profile_cpu(); profile_loops++; }
		if (ctx->mode) for (i=0;i<CIS_MAX_ROOTS;i++) {
			struct cis_root *r=&ctx->roots[i];
			struct cis_metric m;
			int metric_result;
			if (!r->used || now<r->next_ns) continue;
			r->next_ns=now+1000000000;
			ctx->metrics_reads++;
			metric_result=cis_metrics_read(r,&m);
			if(metric_result<0) {
				char link[64],name[4096];
				ssize_t n;
				snprintf(link,sizeof(link),"/proc/self/fd/%d",r->fd);
				n=readlink(link,name,sizeof(name)-1);
				if(n>=0) name[n]=0;
				if(n>=0 && strstr(name," (deleted)")) {
					cis_report(ctx,"root_deleted",r,"retiring registration; no path-name reassignment");
					cis_registry_remove(ctx,r->id,r->generation);
				} else { ctx->errors++; cis_report(ctx,"metric_error",r,"missing/stale resource field, not zero"); }
			} else {
				if(cis_config_epoch(ctx,r,now)) { ctx->errors++; cis_report(ctx,"config_error",r,"configuration read failed, not silently frozen"); }
				if(!m.populated) cis_baseline_idle(ctx,r,&m,metric_result);
				else cis_baseline_update(ctx,r,&m);
			}
		}
		if(ctx->profile_loop) { uint64_t stamp=profile_cpu(); profile_totals[1]+=stamp-segment; segment=stamp; }
		if (cis_capture_poll(ctx)<0) { cis_report(ctx,"capture_error",NULL,"stopping collectors"); cis_capture_stop(ctx); }
		if(ctx->profile_loop) { uint64_t stamp=profile_cpu(); profile_totals[2]+=stamp-segment; segment=stamp; }
		cis_fast_poll(ctx);
		cis_diagnostics_tick(ctx,now); cis_budget_tick(ctx,now);
		if(ctx->profile_loop) {
			profile_totals[3]+=profile_cpu()-segment;
			if(now>=profile_due) {
				char detail[384];
				snprintf(detail,sizeof(detail),"loops=%llu requests=%llu control_cpu_ns=%llu metrics_cpu_ns=%llu capture_cpu_ns=%llu state_budget_cpu_ns=%llu instrumentation_included=1 not_performance_acceptance=1",
					(unsigned long long)profile_loops,(unsigned long long)profile_requests,
					(unsigned long long)profile_totals[0],(unsigned long long)profile_totals[1],
					(unsigned long long)profile_totals[2],(unsigned long long)profile_totals[3]);
				cis_report(ctx,"cpu_profile",NULL,detail);
				memset(profile_totals,0,sizeof(profile_totals)); profile_loops=profile_requests=0;
				profile_due=now+1000000000ULL;
			}
		}
	}
	status=0;
out:
	cis_registry_destroy(ctx); cis_capture_stop(ctx); cis_symbols_free(ctx);
	if(ctx->psi_epoll>=0) close(ctx->psi_epoll);
	{
		char quality[192];
		snprintf(quality,sizeof(quality),"errors=%u drops=%u retired_or_unknown_userspace_samples=%u",ctx->errors,ctx->dropped,ctx->unknown);
		cis_report(ctx,"final_quality",NULL,quality);
	}
	if (ctx->socket_fd>=0) { close(ctx->socket_fd); unlink(socket_path); }
	if (ctx->output_fd!=STDOUT_FILENO) close(ctx->output_fd);
	free(ctx); return status;
}
