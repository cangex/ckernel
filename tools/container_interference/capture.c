// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include <linux/types.h>
#include "include/cis_event.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#define CIS_CPU_CAP 512
#define CIS_DIAGNOSTIC_LINKS 12
struct capture {
	struct cis_context *ctx;
	struct bpf_object *object;
	struct perf_buffer *ring;
	struct bpf_link *diagnostic_links[CIS_DIAGNOSTIC_LINKS];
	int perf_fds[CIS_CPU_CAP], ncpu, roots, targets, pending, stacks, stats;
	void *perf_pages[CIS_CPU_CAP];
	size_t perf_page_size;
	uint64_t perf_lost, perf_throttle, perf_unthrottle, perf_bad_records;
	unsigned int active_kinds;
	uint64_t last_stats_ns, last_received;
	struct cis_bpf_stats *cpu_stats;
	int possible_cpus;
};

static int mapfd(struct capture *c,const char *name)
{
	return bpf_object__find_map_fd_by_name(c->object,name);
}

static void event(void *opaque,int cpu,void *data,__u32 size)
{
	struct capture *c=opaque;
	struct cis_context *ctx=c->ctx;
	struct cis_event *e=data;
	struct cis_root *r;
	char detail[768];
	const char *symbol;
	(void)cpu;
	/* PERF_SAMPLE_RAW includes trailing alignment bytes in its reported size. */
	if(size<sizeof(*e) || size>sizeof(*e)+7) {
		if(!ctx->errors) {
			snprintf(detail,sizeof(detail),"payload_bytes=%u expected=%zu",size,sizeof(*e));
			cis_report(ctx,"sample_schema_error",NULL,detail);
		}
		ctx->errors++; return;
	}
	r=cis_registry_lookup(ctx,e->id,e->generation);
	if(!r) { ctx->unknown++; return; }
	symbol=cis_symbol(ctx,e->ip);
	if(e->type==CIS_IP) {
		r->ip_samples++;
		if(strstr(symbol,"mutex") || strstr(symbol,"spin_lock") || strstr(symbol,"rwsem")) r->lock_samples++;
		if(strstr(symbol,"reclaim") || strstr(symbol,"shrink_")) r->reclaim_samples++;
	}
	snprintf(detail,sizeof(detail),"sample_time_ns=%llu type=%u tid=%llu cpu=%u object=0x%llx duration_ns=%llu ip=0x%llx weight=%llu stack_id=%d flags=%u executor_tid=%llu sequence_ns=%llu symbol=%s owner=unknown execution_context=task_or_irq_unresolved",
		(unsigned long long)e->time_ns,e->type,(unsigned long long)e->tid,e->cpu,
		(unsigned long long)e->object,(unsigned long long)e->duration_ns,(unsigned long long)e->ip,
		(unsigned long long)e->weight,e->stack_id,e->flags,(unsigned long long)e->executor_tid,(unsigned long long)e->sequence_ns,symbol);
	cis_report(ctx,e->type==CIS_IP?"IP":(e->type>=CIS_WORK_QUEUED && e->type<=CIS_WORK_UNRESOLVED)?"async_submitter":"E1",r,detail);
}

static void lost(void *opaque,int cpu,__u64 count)
{
	struct capture *c=opaque;
	char detail[128];
	snprintf(detail,sizeof(detail),"cpu=%d lost=%llu per_cpu_buffer_full=1",cpu,(unsigned long long)count);
	cis_report(c->ctx,"buffer_loss",NULL,detail);
}

static int attach(struct capture *c,const char *name,struct bpf_link **slot)
{
	struct bpf_program *p=bpf_object__find_program_by_name(c->object,name);
	if(!p) return -ENOENT;
	*slot=bpf_program__attach(p);
	if(libbpf_get_error(*slot)) { *slot=NULL; return -EIO; }
	return 0;
}

static int configure_links(struct capture *c,unsigned int kinds)
{
	static const char *names[]={"sched_wait","lock_begin","lock_end","reclaim_begin","reclaim_end","work_queue","work_start","work_end","work_cancel_begin","work_cancel_end","memcg_begin","memcg_end"};
	static const unsigned int masks[]={1,2,2,4,4,8,8,8,8,8,4,4};
	unsigned int i;
	for(i=0;i<CIS_DIAGNOSTIC_LINKS;i++) {
		if(!(kinds&masks[i])) { bpf_link__destroy(c->diagnostic_links[i]); c->diagnostic_links[i]=NULL; }
		else if(!c->diagnostic_links[i] && attach(c,names[i],&c->diagnostic_links[i])) return -EIO;
	}
	c->active_kinds=kinds; return 0;
}

int cis_capture_root(struct cis_context *ctx,struct cis_root *r,int add)
{
	struct capture *c=ctx->capture;
	struct cis_identity id={r->id,r->generation};
	if(!c) return 0;
	return add?bpf_map_update_elem(c->roots,&r->id,&id,BPF_NOEXIST):bpf_map_delete_elem(c->roots,&r->id);
}

static void unfinished(struct capture *c,struct cis_root *r)
{
	struct cis_pending_key key,next;
	struct cis_event value;
	unsigned int visited=0;
	int present=bpf_map_get_next_key(c->pending,NULL,&key);
	while(!present && visited++<CIS_INFLIGHT*2) {
		int end=bpf_map_get_next_key(c->pending,&key,&next);
		if(!bpf_map_lookup_elem(c->pending,&key,&value) && value.id==r->id && value.generation==r->generation) {
			char detail[256];
			snprintf(detail,sizeof(detail),"tid=%llu object=0x%llx begin_ns=%llu type=%u; end unobserved",
				(unsigned long long)value.tid,(unsigned long long)value.object,(unsigned long long)value.time_ns,value.type);
			cis_report(c->ctx,"incomplete",r,detail);
			bpf_map_delete_elem(c->pending,&key);
		}
		if(end) break;
		key=next;
	}
	if(visited>=CIS_INFLIGHT*2) cis_report(c->ctx,"incomplete_scan_limited",r,"bounded scan under concurrent map updates; residual remains auditable at shutdown");
}

static void export_stacks(struct capture *c,struct cis_root *r)
{
	__u32 key,next;
	__u64 ips[CIS_STACK_DEPTH];
	int err=bpf_map_get_next_key(c->stacks,NULL,&key);
	while(!err) {
		unsigned int i;
		char detail[1200];
		size_t n=snprintf(detail,sizeof(detail),"stack_id=%u ips=",key);
		if(!bpf_map_lookup_elem(c->stacks,&key,ips)) {
			for(i=0;i<CIS_STACK_DEPTH && ips[i] && n+20<sizeof(detail);i++)
				n+=snprintf(detail+n,sizeof(detail)-n,"%s%llx",i?",":"",(unsigned long long)ips[i]);
			cis_report(c->ctx,"stack",r,detail);
		}
		err=bpf_map_get_next_key(c->stacks,&key,&next); key=next;
	}
}

static void unfinished_work(struct capture *c,struct cis_root *r)
{
	int fd=mapfd(c,"work_items"),ret;
	__u64 key,next;
	struct cis_work_state state;
	unsigned int visited=0;
	ret=bpf_map_get_next_key(fd,NULL,&key);
	while(!ret && visited++<256) {
		int end=bpf_map_get_next_key(fd,&key,&next);
		if(!bpf_map_lookup_elem(fd,&key,&state)) {
			struct cis_event *e=state.active_valid?&state.active:&state.queued;
			if(e->id==r->id && e->generation==r->generation) {
				char detail[256];
				snprintf(detail,sizeof(detail),"object=0x%llx sequence_ns=%llu queued=%u active=%u cancellation/requeue/lifetime unresolved",
					(unsigned long long)key,(unsigned long long)e->sequence_ns,state.queued_valid,state.active_valid);
				cis_report(c->ctx,"async_incomplete",r,detail);
				bpf_map_delete_elem(fd,&key);
			}
		}
		if(end) break;
		key=next;
	}
}

int cis_capture_diagnostic(struct cis_context *ctx,struct cis_root *r,int enable)
{
	struct capture *c=ctx->capture;
	struct cis_target target={.generation=r->generation,.start_ns=cis_clock_ns(),.kind=r->diagnostic_kind};
	unsigned int kinds=enable?r->diagnostic_kind:0,i;
	unsigned int previous_kinds;
	if(!c) return enable?-EOPNOTSUPP:0;
	target.deadline_ns=target.start_ns+ctx->window_ms*1000000ULL;
	previous_kinds=c->active_kinds;
	for(i=0;i<CIS_MAX_ROOTS;i++)
		if(&ctx->roots[i]!=r && ctx->roots[i].used && ctx->roots[i].state==CIS_DIAGNOSING) kinds|=ctx->roots[i].diagnostic_kind;
	if(enable) {
		if(configure_links(c,kinds)) { configure_links(c,previous_kinds); return -EOPNOTSUPP; }
		if(bpf_map_update_elem(c->targets,&r->id,&target,BPF_NOEXIST)) { configure_links(c,previous_kinds); return -errno; }
	} else {
		bpf_map_delete_elem(c->targets,&r->id);
		configure_links(c,kinds);
		perf_buffer__poll(c->ring,0); unfinished(c,r); unfinished_work(c,r); export_stacks(c,r);
	}
	return 0;
}

int cis_capture_start(struct cis_context *ctx,const char *path)
{
	struct capture *c=calloc(1,sizeof(*c));
	struct bpf_program *p;
	int i,prog_fd;
	struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};
	char detail[256];
	if(!c) return -ENOMEM;
	/* The audited kernel-memory reserve assumes 4 KiB perf pages. */
	if(sysconf(_SC_PAGESIZE)!=4096) {
		cis_report(ctx,"capture_failure",NULL,"unsupported_page_size: kernel-memory budget not validated");
		free(c); return -EOPNOTSUPP;
	}
	c->ctx=ctx; ctx->capture=c;
	for(i=0;i<CIS_CPU_CAP;i++) c->perf_fds[i]=-1;
	if(setrlimit(RLIMIT_MEMLOCK,&limit)) goto fail;
	c->object=bpf_object__open_file(path,NULL);
	if(libbpf_get_error(c->object)) { c->object=NULL; goto fail; }
	if(bpf_object__load(c->object)) goto fail;
	c->roots=mapfd(c,"roots"); c->targets=mapfd(c,"targets"); c->pending=mapfd(c,"pending");
	c->stacks=mapfd(c,"stacks"); c->stats=mapfd(c,"stats");
	c->possible_cpus=libbpf_num_possible_cpus();
	if(c->possible_cpus<1 || c->possible_cpus>CIS_CPU_CAP) goto fail;
	c->cpu_stats=calloc(c->possible_cpus,sizeof(*c->cpu_stats));
	if(!c->cpu_stats) goto fail;
	c->ring=perf_buffer__new(mapfd(c,"events"),CIS_BUFFER_PAGES,event,lost,c,NULL);
	if(libbpf_get_error(c->ring)) { c->ring=NULL; goto fail; }
	p=bpf_object__find_program_by_name(c->object,"sample_ip");
	if(!p) goto fail;
	prog_fd=bpf_program__fd(p);
	c->ncpu=sysconf(_SC_NPROCESSORS_CONF);
	if(c->ncpu<1 || c->ncpu>CIS_CPU_CAP || ctx->ip_hz<(unsigned int)c->ncpu) goto fail;
	for(i=0;i<c->ncpu;i++) {
		struct perf_event_attr attr={.size=sizeof(attr),.type=PERF_TYPE_HARDWARE,.config=PERF_COUNT_HW_CPU_CYCLES,
			.read_format=PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING,
			.sample_period=4000000000ULL/(ctx->ip_hz/c->ncpu),.exclude_user=1,.exclude_hv=1,.disabled=1};
		int fd=syscall(__NR_perf_event_open,&attr,-1,i,-1,PERF_FLAG_FD_CLOEXEC);
		if(fd<0 && (errno==ENOENT || errno==EOPNOTSUPP || errno==EINVAL)) {
			attr.type=PERF_TYPE_SOFTWARE; attr.config=PERF_COUNT_SW_CPU_CLOCK;
			attr.sample_period=1000000000ULL/(ctx->ip_hz/c->ncpu);
			fd=syscall(__NR_perf_event_open,&attr,-1,i,-1,PERF_FLAG_FD_CLOEXEC);
			cis_report(ctx,"pmu_fallback",NULL,"hardware kernel cycles unavailable: software kernel CPU-clock IP sampling, not cycles");
		}
		if(fd<0 && errno==ENODEV) continue;
		if(fd<0) goto fail;
		c->perf_fds[i]=fd;
		c->perf_page_size=sysconf(_SC_PAGESIZE);
		c->perf_pages[i]=mmap(NULL,2*c->perf_page_size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
		if(c->perf_pages[i]==MAP_FAILED) { c->perf_pages[i]=NULL; goto fail; }
		if(ioctl(fd,PERF_EVENT_IOC_SET_BPF,prog_fd) || ioctl(fd,PERF_EVENT_IOC_ENABLE,0)) goto fail;
	}
	snprintf(detail,sizeof(detail),"configured_cpus=%d per_cpu_budget_hz=%u nominal_total_budget_hz=%u per_cpu_buffer_pages=%u inflight_limit=%u fixed_period_at_4GHz_bound=1 no_idle_period_shrinking=1",
		c->ncpu,ctx->ip_hz/c->ncpu,(ctx->ip_hz/c->ncpu)*c->ncpu,CIS_BUFFER_PAGES,CIS_INFLIGHT);
	cis_report(ctx,"capture_ready",NULL,detail);
	return 0;
fail:
	cis_capture_stop(ctx); return -EIO;
}

static void perf_ring(struct capture *c,int cpu)
{
	struct perf_event_mmap_page *meta=c->perf_pages[cpu];
	uint64_t head,tail;
	unsigned int n=0;
	if(!meta) return;
	head=__atomic_load_n(&meta->data_head,__ATOMIC_ACQUIRE);
	tail=meta->data_tail;
	while(tail<head && n++<256) {
		struct perf_event_header h;
		unsigned char *data=(void*)((char*)meta+c->perf_page_size);
		unsigned int j;
		for(j=0;j<sizeof(h);j++) ((unsigned char*)&h)[j]=data[(tail+j)%c->perf_page_size];
		if(h.size<sizeof(h) || h.size>c->perf_page_size || tail+h.size>head) { c->perf_bad_records++; tail=head; break; }
		if(h.type==PERF_RECORD_THROTTLE) c->perf_throttle++;
		else if(h.type==PERF_RECORD_UNTHROTTLE) c->perf_unthrottle++;
		else if(h.type==PERF_RECORD_LOST && h.size>=sizeof(h)+16) {
			uint64_t lost=0;
			for(j=0;j<8;j++) ((unsigned char*)&lost)[j]=data[(tail+sizeof(h)+8+j)%c->perf_page_size];
			c->perf_lost+=lost;
		}
		tail+=h.size;
	}
	__atomic_store_n(&meta->data_tail,tail,__ATOMIC_RELEASE);
}

int cis_capture_poll(struct cis_context *ctx)
{
	struct capture *c=ctx->capture;
	uint64_t now=cis_clock_ns(),received=0;
	struct cis_bpf_stats total={0};
	__u32 zero=0;
	int i,ret;
	char detail[512];
	if(!c) return 0;
	ret=perf_buffer__poll(c->ring,0);
	if(ret<0 && ret!=-EINTR) return ret;
	if(now-c->last_stats_ns<1000000000) return 0;
	{
		uint64_t enabled=0,running=0;
		for(i=0;i<c->ncpu;i++) if(c->perf_fds[i]>=0) {
			struct { uint64_t value,enabled,running; } counter;
			perf_ring(c,i);
			if(read(c->perf_fds[i],&counter,sizeof(counter))==sizeof(counter)) { enabled+=counter.enabled; running+=counter.running; }
			else ctx->errors++;
		}
		snprintf(detail,sizeof(detail),"enabled_ns=%llu running_ns=%llu lost=%llu throttle=%llu unthrottle=%llu invalid_records=%llu",
			(unsigned long long)enabled,(unsigned long long)running,(unsigned long long)c->perf_lost,
			(unsigned long long)c->perf_throttle,(unsigned long long)c->perf_unthrottle,(unsigned long long)c->perf_bad_records);
		cis_report(ctx,"perf_quality",NULL,detail);
	}
	if(bpf_map_lookup_elem(c->stats,&zero,c->cpu_stats)) return -EIO;
	for(i=0;i<c->possible_cpus;i++) {
		struct cis_bpf_stats *s=&c->cpu_stats[i];
		total.received+=s->received; total.emitted+=s->emitted; total.lost+=s->lost;
		total.unknown+=s->unknown; total.overdepth+=s->overdepth; total.unmatched+=s->unmatched;
		total.nested+=s->nested; total.rejected+=s->rejected; total.expired+=s->expired;
		total.phase_changes+=s->phase_changes;
		total.irq_context+=s->irq_context;
	}
	received=total.received;
	snprintf(detail,sizeof(detail),"received=%llu emitted=%llu lost=%llu unknown=%llu overdepth=%llu unmatched=%llu nested=%llu rejected=%llu expired=%llu phase_changes=%llu irq_context=%llu",
		(unsigned long long)total.received,(unsigned long long)total.emitted,(unsigned long long)total.lost,
		(unsigned long long)total.unknown,(unsigned long long)total.overdepth,(unsigned long long)total.unmatched,
		(unsigned long long)total.nested,(unsigned long long)total.rejected,(unsigned long long)total.expired,(unsigned long long)total.phase_changes,(unsigned long long)total.irq_context);
	cis_report(ctx,"coverage",NULL,detail);
	if(c->last_stats_ns && (received-c->last_received)*1000000000.0/(now-c->last_stats_ns)>200000) {
		cis_report(ctx,"entry_budget_disable",NULL,"entry rate exceeded 200000/s, detaching collectors"); return -E2BIG;
	}
	c->last_stats_ns=now; c->last_received=received;
	return 0;
}

void cis_capture_stop(struct cis_context *ctx)
{
	struct capture *c=ctx->capture;
	int i;
	if(!c) return;
	for(i=0;i<CIS_DIAGNOSTIC_LINKS;i++) bpf_link__destroy(c->diagnostic_links[i]);
	for(i=0;i<CIS_CPU_CAP;i++) if(c->perf_fds[i]>=0) {
		ioctl(c->perf_fds[i],PERF_EVENT_IOC_DISABLE,0);
		if(c->perf_pages[i]) munmap(c->perf_pages[i],2*c->perf_page_size);
		close(c->perf_fds[i]);
	}
	perf_buffer__free(c->ring); bpf_object__close(c->object); free(c->cpu_stats); free(c);
	ctx->capture=NULL; ctx->diagnostic=0;
	for(i=0;i<CIS_MAX_ROOTS;i++) if(ctx->roots[i].used && ctx->roots[i].state==CIS_DIAGNOSING) {
		ctx->roots[i].state=CIS_COOLDOWN; ctx->roots[i].last_diag_ns=cis_clock_ns();
	}
}
