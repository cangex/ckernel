// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../include/cis_event.h"
char LICENSE[] SEC("license") = "GPL";
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,256); __type(key,__u64); __type(value,struct cis_identity); } roots SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,2); __type(key,__u64); __type(value,struct cis_target); } targets SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,CIS_RING_BYTES); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct cis_bpf_stats); } stats SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,CIS_INFLIGHT); __type(key,struct cis_pending_key); __type(value,struct cis_event); } pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries,CIS_STACKS); __type(key,__u32); __type(value,__u64[CIS_STACK_DEPTH]); } stacks SEC(".maps");

static __always_inline struct cis_bpf_stats *statistics(void)
{
	__u32 zero=0;
	return bpf_map_lookup_elem(&stats,&zero);
}

static __always_inline int identity(struct task_struct *task,struct cis_identity *out)
{
	struct kernfs_node *kn=BPF_CORE_READ(task,cgroups,dfl_cgrp,kn);
	struct cis_bpf_stats *s;
	int i;
	/* Cgroup parentage is immutable; CO-RE reads fail closed on missing nodes. */
#pragma clang loop unroll(disable)
	for(i=0;i<32;i++) {
		struct cis_identity *r;
		__u64 id;
		if(!kn) break;
		id=BPF_CORE_READ(kn,id);
		r=bpf_map_lookup_elem(&roots,&id);
		if(r) { *out=*r; return 1; }
		kn=BPF_CORE_READ(kn,parent);
	}
	s=statistics();
	if(s) { s->unknown++; if(kn) s->overdepth++; }
	return 0;
}

static __always_inline int allowed(struct cis_identity *id,__u32 kind,__u64 now)
{
	struct cis_target *t=bpf_map_lookup_elem(&targets,&id->id);
	return t && t->generation==id->generation && t->deadline_ns>now && (t->kind&kind);
}

static __always_inline void emit(struct cis_event *e)
{
	struct cis_bpf_stats *s=statistics();
	if(bpf_ringbuf_output(&events,e,sizeof(*e),0)) { if(s) s->lost++; }
	else if(s) s->emitted++;
}

SEC("perf_event")
int sample_ip(struct bpf_perf_event_data *ctx)
{
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_bpf_stats *s=statistics();
	if(s) s->received++;
	if(!identity((void*)bpf_get_current_task(),&id)) return 0;
	e.time_ns=bpf_ktime_get_ns(); e.id=id.id; e.generation=id.generation;
	e.tid=bpf_get_current_pid_tgid(); e.ip=ctx->regs.pc; e.weight=ctx->sample_period;
	e.type=CIS_IP; e.cpu=bpf_get_smp_processor_id(); e.stack_id=-1;
	emit(&e); return 0;
}

SEC("raw_tp/sched_stat_wait")
int sched_wait(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task=(void*)ctx->args[0];
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_bpf_stats *s=statistics();
	if(s) s->received++;
	e.time_ns=bpf_ktime_get_ns();
	if(!identity(task,&id) || !allowed(&id,CIS_DIAG_SCHED,e.time_ns)) return 0;
	e.id=id.id; e.generation=id.generation;
	e.tid=((__u64)BPF_CORE_READ(task,tgid)<<32)|(__u32)BPF_CORE_READ(task,pid);
	e.duration_ns=ctx->args[1]; e.cpu=bpf_get_smp_processor_id(); e.type=CIS_SCHED_WAIT; e.stack_id=-1;
	emit(&e); return 0;
}

static __always_inline int begin(void *ctx,__u64 object,__u32 type,__u32 kind,__u32 flags)
{
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_pending_key key={.tid=bpf_get_current_pid_tgid(),.object=object,.type=type};
	struct cis_bpf_stats *s=statistics();
	struct cis_event *old;
	if(s) s->received++;
	e.time_ns=bpf_ktime_get_ns();
	if(!identity((void*)bpf_get_current_task(),&id) || !allowed(&id,kind,e.time_ns)) return 0;
	old=bpf_map_lookup_elem(&pending,&key);
	if(old) { old->nesting++; if(s) s->nested++; return 0; }
	e.id=id.id; e.generation=id.generation; e.tid=key.tid; e.object=object;
	e.type=type; e.cpu=bpf_get_smp_processor_id(); e.flags=flags;
	e.stack_id=bpf_get_stackid(ctx,&stacks,0);
	if(bpf_map_update_elem(&pending,&key,&e,BPF_NOEXIST) && s) {
		if(bpf_map_lookup_elem(&pending,&key)) s->nested++; else s->rejected++;
	}
	return 0;
}

static __always_inline int finish(__u64 object,__u32 type,__u32 kind,__s32 ret)
{
	struct cis_pending_key key={.tid=bpf_get_current_pid_tgid(),.object=object,.type=type};
	struct cis_event *saved=bpf_map_lookup_elem(&pending,&key),e;
	struct cis_identity id;
	struct cis_bpf_stats *s=statistics();
	if(!saved) { if(s) s->unmatched++; return 0; }
	if(saved->nesting) { saved->nesting--; return 0; }
	e=*saved;
	id.id=e.id; id.generation=e.generation;
	e.duration_ns=bpf_ktime_get_ns()-e.time_ns;
	if(!allowed(&id,kind,bpf_ktime_get_ns())) { if(s) s->expired++; return 0; }
	/* Recorded identity is the begin owner, even if the task subsequently migrates. */
	e.flags|=ret?0x80000000U:0;
	emit(&e); bpf_map_delete_elem(&pending,&key);
	return 0;
}

SEC("raw_tp/contention_begin")
int lock_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,ctx->args[0],CIS_LOCK_WAIT,CIS_DIAG_LOCK,ctx->args[1]); }
SEC("raw_tp/contention_end")
int lock_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx->args[0],CIS_LOCK_WAIT,CIS_DIAG_LOCK,ctx->args[1]); }
SEC("raw_tp/mm_vmscan_direct_reclaim_begin")
int reclaim_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,0,CIS_RECLAIM,CIS_DIAG_RECLAIM,0); }
SEC("raw_tp/mm_vmscan_direct_reclaim_end")
int reclaim_end(struct bpf_raw_tracepoint_args *ctx) { (void)ctx; return finish(0,CIS_RECLAIM,CIS_DIAG_RECLAIM,0); }
