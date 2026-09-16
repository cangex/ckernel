// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../include/cis_event.h"
char LICENSE[] SEC("license") = "GPL";
#define COUNT(s, field) do { if (s) __sync_fetch_and_add(&(s)->field, 1); } while (0)
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,256); __type(key,__u64); __type(value,struct cis_identity); } roots SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,2); __type(key,__u64); __type(value,struct cis_target); } targets SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries,512); __type(key,__u32); __type(value,__u32); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct cis_bpf_stats); } stats SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,CIS_INFLIGHT); __type(key,struct cis_pending_key); __type(value,struct cis_event); } pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries,CIS_STACKS); __type(key,__u32); __type(value,__u64[CIS_STACK_DEPTH]); } stacks SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,128); __type(key,__u64); __type(value,struct cis_work_state); } work_items SEC(".maps");

static __always_inline struct cis_bpf_stats *statistics(void)
{
	__u32 zero=0;
	return bpf_map_lookup_elem(&stats,&zero);
}

static __always_inline int synchronous_context(void)
{
	struct task_struct *task=(void*)bpf_get_current_task();
	__u32 count=BPF_CORE_READ(task,thread_info.preempt_count);
	/* Fixed ARM64 OLK preempt layout: active softirq, hardirq or NMI, not bh-disabled. */
	if(count&0x00ff0100U) {
		struct cis_bpf_stats *s=statistics(); COUNT(s,irq_context); return 0;
	}
	return 1;
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
	COUNT(s,unknown); if(kn) COUNT(s,overdepth);
	return 0;
}

static __always_inline int allowed(struct cis_identity *id,__u32 kind,__u64 now)
{
	struct cis_target *t=bpf_map_lookup_elem(&targets,&id->id);
	return t && t->generation==id->generation && now>=t->start_ns && t->deadline_ns>now && (t->kind&kind);
}

static __always_inline int same_window(struct cis_event *e,__u32 kind,__u64 now)
{
	struct cis_target *t=bpf_map_lookup_elem(&targets,&e->id);
	return t && t->generation==e->generation && t->deadline_ns>now &&
	       e->time_ns>=t->start_ns && (t->kind&kind);
}

static __always_inline void emit(void *ctx,struct cis_event *e)
{
	struct cis_bpf_stats *s=statistics();
	if(bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,e,sizeof(*e))) COUNT(s,lost);
	else COUNT(s,emitted);
}

SEC("perf_event")
int sample_ip(struct bpf_perf_event_data *ctx)
{
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	if(!identity((void*)bpf_get_current_task(),&id)) return 0;
	e.time_ns=bpf_ktime_get_ns(); e.id=id.id; e.generation=id.generation;
	e.tid=bpf_get_current_pid_tgid(); e.ip=ctx->regs.pc; e.weight=ctx->sample_period;
	e.type=CIS_IP; e.cpu=bpf_get_smp_processor_id(); e.stack_id=-1;
	emit(ctx,&e); return 0;
}

SEC("raw_tp/sched_stat_wait")
int sched_wait(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task=(void*)ctx->args[0];
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	e.time_ns=bpf_ktime_get_ns();
	if(!identity(task,&id) || !allowed(&id,CIS_DIAG_SCHED,e.time_ns)) return 0;
	e.id=id.id; e.generation=id.generation;
	e.tid=((__u64)BPF_CORE_READ(task,tgid)<<32)|(__u32)BPF_CORE_READ(task,pid);
	e.duration_ns=ctx->args[1]; e.cpu=bpf_get_smp_processor_id(); e.type=CIS_SCHED_WAIT; e.stack_id=-1;
	emit(ctx,&e); return 0;
}

static __always_inline int begin(void *ctx,__u64 object,__u32 type,__u32 kind,__u32 flags)
{
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_pending_key key={.tid=bpf_get_current_pid_tgid(),.object=object,.type=type};
	struct cis_bpf_stats *s=statistics();
	struct cis_event *old;
	COUNT(s,received);
	if(!synchronous_context()) return 0;
	key.task_start_ns=BPF_CORE_READ((struct task_struct*)bpf_get_current_task(),start_boottime);
	e.time_ns=bpf_ktime_get_ns();
	if(!identity((void*)bpf_get_current_task(),&id) || !allowed(&id,kind,e.time_ns)) return 0;
	old=bpf_map_lookup_elem(&pending,&key);
	if(old && !same_window(old,kind,e.time_ns)) {
		COUNT(s,expired); bpf_map_delete_elem(&pending,&key); old=NULL;
	}
	if(old) {
		/* mutex.c repeats begin when switching spin/sleep phases, with one final end. */
		if(type==CIS_LOCK_WAIT) { old->flags|=flags; COUNT(s,phase_changes); }
		else { old->nesting++; COUNT(s,nested); }
		return 0;
	}
	e.id=id.id; e.generation=id.generation; e.tid=key.tid; e.object=object;
	e.type=type; e.cpu=bpf_get_smp_processor_id(); e.flags=flags;
	e.stack_id=bpf_get_stackid(ctx,&stacks,0);
	if(bpf_map_update_elem(&pending,&key,&e,BPF_NOEXIST) && s) {
		if(bpf_map_lookup_elem(&pending,&key)) COUNT(s,nested); else COUNT(s,rejected);
	}
	return 0;
}

static __always_inline int finish(void *ctx,__u64 object,__u32 type,__u32 kind,__s32 ret)
{
	struct cis_pending_key key={.tid=bpf_get_current_pid_tgid(),.object=object,.type=type};
	struct cis_event *saved,e;
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	if(!synchronous_context()) return 0;
	key.task_start_ns=BPF_CORE_READ((struct task_struct*)bpf_get_current_task(),start_boottime);
	saved=bpf_map_lookup_elem(&pending,&key);
	if(!saved) { COUNT(s,unmatched); return 0; }
	if(saved->nesting) { saved->nesting--; return 0; }
	e=*saved;
	e.duration_ns=bpf_ktime_get_ns()-e.time_ns;
	if(!same_window(&e,kind,bpf_ktime_get_ns())) { COUNT(s,expired); bpf_map_delete_elem(&pending,&key); return 0; }
	/* Recorded identity is the begin owner, even if the task subsequently migrates. */
	e.flags|=ret?0x80000000U:0;
	emit(ctx,&e); bpf_map_delete_elem(&pending,&key);
	return 0;
}

SEC("raw_tp/contention_begin")
int lock_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,ctx->args[0],CIS_LOCK_WAIT,CIS_DIAG_LOCK,ctx->args[1]); }
SEC("raw_tp/contention_end")
int lock_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx,ctx->args[0],CIS_LOCK_WAIT,CIS_DIAG_LOCK,ctx->args[1]); }
SEC("raw_tp/mm_vmscan_direct_reclaim_begin")
int reclaim_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,0,CIS_RECLAIM,CIS_DIAG_RECLAIM,0); }
SEC("raw_tp/mm_vmscan_direct_reclaim_end")
int reclaim_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx,0,CIS_RECLAIM,CIS_DIAG_RECLAIM,0); }

SEC("raw_tp/mm_vmscan_memcg_reclaim_begin")
int memcg_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,0,CIS_MEMCG_RECLAIM,CIS_DIAG_RECLAIM,0); }
SEC("raw_tp/mm_vmscan_memcg_reclaim_end")
int memcg_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx,0,CIS_MEMCG_RECLAIM,CIS_DIAG_RECLAIM,0); }

SEC("raw_tp/workqueue_queue_work")
int work_queue(struct bpf_raw_tracepoint_args *ctx)
{
	struct work_struct *work=(void*)ctx->args[2];
	__u64 key=(__u64)work,now=bpf_ktime_get_ns();
	struct cis_identity id={0};
	struct cis_work_state *state,empty={0};
	struct cis_event e={0};
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	if(!synchronous_context()) return 0;
	state=bpf_map_lookup_elem(&work_items,&key);
	if(state && state->active_valid) {
		e=state->active; id.id=e.id; id.generation=e.generation;
		if(same_window(&e,CIS_DIAG_WORK,now)) {
			e.type=CIS_WORK_UNRESOLVED; e.time_ns=now; e.executor_tid=bpf_get_current_pid_tgid();
			e.flags=1; emit(ctx,&e); COUNT(s,rejected);
		}
		return 0;
	}
	if(!identity((void*)bpf_get_current_task(),&id) || !allowed(&id,CIS_DIAG_WORK,now)) return 0;
	if(!state) {
		if(bpf_map_update_elem(&work_items,&key,&empty,BPF_NOEXIST)) { COUNT(s,rejected); return 0; }
		state=bpf_map_lookup_elem(&work_items,&key);
	}
	if(!state) return 0;
	/* In-flight/requeued or merged work is deliberately not assigned a unique owner. */
	if(state->queued_valid || state->active_valid) { COUNT(s,rejected); return 0; }
	e.id=id.id; e.generation=id.generation; e.tid=bpf_get_current_pid_tgid();
	e.time_ns=now; e.sequence_ns=now; e.object=key; e.type=CIS_WORK_QUEUED;
	e.ip=(__u64)BPF_CORE_READ(work,func); e.cpu=bpf_get_smp_processor_id(); e.stack_id=-1;
	state->queued=e; state->queued_valid=1; emit(ctx,&e); return 0;
}

SEC("raw_tp/workqueue_execute_start")
int work_start(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 key=ctx->args[0],now=bpf_ktime_get_ns();
	struct cis_work_state *state=bpf_map_lookup_elem(&work_items,&key);
	struct cis_event e;
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	if(!state || !state->queued_valid || state->active_valid) return 0;
	e=state->queued;
	if(!same_window(&e,CIS_DIAG_WORK,now)) return 0;
	e.type=CIS_WORK_START; e.duration_ns=now-e.time_ns; e.time_ns=now;
	e.executor_tid=bpf_get_current_pid_tgid(); e.cpu=bpf_get_smp_processor_id();
	state->active=e; state->active_valid=1; state->queued_valid=0; emit(ctx,&e); return 0;
}

SEC("raw_tp/workqueue_execute_end")
int work_end(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 key=ctx->args[0],now=bpf_ktime_get_ns();
	struct cis_work_state *state=bpf_map_lookup_elem(&work_items,&key);
	struct cis_event e;
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	if(!state || !state->active_valid) return 0;
	e=state->active;
	if(!same_window(&e,CIS_DIAG_WORK,now)) return 0;
	e.type=CIS_WORK_END; e.duration_ns=now-e.time_ns;
	e.executor_tid=bpf_get_current_pid_tgid(); e.cpu=bpf_get_smp_processor_id();
	emit(ctx,&e); bpf_map_delete_elem(&work_items,&key); return 0;
}

SEC("kprobe/cancel_work_sync")
int work_cancel_begin(struct pt_regs *ctx)
{
	__u64 object=PT_REGS_PARM1_CORE(ctx);
	struct cis_work_state *state=bpf_map_lookup_elem(&work_items,&object);
	struct cis_event e;
	struct cis_pending_key key={.tid=bpf_get_current_pid_tgid(),.type=CIS_WORK_CANCEL};
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	if(!state || (!state->queued_valid && !state->active_valid)) return 0;
	e=state->active_valid?state->active:state->queued;
	if(!same_window(&e,CIS_DIAG_WORK,bpf_ktime_get_ns())) return 0;
	key.task_start_ns=BPF_CORE_READ((struct task_struct*)bpf_get_current_task(),start_boottime);
	e.type=CIS_WORK_CANCEL; e.time_ns=bpf_ktime_get_ns();
	if(bpf_map_update_elem(&pending,&key,&e,BPF_NOEXIST)) { struct cis_bpf_stats *s=statistics(); COUNT(s,rejected); }
	return 0;
}

SEC("kretprobe/cancel_work_sync")
int work_cancel_end(struct pt_regs *ctx)
{
	struct cis_pending_key key={.tid=bpf_get_current_pid_tgid(),.type=CIS_WORK_CANCEL};
	struct cis_event *saved,e;
	struct cis_work_state *state;
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	key.task_start_ns=BPF_CORE_READ((struct task_struct*)bpf_get_current_task(),start_boottime);
	saved=bpf_map_lookup_elem(&pending,&key);
	if(!saved) return 0;
	e=*saved;
	e.duration_ns=bpf_ktime_get_ns()-e.time_ns; e.executor_tid=bpf_get_current_pid_tgid();
	e.flags=PT_REGS_RC_CORE(ctx)?1:0;
	if(same_window(&e,CIS_DIAG_WORK,bpf_ktime_get_ns())) emit(ctx,&e);
	state=bpf_map_lookup_elem(&work_items,&e.object);
	if(state) {
		__u64 sequence=state->active_valid?state->active.sequence_ns:state->queued.sequence_ns;
		if(sequence==e.sequence_ns) bpf_map_delete_elem(&work_items,&e.object);
	}
	bpf_map_delete_elem(&pending,&key); return 0;
}
