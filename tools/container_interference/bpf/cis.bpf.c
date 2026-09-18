// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../include/cis_event.h"
#ifndef CIS_PROFILE
#define CIS_PROFILE 0
#endif
char LICENSE[] SEC("license") = "GPL";
struct session_window { __u64 session_id, start_ns, end_ns; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct session_window); } session_window SEC(".maps");
#define COUNT(s, field) do { if (s) __sync_fetch_and_add(&(s)->field, 1); } while (0)
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,256); __type(key,__u64); __type(value,struct cis_identity); } roots SEC(".maps");
#if CIS_PROFILE != 1
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,2); __type(key,__u64); __type(value,struct cis_target); } targets SEC(".maps");
#endif
struct { __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries,512); __type(key,__u32); __type(value,__u32); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct cis_bpf_stats); } stats SEC(".maps");
#if CIS_PROFILE == 0 || CIS_PROFILE == 4 || CIS_PROFILE == 5 || CIS_PROFILE == 7 || CIS_PROFILE == 8
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,CIS_INFLIGHT); __type(key,struct cis_pending_key); __type(value,struct cis_event); } pending SEC(".maps");
#endif
#if CIS_PROFILE == 0 || CIS_PROFILE == 2 || CIS_PROFILE == 4 || CIS_PROFILE == 5 || CIS_PROFILE == 6 || CIS_PROFILE == 7 || CIS_PROFILE == 8 || CIS_PROFILE == 9
struct { __uint(type,BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries,CIS_STACKS); __type(key,__u32); __type(value,__u64[CIS_STACK_DEPTH]); } stacks SEC(".maps");
#endif
#if CIS_PROFILE == 0
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,128); __type(key,__u64); __type(value,struct cis_work_state); } work_items SEC(".maps");
#endif
#if CIS_PROFILE == 8
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,CIS_INFLIGHT); __type(key,struct cis_alloc_live_key); __type(value,struct cis_alloc_live); } alloc_live SEC(".maps");
#endif
#if CIS_PROFILE == 9
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,64); __type(key,__u64); __type(value,struct cis_watch); } net_watched SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,256); __type(key,__u64); __type(value,struct cis_net_event); } net_skb SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,256); __type(key,struct cis_net_service_key); __type(value,struct cis_net_event); } net_service SEC(".maps");
#endif
#if CIS_PROFILE == 0 || CIS_PROFILE == 2 || CIS_PROFILE == 6
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,64); __type(key,struct cis_object_key); __type(value,struct cis_watch); } watched SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,128); __type(key,struct cis_object_key); __type(value,struct cis_owner_record); } holders SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,128); __type(key,__u64); __type(value,struct cis_owner_task); } holder_tasks SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,CIS_INFLIGHT); __type(key,struct cis_pending_key); __type(value,struct cis_attempt); } owner_attempts SEC(".maps");

static __always_inline struct cis_bpf_stats *statistics(void);
static __always_inline void owner_emit(void *ctx,struct cis_owner_event *e)
{
	struct cis_bpf_stats *s;
	s=statistics();
	if(bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,e,sizeof(*e))) COUNT(s,lost);
	else COUNT(s,emitted);
}
#endif

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

#if CIS_PROFILE != 1
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
#endif

static __always_inline void emit(void *ctx,struct cis_event *e)
{
	struct cis_bpf_stats *s=statistics();
	if(bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,e,sizeof(*e))) COUNT(s,lost);
	else COUNT(s,emitted);
}

#if CIS_PROFILE == 9
static __always_inline void net_actor(struct cis_net_event *e, u32 context)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_identity actor = {};
	e->base.flags = context; e->base.cpu = bpf_get_smp_processor_id();
	e->base.tid = 0; e->actor_start = 0; e->actor_id = 0; e->actor_generation = 0;
	if (!context) {
		e->base.tid = bpf_get_current_pid_tgid();
		e->actor_start = BPF_CORE_READ(task, start_boottime);
		if (identity(task, &actor)) { e->actor_id = actor.id; e->actor_generation = actor.generation; }
	}
}
static __always_inline void net_emit(void *ctx, struct cis_net_event *e)
{
	struct cis_bpf_stats *s = statistics();
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e))) COUNT(s, lost);
	else COUNT(s, emitted);
}
SEC("raw_tp/cis_net_state")
int net_state(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_net_sample *sample = (void *)ctx->args[0];
	struct cis_net_event e = {};
	struct cis_bpf_stats *s = statistics();
	struct cis_watch *watch, new_watch = {};
	struct cis_net_service_key key = {};
	struct cis_net_event *queued;
	u64 now = BPF_CORE_READ(sample, time_ns), cookie = BPF_CORE_READ(sample, cookie);
	u32 phase = BPF_CORE_READ(sample, phase), context = BPF_CORE_READ(sample, context);
	COUNT(s, received);
	if (!cookie || context > 2 || phase < 1 || phase > 8) { COUNT(s, rejected); return 0; }
	net_actor(&e, context);
	watch = bpf_map_lookup_elem(&net_watched, &cookie);
	if (!watch && phase <= 5 && e.actor_id) {
		struct cis_identity actor = { .id = e.actor_id, .generation = e.actor_generation };
		struct cis_target *target;
		if (!allowed(&actor, CIS_DIAG_NET, now)) return 0;
		target = bpf_map_lookup_elem(&targets, &actor.id);
		if (!target) return 0;
		new_watch.id = actor.id; new_watch.generation = actor.generation;
		new_watch.start_ns = target->start_ns; new_watch.deadline_ns = target->deadline_ns;
		new_watch.epoch = now;
		bpf_map_update_elem(&net_watched, &cookie, &new_watch, BPF_NOEXIST);
		watch = bpf_map_lookup_elem(&net_watched, &cookie);
		if (!watch) { COUNT(s, rejected); return 0; }
	}
	if (!watch) return 0;
	if (now < watch->start_ns || now >= watch->deadline_ns) { COUNT(s, expired); return 0; }
	e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	e.base.id = watch->id; e.base.generation = watch->generation;
	e.base.time_ns = now; e.base.type = CIS_NET_EVENT;
	e.base.object = (u64)BPF_CORE_READ(sample, sk); e.cookie = cookie;
	e.skb = (u64)BPF_CORE_READ(sample, skb); e.phase = phase;
	e.netns = BPF_CORE_READ(sample, netns); e.bytes = BPF_CORE_READ(sample, bytes);
	e.backlog_bytes = BPF_CORE_READ(sample, backlog_bytes); e.packet_flags = BPF_CORE_READ(sample, flags);
	key.cookie = cookie; key.skb = e.skb; key.tid = e.base.tid; key.task_start = e.actor_start;
	if (phase == 6) {
		e.base.sequence_ns = now;
		if (!e.skb || bpf_map_update_elem(&net_skb, &e.skb, &e, BPF_NOEXIST)) { COUNT(s, rejected); return 0; }
	} else if (phase == 7) {
		queued = bpf_map_lookup_elem(&net_skb, &e.skb);
		if (!queued || queued->cookie != cookie) { COUNT(s, unmatched); return 0; }
		e.base.sequence_ns = queued->base.sequence_ns;
		if (bpf_map_update_elem(&net_service, &key, &e, BPF_NOEXIST)) { COUNT(s, rejected); return 0; }
	} else if (phase == 8) {
		queued = bpf_map_lookup_elem(&net_service, &key);
		if (!queued) { COUNT(s, unmatched); return 0; }
		e.base.sequence_ns = queued->base.sequence_ns;
		bpf_map_delete_elem(&net_service, &key);
	}
	net_emit(ctx, &e);
	return 0;
}
SEC("raw_tp/cis_net_skb_release")
int net_release(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_net_sample *sample = (void *)ctx->args[0];
	u64 skb = (u64)BPF_CORE_READ(sample, skb), now = BPF_CORE_READ(sample, time_ns);
	struct cis_net_event *queued, e = {};
	struct cis_bpf_stats *s = statistics();
	COUNT(s, received);
	queued = bpf_map_lookup_elem(&net_skb, &skb);
	if (!queued) return 0;
	e = *queued;
	bpf_map_delete_elem(&net_skb, &skb);
	if (!same_window(&e.base, CIS_DIAG_NET, now)) { COUNT(s, expired); return 0; }
	e.base.time_ns = now; e.phase = 9;
	net_actor(&e, BPF_CORE_READ(sample, context));
	e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	net_emit(ctx, &e);
	return 0;
}
#endif

#if CIS_PROFILE == 8
SEC("raw_tp/cis_alloc_step")
int alloc_step(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_alloc_sample *sample = (void *)ctx->args[0];
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_alloc_event e = {};
	struct cis_identity id = {};
	struct cis_pending_key key = {};
	struct cis_event *saved, begin = {};
	struct cis_bpf_stats *s = statistics();
	u64 now = bpf_ktime_get_ns();

	COUNT(s, received);
	if (!synchronous_context()) return 0;
	e.base.sequence_ns = BPF_CORE_READ(sample, start_ns);
	e.base.time_ns = BPF_CORE_READ(sample, time_ns);
	e.stage = BPF_CORE_READ(sample, stage);
	key.tid = bpf_get_current_pid_tgid();
	key.task_start_ns = BPF_CORE_READ(task, start_boottime);
	key.object = e.base.sequence_ns; key.type = CIS_ALLOC_EVENT;
	if (e.stage == 1) {
		if (!identity(task, &id) || !allowed(&id, CIS_DIAG_ALLOCATOR, now)) return 0;
		begin.time_ns = e.base.sequence_ns; begin.id = id.id; begin.generation = id.generation;
		begin.type = CIS_ALLOC_EVENT; begin.tid = key.tid; begin.object = key.object;
		begin.stack_id = bpf_get_stackid(ctx, &stacks, 0);
		if (bpf_map_update_elem(&pending, &key, &begin, BPF_NOEXIST)) {
			COUNT(s, rejected); return 0;
		}
	}
	saved = bpf_map_lookup_elem(&pending, &key);
	if (!saved) return 0;
	if (!same_window(saved, CIS_DIAG_ALLOCATOR, now)) {
		COUNT(s, expired); bpf_map_delete_elem(&pending, &key); return 0;
	}
	e.base.id = saved->id; e.base.generation = saved->generation;
	e.base.stack_id = saved->stack_id; e.base.type = CIS_ALLOC_EVENT;
	e.base.tid = key.tid; e.task_start = key.task_start_ns;
	e.base.cpu = bpf_get_smp_processor_id(); e.base.object = (u64)BPF_CORE_READ(sample, object);
	e.cache = (u64)BPF_CORE_READ(sample, cache); e.resource = (u64)BPF_CORE_READ(sample, resource);
	e.gfp = BPF_CORE_READ(sample, gfp); e.requested = BPF_CORE_READ(sample, requested);
	e.count = BPF_CORE_READ(sample, count); e.operation = BPF_CORE_READ(sample, operation);
	e.ordinal = BPF_CORE_READ(sample, ordinal); e.sample_shift = BPF_CORE_READ(sample, sample_shift);
	e.requested_node = BPF_CORE_READ(sample, requested_node);
	e.observed_node = BPF_CORE_READ(sample, observed_node);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	if (e.base.object && (e.stage == 17 || (e.stage == 20 && e.operation == 1 && e.count == 1))) {
		struct cis_alloc_live_key object_key = { .cache = e.cache, .object = e.base.object };
		struct cis_alloc_live live = { .allocation = e.base, .task_start = e.task_start };
		live.allocation.nesting = e.ordinal;
		/* Never silently replace an unmatched lifetime at the same address. */
		if (bpf_map_update_elem(&alloc_live, &object_key, &live, BPF_NOEXIST)) COUNT(s, rejected);
	}
	if (e.stage == 20) bpf_map_delete_elem(&pending, &key);
	return 0;
}

SEC("raw_tp/cis_alloc_release")
int alloc_release(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_alloc_release_sample *sample = (void *)ctx->args[0];
	struct cis_alloc_live_key key = { .cache = (u64)BPF_CORE_READ(sample, cache),
		.object = (u64)BPF_CORE_READ(sample, object) };
	struct cis_alloc_live *live;
	struct cis_alloc_release_event e = {};
	struct cis_bpf_stats *s = statistics();
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_identity executor = {};
	u64 now = BPF_CORE_READ(sample, time_ns);

	COUNT(s, received);
	live = bpf_map_lookup_elem(&alloc_live, &key);
	if (!live) return 0;
	if (!same_window(&live->allocation, CIS_DIAG_ALLOCATOR, now)) {
		COUNT(s, expired); bpf_map_delete_elem(&alloc_live, &key); return 0;
	}
	e.base = live->allocation; e.allocation_task_start = live->task_start;
	e.base.weight = e.base.time_ns; e.base.time_ns = now;
	e.base.type = CIS_ALLOC_RELEASE_EVENT; e.cache = key.cache;
	e.base.flags = BPF_CORE_READ(sample, context); e.base.cpu = bpf_get_smp_processor_id();
	e.base.ip = BPF_CORE_READ(sample, caller);
	e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	e.base.executor_tid = 0;
	if (!e.base.flags) {
		e.base.executor_tid = bpf_get_current_pid_tgid();
		e.executor_start = BPF_CORE_READ(task, start_boottime);
		if (identity(task, &executor)) {
			e.executor_id = executor.id; e.executor_generation = executor.generation;
		}
	}
	/* The hook precedes publication for reuse; retire identity before returning. */
	bpf_map_delete_elem(&alloc_live, &key);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}
#endif

#if CIS_PROFILE == 7
SEC("raw_tp/cis_counter_step")
int counter_step(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_counter_sample *sample = (void *)ctx->args[0];
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_counter_event e = {};
	struct cis_identity id = {};
	struct cis_pending_key key = {};
	struct cis_event *saved, begin = {};
	struct cis_bpf_stats *s = statistics();
	u64 now = bpf_ktime_get_ns();

	COUNT(s, received);
	if (!synchronous_context()) return 0;
	e.base.sequence_ns = BPF_CORE_READ(sample, start_ns);
	e.base.time_ns = BPF_CORE_READ(sample, time_ns);
	e.stage = BPF_CORE_READ(sample, stage);
	key.tid = bpf_get_current_pid_tgid();
	key.task_start_ns = BPF_CORE_READ(task, start_boottime);
	key.object = e.base.sequence_ns; key.type = CIS_COUNTER_EVENT;
	if (e.stage == 1) {
		if (!identity(task, &id) || !allowed(&id, CIS_DIAG_COUNTER, now)) return 0;
		begin.time_ns = e.base.sequence_ns; begin.id = id.id;
		begin.type = CIS_COUNTER_EVENT; begin.tid = key.tid; begin.object = key.object;
		begin.generation = id.generation; begin.stack_id = bpf_get_stackid(ctx, &stacks, 0);
		if (bpf_map_update_elem(&pending, &key, &begin, BPF_NOEXIST)) {
			COUNT(s, rejected); return 0;
		}
	}
	saved = bpf_map_lookup_elem(&pending, &key);
	if (!saved) return 0; /* Unselected/pre-window calls are not partial target calls. */
	if (!same_window(saved, CIS_DIAG_COUNTER, now)) {
		COUNT(s, expired); bpf_map_delete_elem(&pending, &key); return 0;
	}
	e.base.id = saved->id; e.base.generation = saved->generation;
	e.base.stack_id = saved->stack_id; e.base.type = CIS_COUNTER_EVENT;
	e.base.tid = key.tid; e.task_start = key.task_start_ns;
	e.base.cpu = bpf_get_smp_processor_id();
	e.base.object = (u64)BPF_CORE_READ(sample, counter);
	e.leaf = (u64)BPF_CORE_READ(sample, leaf); e.parent = (u64)BPF_CORE_READ(sample, parent);
	e.leaf_generation = BPF_CORE_READ(sample, leaf_generation);
	e.object_generation = BPF_CORE_READ(sample, generation);
	e.parent_generation = BPF_CORE_READ(sample, parent_generation);
	e.pages = BPF_CORE_READ(sample, pages); e.limit = BPF_CORE_READ(sample, limit);
	e.usage = BPF_CORE_READ(sample, usage); e.operation = BPF_CORE_READ(sample, op);
	e.depth = BPF_CORE_READ(sample, depth); e.ordinal = BPF_CORE_READ(sample, ordinal);
	e.sample_shift = BPF_CORE_READ(sample, sample_shift);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	if (e.stage == 9) bpf_map_delete_elem(&pending, &key);
	return 0;
}
#endif

#if CIS_PROFILE == 0 || CIS_PROFILE == 1
SEC("perf_event")
int sample_ip(struct bpf_perf_event_data *ctx)
{
	struct cis_identity id={0};
	struct cis_event e={0};
	struct cis_bpf_stats *s=statistics();
	COUNT(s,received);
	{
		__u32 zero=0;
		struct session_window *w=bpf_map_lookup_elem(&session_window,&zero);
		__u64 now=bpf_ktime_get_ns();
		/* Zero ID preserves the legacy ambient collector. Session resources are fresh. */
		if(w && w->session_id && (now<w->start_ns || now>=w->end_ns)) return 0;
	}
	if(!identity((void*)bpf_get_current_task(),&id)) return 0;
	e.time_ns=bpf_ktime_get_ns(); e.id=id.id; e.generation=id.generation;
	e.tid=bpf_get_current_pid_tgid(); e.ip=ctx->regs.pc; e.weight=ctx->sample_period;
	e.type=CIS_IP; e.cpu=bpf_get_smp_processor_id(); e.stack_id=-1;
	emit(ctx,&e); return 0;
}
#endif

#if CIS_PROFILE == 0 || CIS_PROFILE == 3
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
#endif

#if CIS_PROFILE == 0 || CIS_PROFILE == 4 || CIS_PROFILE == 5
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

#if CIS_PROFILE == 0 || CIS_PROFILE == 5
SEC("raw_tp/contention_begin")
int lock_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,ctx->args[0],CIS_LOCK_WAIT,CIS_DIAG_LOCK,ctx->args[1]); }
SEC("raw_tp/contention_end")
int lock_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx,ctx->args[0],CIS_LOCK_WAIT,CIS_DIAG_LOCK,ctx->args[1]); }
#endif
#if CIS_PROFILE == 0 || CIS_PROFILE == 4
SEC("raw_tp/mm_vmscan_direct_reclaim_begin")
int reclaim_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,0,CIS_RECLAIM,CIS_DIAG_RECLAIM,0); }
SEC("raw_tp/mm_vmscan_direct_reclaim_end")
int reclaim_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx,0,CIS_RECLAIM,CIS_DIAG_RECLAIM,0); }

SEC("raw_tp/mm_vmscan_memcg_reclaim_begin")
int memcg_begin(struct bpf_raw_tracepoint_args *ctx) { return begin(ctx,0,CIS_MEMCG_RECLAIM,CIS_DIAG_RECLAIM,0); }
SEC("raw_tp/mm_vmscan_memcg_reclaim_end")
int memcg_end(struct bpf_raw_tracepoint_args *ctx) { return finish(ctx,0,CIS_MEMCG_RECLAIM,CIS_DIAG_RECLAIM,0); }
#endif
#endif

#if CIS_PROFILE == 0
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

#endif
#if CIS_PROFILE == 0 || CIS_PROFILE == 2 || CIS_PROFILE == 6
static __always_inline int live_watch(struct cis_watch *w,__u64 now)
{
	struct cis_target *t;
	if(!w || now<w->start_ns || now>=w->deadline_ns) return 0;
	t=bpf_map_lookup_elem(&targets,&w->id);
	return t && t->generation==w->generation && t->start_ns==w->start_ns &&
	       (t->kind&CIS_DIAG_OWNER);
}

#if CIS_PROFILE == 6
SEC("raw_tp/cis_fdlock_state")
#else
SEC("raw_tp/cis_lock_state")
#endif
int owner_state(struct bpf_raw_tracepoint_args *ctx)
{
	/* Keep this raw-tp argument as a scalar: older verifiers reject a ctx+40 alias. */
	volatile __u64 raw_skipped=ctx->args[5];
	struct cis_object_key key={.object=ctx->args[0],.kind=ctx->args[1]};
	struct cis_owner_event e={0};
	struct cis_identity actor={0},holder={0};
	struct cis_owner_record rec={0},*old;
	struct cis_watch *w,create={0};
	struct task_struct *task=(void*)bpf_get_current_task(),*owner=(void*)ctx->args[3];
	struct cis_bpf_stats *s=statistics();
	__u64 now=bpf_ktime_get_ns(),tid=bpf_get_current_pid_tgid();
	__u32 phase=ctx->args[2];
	COUNT(s,received);
	COUNT(s,owner_entries);
	if (CIS_PROFILE == 6 ? key.kind != 3 : (key.kind < 1 || key.kind > 2)) { COUNT(s,rejected); return 0; }
	if(s) {
		if(!s->owner_seen) {s->owner_seen=1;s->owner_skip_base=raw_skipped;}
		s->owner_skipped=raw_skipped-s->owner_skip_base;
	}
	if(!synchronous_context()) return 0;
	w=bpf_map_lookup_elem(&watched,&key);
	if(w && !live_watch(w,now)) { bpf_map_delete_elem(&watched,&key); w=NULL; }
	if(!w && phase!=2) return 0;
	if(w && key.kind>=2 && w->events>64 && phase!=1 && phase!=8) return 0;
	identity(task,&actor);
	if(phase==2 && allowed(&actor,CIS_DIAG_OWNER,now)) {
		struct cis_target *t=bpf_map_lookup_elem(&targets,&actor.id);
		COUNT(s,owner_target_waits);
		if(!t) return 0;
		if(!w) {
			long result;
			create.id=actor.id;create.generation=actor.generation;
			create.start_ns=t->start_ns;create.deadline_ns=t->deadline_ns;create.epoch=now;
			result=bpf_map_update_elem(&watched,&key,&create,BPF_NOEXIST);
			/* Concurrent target waiters may publish the same object. Only
			 * EEXIST plus a live lookup is benign; capacity failures stay fatal. */
			if(result && result!=-17) {COUNT(s,owner_watch_failed);COUNT(s,rejected);return 0;}
			w=bpf_map_lookup_elem(&watched,&key);
			if(!live_watch(w,now)) {COUNT(s,owner_watch_failed);COUNT(s,rejected);return 0;}
			if(result==-17) COUNT(s,owner_watch_races);
		}
	}
	if(phase==3 && w) {
		rec.id=actor.id;rec.generation=actor.generation;rec.tid=tid;
		rec.task_start=BPF_CORE_READ(task,start_boottime);rec.acquired_ns=now;rec.epoch=w->epoch;
		if(bpf_map_update_elem(&holders,&key,&rec,BPF_ANY)) {COUNT(s,owner_holder_failed);COUNT(s,rejected);}
	}
	if(w) {
		COUNT(s,owner_watch_events);
		if(key.kind>=2 && phase!=1 && phase!=8) {
			__u64 seq;
			/* A bounded prefix, not dropped records in an allegedly complete window. */
			if(w->events>64) return 0;
			seq=__sync_fetch_and_add(&w->events,1);
			if(seq==64) phase=11;
			else if(seq>64) return 0;
		}
		e.base.id=w->id;e.base.generation=w->generation;e.base.sequence_ns=w->epoch;
		e.base.time_ns=now;e.base.type=CIS_OWNER_EVENT;e.base.object=key.object;
		e.base.cpu=bpf_get_smp_processor_id();e.base.tid=tid;e.base.stack_id=-1;
		e.phase=phase;e.resource=key.kind;e.skipped=s?s->owner_skipped:1;
		e.actor_id=actor.id;e.actor_generation=actor.generation;
		e.actor_start=BPF_CORE_READ(task,start_boottime);e.base.flags=ctx->args[4];
		if(phase==2 || phase==3 || phase==12) {
			struct cis_pending_key pk={.tid=tid,.object=key.object,
				.task_start_ns=e.actor_start,.type=key.kind};
			struct cis_attempt *a,attempt={.start_ns=now,.epoch=w->epoch,
				.id=w->id,.generation=w->generation};
			if(phase==2) {
				/* A new WAIT replaces only this task's attempt. No global sequence. */
				if(bpf_map_update_elem(&owner_attempts,&pk,&attempt,BPF_ANY)) {COUNT(s,owner_attempt_failed);COUNT(s,rejected);}
			}
			a=bpf_map_lookup_elem(&owner_attempts,&pk);
			if(a && a->epoch==w->epoch) e.attempt_ns=a->start_ns;
			if(phase!=2) bpf_map_delete_elem(&owner_attempts,&pk);
		}
		if(phase==2 && owner) {
			identity(owner,&holder);
			e.holder_id=holder.id;e.holder_generation=holder.generation;
			e.holder_tid=((__u64)BPF_CORE_READ(owner,tgid)<<32)|(__u32)BPF_CORE_READ(owner,pid);
			e.holder_start=BPF_CORE_READ(owner,start_boottime);
		}
		if(phase==2) e.base.stack_id=bpf_get_stackid(ctx,&stacks,0);
		if(phase!=5) owner_emit(ctx,&e);
		if(phase==2 || phase==3) {
			struct cis_owner_record *h=bpf_map_lookup_elem(&holders,&key);
			if(h && h->epoch==w->epoch) {
				struct cis_owner_task ht={.key=key,.task_start=h->task_start,.epoch=w->epoch};
				bpf_map_update_elem(&holder_tasks,&h->tid,&ht,BPF_ANY);
			}
		}
	}
	if(phase==1 || phase==4 || phase==7 || phase==8) {
		old=bpf_map_lookup_elem(&holders,&key);
		if(old) {
			struct cis_owner_task *ht=bpf_map_lookup_elem(&holder_tasks,&old->tid);
			if(ht && ht->key.object==key.object && ht->key.kind==key.kind)
				bpf_map_delete_elem(&holder_tasks,&old->tid);
		}
		bpf_map_delete_elem(&holders,&key);
	}
	if(phase==1 || phase==7 || phase==8) bpf_map_delete_elem(&watched,&key);
	return 0;
}

static __always_inline void owner_schedule(void *ctx,struct task_struct *task,__u32 phase,__u64 flags)
{
	__u64 tid=((__u64)BPF_CORE_READ(task,tgid)<<32)|(__u32)BPF_CORE_READ(task,pid);
	struct cis_owner_task *ht=bpf_map_lookup_elem(&holder_tasks,&tid);
	struct cis_owner_record *h;
	struct cis_watch *w;
	struct cis_owner_event e={0};
	__u64 now=bpf_ktime_get_ns();
	if(!ht || ht->task_start!=BPF_CORE_READ(task,start_boottime)) return;
	w=bpf_map_lookup_elem(&watched,&ht->key);
	h=bpf_map_lookup_elem(&holders,&ht->key);
	if(!live_watch(w,now) || (ht->key.kind>=2 && w->events>64) || !h ||
	   h->epoch!=w->epoch || ht->epoch!=w->epoch || h->tid!=tid || h->task_start!=ht->task_start) return;
	e.base.id=w->id;e.base.generation=w->generation;e.base.sequence_ns=w->epoch;
	e.base.time_ns=now;e.base.type=CIS_OWNER_EVENT;e.base.object=ht->key.object;
	e.base.tid=tid;e.base.cpu=bpf_get_smp_processor_id();e.base.flags=flags;
	e.base.stack_id=-1;e.phase=phase;e.resource=ht->key.kind;
	e.actor_id=h->id;e.actor_generation=h->generation;e.actor_start=h->task_start;
	owner_emit(ctx,&e);
}

SEC("raw_tp/sched_switch")
int owner_switch(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_bpf_stats *s=statistics(); COUNT(s,received);
	COUNT(s,owner_sched_entries);
	owner_schedule(ctx,(void*)ctx->args[1],9,ctx->args[0]?1:ctx->args[3]?2:4);
	owner_schedule(ctx,(void*)ctx->args[2],10,0);
	return 0;
}
#endif
