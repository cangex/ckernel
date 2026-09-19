// SPDX-License-Identifier: GPL-2.0
#define CIS_PROFILE 10
#include "cis.bpf.c"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct cis_block_event);
} block_watched SEC(".maps");

struct tag_key { __u64 tid, start; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct tag_key);
	__type(value, struct cis_block_tag_event);
} tag_pending SEC(".maps");

SEC("raw_tp/block_tag_wait")
int block_tag(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_bpf_stats *s = statistics();
	struct cis_block_tag_event e = {}, *saved;
	struct cis_identity id = {};
	struct task_struct *task = (void *)bpf_get_current_task();
	struct request_queue *q = (void *)ctx->args[0];
	struct tag_key key = { bpf_get_current_pid_tgid(), BPF_CORE_READ(task, start_boottime) };
	__u64 now = bpf_ktime_get_ns();
	__u32 phase = ctx->args[2], pc = BPF_CORE_READ(task, thread_info.preempt_count);

	COUNT(s, received);
	if (!q || !ctx->args[1] || phase < 1 || phase > 5 || (pc & 0x00ff0100U)) {
		COUNT(s, rejected); return 0;
	}
	if (phase == 1 || phase == 5) {
		if (!identity(task, &id) || !allowed(&id, CIS_DIAG_BLOCK, now)) return 0;
		e.base.id = id.id; e.base.generation = id.generation;
		e.base.tid = key.tid; e.task_start = key.start;
		e.base.sequence_ns = now; e.queue = (__u64)q;
		e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	} else {
		saved = bpf_map_lookup_elem(&tag_pending, &key);
		if (!saved) { COUNT(s, unmatched); return 0; }
		e = *saved;
		if (!same_window(&e.base, CIS_DIAG_BLOCK, now)) {
			if (phase == 4) bpf_map_delete_elem(&tag_pending, &key);
			COUNT(s, expired); return 0;
		}
		if (e.queue != (__u64)q) { COUNT(s, rejected); return 0; }
		identity(task, &id);
	}
	e.base.time_ns = now; e.base.cpu = bpf_get_smp_processor_id();
	e.base.type = CIS_BLOCK_TAG_EVENT; e.base.object = ctx->args[1];
	e.phase = phase; e.alloc_flags = ctx->args[3]; e.tag = (int)ctx->args[4];
	e.dev_major = BPF_CORE_READ(q, disk, major); e.dev_minor = BPF_CORE_READ(q, disk, first_minor);
	e.actor_id = id.id; e.actor_generation = id.generation;
	if (phase == 1 && bpf_map_update_elem(&tag_pending, &key, &e, BPF_NOEXIST)) {
		COUNT(s, rejected); return 0;
	}
	if (phase == 4) bpf_map_delete_elem(&tag_pending, &key);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}

static __always_inline int block_event(void *ctx, struct request *rq,
		__u32 phase, __u32 completed, __u32 status)
{
	struct cis_bpf_stats *s = statistics();
	struct cis_block_event e = {}, *saved;
	struct cis_identity id = {}, executor = {};
	struct task_struct *task = (void *)bpf_get_current_task();
	struct bio *bio;
	__u64 object = (__u64)rq, now = bpf_ktime_get_ns();
	__u32 pc = BPF_CORE_READ(task, thread_info.preempt_count);
	__u32 context = (pc & 0x00f00000U) ? 3 : (pc & 0x000f0000U) ? 2 : (pc & 0x00000100U) ? 1 : 0;
	COUNT(s, received);
	if (!rq) { COUNT(s, rejected); return 0; }
	if (phase == 1) {
		if (context || !identity(task, &id) || !allowed(&id, CIS_DIAG_BLOCK, now)) return 0;
		e.base.id = id.id; e.base.generation = id.generation;
		e.base.time_ns = now; e.base.sequence_ns = now;
		e.base.object = object; e.base.tid = bpf_get_current_pid_tgid();
		e.submitter_start = BPF_CORE_READ(task, start_boottime);
	} else {
		saved = bpf_map_lookup_elem(&block_watched, &object);
		if (!saved) { COUNT(s, unmatched); return 0; }
		e = *saved;
		if (!same_window(&e.base, CIS_DIAG_BLOCK, now)) { COUNT(s, expired); return 0; }
	}
	e.base.time_ns = now; e.base.type = CIS_BLOCK_EVENT; e.base.cpu = bpf_get_smp_processor_id();
	e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	e.phase = phase; e.completed = completed; e.status = status; e.context = context;
	e.queue = (__u64)BPF_CORE_READ(rq, q);
	e.dev_major = BPF_CORE_READ(rq, q, disk, major);
	e.dev_minor = BPF_CORE_READ(rq, q, disk, first_minor);
	e.remaining = BPF_CORE_READ(rq, __data_len); e.operation = BPF_CORE_READ(rq, cmd_flags);
	bio = BPF_CORE_READ(rq, bio); e.bio = (__u64)bio;
	e.multi_bio = bio && BPF_CORE_READ(bio, bi_next) != 0;
	e.bio_cgroup=0; e.bio_owner_id=0; e.bio_owner_generation=0;
	e.bio_bytes=0; e.bio_origin_overdepth=0;
	if (bio) {
		struct kernfs_node *kn=BPF_CORE_READ(bio,bi_blkg,blkcg,css.cgroup,kn);
		e.bio_cgroup=BPF_CORE_READ(kn,id);
		e.bio_bytes=BPF_CORE_READ(bio,bi_iter.bi_size);
#pragma clang loop unroll(disable)
		for (int i=0;i<32;i++) {
			struct cis_identity *origin;
			__u64 cg;
			if (!kn) break;
			cg=BPF_CORE_READ(kn,id); origin=bpf_map_lookup_elem(&roots,&cg);
			if (origin) {e.bio_owner_id=origin->id; e.bio_owner_generation=origin->generation; kn=NULL; break;}
			kn=BPF_CORE_READ(kn,parent);
		}
		if (kn) e.bio_origin_overdepth=1;
	}
	e.actor_id = 0; e.actor_generation = 0; e.actor_tid = 0; e.actor_start = 0;
	if (!context) {
		e.actor_tid = bpf_get_current_pid_tgid(); e.actor_start = BPF_CORE_READ(task, start_boottime);
		if (identity(task, &executor)) { e.actor_id = executor.id; e.actor_generation = executor.generation; }
	}
	if (phase == 1) {
		if (bpf_map_update_elem(&block_watched, &object, &e, BPF_NOEXIST)) { COUNT(s, rejected); return 0; }
	} else if (phase == 6 || (phase == 5 && completed >= e.remaining)) {
		/* Terminal data completion/transfer, not proof of request-memory free. */
		bpf_map_delete_elem(&block_watched, &object);
	}
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}

SEC("raw_tp/block_io_start")
int block_start(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 1, 0, 0); }
SEC("raw_tp/block_rq_insert")
int block_insert(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 2, 0, 0); }
SEC("raw_tp/block_rq_issue")
int block_issue(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 3, 0, 0); }
SEC("raw_tp/block_rq_requeue")
int block_requeue(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 4, 0, 0); }
SEC("raw_tp/block_rq_complete")
int block_complete(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 5, ctx->args[2], ctx->args[1]); }
SEC("raw_tp/block_rq_merge")
int block_merge(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 6, 0, 0); }
SEC("raw_tp/block_rq_remap")
int block_remap(struct bpf_raw_tracepoint_args *ctx) { return block_event(ctx, (void *)ctx->args[0], 7, 0, 0); }
