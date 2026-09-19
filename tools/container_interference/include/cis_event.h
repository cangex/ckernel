/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_EVENT_H
#define CIS_EVENT_H
#define CIS_BUFFER_PAGES 2
#define CIS_INFLIGHT 1024
#define CIS_STACKS 256
#define CIS_STACK_DEPTH 64
#define CIS_DIAG_SCHED 1
#define CIS_DIAG_LOCK 2
#define CIS_DIAG_RECLAIM 4
#define CIS_DIAG_WORK 8
#define CIS_DIAG_OWNER 16
#define CIS_DIAG_COUNTER 32
#define CIS_DIAG_ALLOCATOR 64
#define CIS_DIAG_NET 128
#define CIS_DIAG_BLOCK 256
#define CIS_DIAG_RWSEM 512
#define CIS_OWNER_EVENT 12
#define CIS_COUNTER_EVENT 13
#define CIS_ALLOC_EVENT 14
#define CIS_ALLOC_RELEASE_EVENT 15
#define CIS_NET_EVENT 16
#define CIS_BLOCK_EVENT 17
#define CIS_RWSEM_EVENT 18
#define CIS_BLOCK_TAG_EVENT 19
#define CIS_BLOCK_LINK_EVENT 20
#define CIS_BLOCK_BIO_EVENT 21
#define CIS_WRITEBACK_EVENT 22
#define CIS_MAPLE_EVENT 23
#define CIS_NET_TX_EVENT 24
struct cis_identity { __u64 id, generation; };
struct cis_target { __u64 generation, deadline_ns, start_ns; __u32 kind, reserved; };
enum cis_event_type { CIS_IP=1, CIS_SCHED_WAIT, CIS_LOCK_WAIT, CIS_RECLAIM, CIS_UNFINISHED,
	CIS_WORK_QUEUED, CIS_WORK_START, CIS_WORK_END, CIS_WORK_CANCEL, CIS_WORK_UNRESOLVED, CIS_MEMCG_RECLAIM };
struct cis_event {
	__u64 time_ns, id, generation, tid, object, duration_ns, ip, weight;
	__u32 type, cpu, flags;
	__s32 stack_id;
	__u32 nesting, reserved;
	__u64 executor_tid, sequence_ns;
};
struct cis_work_state { struct cis_event queued, active; __u32 queued_valid, active_valid; };
struct cis_pending_key { __u64 tid, object, task_start_ns; __u32 type, reserved; };
struct cis_bpf_stats {
	__u64 received, emitted, lost, unknown, overdepth, unmatched, nested, rejected,
	      expired, phase_changes, irq_context, owner_seen, owner_skip_base, owner_skipped;
	__u64 owner_entries, owner_sched_entries, owner_target_waits, owner_watch_events;
	__u64 owner_watch_races, owner_watch_failed, owner_holder_failed, owner_attempt_failed;
};
struct cis_owner_event {
	/* OWNER resource 4 uses the otherwise unused base.ip as a u64 cache
	 * address. It is not a sampled IP or the 32-bit flags field. */
	struct cis_event base;
	__u64 actor_id, actor_generation, actor_start;
	__u64 holder_id, holder_generation, holder_tid, holder_start;
	__u32 phase, resource;
	__u64 skipped;
	__u64 attempt_ns;
};
struct cis_attempt { __u64 start_ns, epoch, id, generation; };
struct cis_counter_event {
	struct cis_event base;
	__u64 leaf, parent, task_start, pages, limit;
	__u64 leaf_generation, object_generation, parent_generation;
	__s64 usage;
	__u32 operation, stage, depth, ordinal, sample_shift, reserved;
};
#define CIS_COUNTER_BUCKETS 96 /* 8 selected objects x 2 targets x 6 operations */
struct cis_counter_actor { __u64 generation; __u32 slot, reserved; };
struct cis_counter_sum {
	__u64 generation, first_ns, last_ns;
	__u64 counts[7], pages[7]; /* stages 2..8; keep rollback separate */
	__u64 offset_hist[8]; /* call-entry to this step, not atomic latency */
	__u32 shift, tainted, min_depth, max_depth;
};
struct cis_alloc_event {
	struct cis_event base;
	__u64 cache, resource, task_start, gfp, requested, count;
	__u32 operation, stage, ordinal, sample_shift;
	__s32 requested_node, observed_node;
};
struct cis_alloc_live_key { __u64 cache, object; };
struct cis_alloc_live { struct cis_event allocation; __u64 task_start; };
struct cis_maple_key { __u64 tid, task_start; };
struct cis_maple_event {
	struct cis_event base; /* object=tree, sequence_ns=wrapper begin, weight=backend call */
	__u64 task_start, cache, gfp, requested, count;
	__u32 operation, reserved;
};
struct cis_alloc_release_event {
	struct cis_event base;
	__u64 cache, allocation_task_start, executor_start, executor_id, executor_generation;
};
struct cis_net_event {
	struct cis_event base;
	__u64 cookie, skb, actor_id, actor_generation, actor_start;
	__u32 phase, netns, bytes, backlog_bytes, packet_flags, reserved;
};
struct cis_net_service_key { __u64 cookie, skb, tid, task_start; };
struct cis_net_tx_event {
	/* object=skb, sequence_ns=allocation start; owner never changes on free. */
	struct cis_event base;
	__u64 cookie, socket, backend_ns, task_start;
	__u64 actor_id, actor_generation, actor_tid, actor_start;
	__u32 phase, netns, gfp, requested;
};
struct cis_block_event {
	/* BLOCK does not sample IP/weight: base.ip/weight hold the immutable
	 * submitter id/generation, base.flags its task flags, base.reserved the
	 * admission kind. Reuse avoids exceeding the BPF caller+callee stack. */
	struct cis_event base;
	__u64 queue, bio, submitter_start, actor_id, actor_generation, actor_tid, actor_start;
	__u64 bio_cgroup, bio_owner_id, bio_owner_generation;
	__u32 bio_bytes, bio_origin_overdepth;
	__u32 phase, dev_major, dev_minor, remaining, completed, operation, multi_bio, context, status, reserved;
};
struct cis_block_tag_event {
	struct cis_event base;
	__u64 queue, task_start, actor_id, actor_generation;
	__u32 phase, alloc_flags, dev_major, dev_minor;
	__s32 tag;
	__u32 reserved;
};
struct cis_block_link_event {
	struct cis_event base;
	__u64 queue, victim, victim_episode, bio;
	__u32 kind, before_bytes, added_bytes, reserved;
};
struct cis_block_bio_event {
	struct cis_event base;
	__u64 bio, cgroup, owner_id, owner_generation;
	__u32 index, bytes, remaining, more, overdepth, reserved;
};
struct cis_writeback_event {
	/* object=inode, ip=i_ino, flags=i_generation, nesting=s_dev,
	 * reserved=phase, weight=folio index (dirty observations only). */
	struct cis_event base;
	__u64 task_start, actor_id, actor_generation, wbc, memcg;
	__u64 wb_owner_id, wb_owner_generation, request, request_episode;
};
struct cis_object_key { __u64 object; __u32 kind, reserved; };
struct cis_rwsem_event {
	struct cis_event base;
	__u64 actor_id, actor_generation, actor_start, skipped;
	__u32 phase, reserved;
};
struct cis_watch { __u64 id, generation, start_ns, deadline_ns, epoch, events; };
struct cis_owner_record { __u64 id, generation, tid, task_start, acquired_ns, epoch; };
struct cis_owner_task { struct cis_object_key key; __u64 task_start, epoch; };
#endif
