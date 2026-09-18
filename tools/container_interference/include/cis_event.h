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
#define CIS_OWNER_EVENT 12
#define CIS_COUNTER_EVENT 13
#define CIS_ALLOC_EVENT 14
#define CIS_ALLOC_RELEASE_EVENT 15
#define CIS_NET_EVENT 16
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
struct cis_alloc_event {
	struct cis_event base;
	__u64 cache, resource, task_start, gfp, requested, count;
	__u32 operation, stage, ordinal, sample_shift;
	__s32 requested_node, observed_node;
};
struct cis_alloc_live_key { __u64 cache, object; };
struct cis_alloc_live { struct cis_event allocation; __u64 task_start; };
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
struct cis_object_key { __u64 object; __u32 kind, reserved; };
struct cis_watch { __u64 id, generation, start_ns, deadline_ns, epoch, events; };
struct cis_owner_record { __u64 id, generation, tid, task_start, acquired_ns, epoch; };
struct cis_owner_task { struct cis_object_key key; __u64 task_start, epoch; };
#endif
