/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_EVENT_H
#define CIS_EVENT_H
#define CIS_RING_BYTES (1U << 20)
#define CIS_INFLIGHT 1024
#define CIS_STACKS 256
#define CIS_STACK_DEPTH 64
#define CIS_DIAG_SCHED 1
#define CIS_DIAG_LOCK 2
#define CIS_DIAG_RECLAIM 4
struct cis_identity { __u64 id, generation; };
struct cis_target { __u64 generation, deadline_ns; __u32 kind, reserved; };
enum cis_event_type { CIS_IP=1, CIS_SCHED_WAIT, CIS_LOCK_WAIT, CIS_RECLAIM, CIS_UNFINISHED };
struct cis_event {
	__u64 time_ns, id, generation, tid, object, duration_ns, ip, weight;
	__u32 type, cpu, flags;
	__s32 stack_id;
	__u32 nesting, reserved;
};
struct cis_pending_key { __u64 tid, object; __u32 type, reserved; };
struct cis_bpf_stats { __u64 received, emitted, lost, unknown, overdepth, unmatched, nested, rejected, expired; };
#endif
