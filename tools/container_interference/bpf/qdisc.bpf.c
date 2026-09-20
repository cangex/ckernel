// SPDX-License-Identifier: GPL-2.0
#define CIS_PROFILE 16
#include "cis.bpf.c"

_Static_assert(sizeof(struct cis_qdisc_data) == sizeof(struct cis_qdisc_sample), "frozen queue sample ABI");
_Static_assert(__builtin_offsetof(struct cis_qdisc_data, result) ==
	       __builtin_offsetof(struct cis_qdisc_sample, result), "queue sample layout");

SEC("raw_tp/cis_qdisc_state")
int qdisc_state(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_qdisc_event e = {};
	struct cis_bpf_stats *stats = statistics();
	struct session_window *window;
	struct cis_identity id = {}, *socket_id;
	struct task_struct *task = (void *)bpf_get_current_task();
	__u32 zero = 0;

	COUNT(stats, received);
	if (bpf_probe_read_kernel(&e.sample, sizeof(e.sample), (void *)ctx->args[0])) {
		COUNT(stats, rejected); return 0;
	}
	window = bpf_map_lookup_elem(&session_window, &zero);
	if (!window || !window->session_id || e.sample.begin_ns < window->start_ns ||
	    e.sample.end_ns >= window->end_ns || e.sample.end_ns < e.sample.begin_ns) {
		COUNT(stats, expired); return 0;
	}
	if (!e.sample.lease || !e.sample.qdisc || e.sample.sample_shift != 4 ||
	    e.sample.operation < 1 || e.sample.operation > 2 || e.sample.context > 1) {
		COUNT(stats, rejected); return 0;
	}
	/* Resource-selected records include unknown/host participants. Base id is
	 * deliberately zero, never the selected victim's id as a stand-in owner. */
	e.base.type = CIS_QDISC_EVENT; e.base.time_ns = e.sample.end_ns;
	e.base.sequence_ns = e.sample.begin_ns; e.base.object = e.sample.qdisc;
	e.base.cpu = bpf_get_smp_processor_id(); e.base.stack_id = -1;
	if (!e.sample.context && synchronous_context() && e.sample.actor_cgroup &&
	    e.sample.actor_cgroup == BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id)) {
		e.base.tid = bpf_get_current_pid_tgid(); e.task_start = BPF_CORE_READ(task, start_boottime);
		if (identity(task, &id)) { e.actor_id = id.id; e.actor_generation = id.generation; }
	}
	/* Only exact registered-root socket accounting is resolved in v1.
	 * Descendant/retired socket cgroups remain raw IDs plus unknown, not current. */
	socket_id = bpf_map_lookup_elem(&roots, &e.sample.socket_cgroup);
	if (socket_id) { e.socket_id = socket_id->id; e.socket_generation = socket_id->generation; }
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(stats, lost);
	else COUNT(stats, emitted);
	return 0;
}
