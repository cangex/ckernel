/* SPDX-License-Identifier: GPL-2.0 */
SEC("raw_tp/cis_rwsem_state")
int rwsem_state(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_bpf_stats *s = statistics();
	struct cis_rwsem_event e = {};
	struct cis_watch *watch;
	struct cis_identity actor = {};
	struct task_struct *task = (void *)bpf_get_current_task();
	__u64 object = ctx->args[0], now = bpf_ktime_get_ns();
	__u32 phase = ctx->args[1];

	COUNT(s, received);
	if (!object || phase < 1 || phase > 16 || !synchronous_context()) return 0;
	watch = bpf_map_lookup_elem(&rwsem_watched, &object);
	if (!watch) {
		struct cis_watch initial = {};
		struct cis_target *target;
		if (phase != 1 && phase != 2 && phase != 3 && phase != 14 && phase != 15) return 0;
		if (!identity(task, &actor) || !allowed(&actor, CIS_DIAG_RWSEM, now)) return 0;
		target = bpf_map_lookup_elem(&targets, &actor.id);
		if (!target) return 0;
		initial.id = actor.id; initial.generation = actor.generation;
		initial.start_ns = now; initial.deadline_ns = target->deadline_ns;
		initial.epoch = phase == 1 ? now : 0;
		if (bpf_map_update_elem(&rwsem_watched, &object, &initial, BPF_NOEXIST)) {
			COUNT(s, owner_watch_failed); return 0;
		}
		watch = bpf_map_lookup_elem(&rwsem_watched, &object);
		if (!watch) return 0;
	}
	if (now < watch->start_ns || now >= watch->deadline_ns) return 0;
	/* Objects are never evicted/rebound to conceal capacity or address reuse. */
	if (__sync_fetch_and_add(&watch->events, 1) >= 1024) {
		COUNT(s, owner_attempt_failed); return 0;
	}
	if (phase == 1) watch->epoch = now;
	if (!actor.id) identity(task, &actor);
	e.base.type = CIS_RWSEM_EVENT; e.base.time_ns = now;
	e.base.object = object; e.base.sequence_ns = watch->epoch;
	e.base.id = watch->id; e.base.generation = watch->generation;
	e.base.tid = bpf_get_current_pid_tgid();
	e.base.cpu = bpf_get_smp_processor_id(); e.base.stack_id = -1;
	e.actor_id = actor.id; e.actor_generation = actor.generation;
	e.actor_start = BPF_CORE_READ(task, start_boottime);
	e.phase = phase; e.skipped = ctx->args[2];
	if (phase == 2 || phase == 3 || phase == 14 || phase == 15)
		e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}
