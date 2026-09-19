// SPDX-License-Identifier: GPL-2.0
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,256);
	__type(key,struct cis_maple_key); __type(value,struct cis_maple_event);
} maple_pending SEC(".maps");

SEC("raw_tp/cis_maple_alloc")
int maple_context(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_maple_sample *sample = (void *)ctx->args[0];
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_maple_key key = { .tid = bpf_get_current_pid_tgid(),
		.task_start = BPF_CORE_READ(task, start_boottime) };
	struct cis_identity id = {};
	struct cis_maple_event e = {}, *saved;
	struct cis_bpf_stats *s = statistics();
	u64 now = BPF_CORE_READ(sample, time_ns);
	u32 phase = BPF_CORE_READ(sample, phase);

	COUNT(s, received);
	if (!synchronous_context()) return 0;
	if (phase == 1) {
		/* Drop both contexts on nesting; do not later pair the outer end
		 * with an inner allocation after an overwrite. */
		if (bpf_map_lookup_elem(&maple_pending, &key)) {
			bpf_map_delete_elem(&maple_pending, &key); COUNT(s, nested); return 0;
		}
		if (!identity(task, &id) || !allowed(&id, CIS_DIAG_ALLOCATOR, now)) return 0;
		e.base.time_ns = now; e.base.sequence_ns = BPF_CORE_READ(sample, begin_ns);
		e.base.id = id.id; e.base.generation = id.generation; e.base.tid = key.tid;
		e.task_start = key.task_start; e.base.object = (u64)BPF_CORE_READ(sample, tree);
		e.base.type = CIS_MAPLE_EVENT; e.cache = (u64)BPF_CORE_READ(sample, cache);
		e.gfp = BPF_CORE_READ(sample, gfp); e.requested = BPF_CORE_READ(sample, requested);
		e.operation = BPF_CORE_READ(sample, operation);
		if (bpf_map_update_elem(&maple_pending, &key, &e, BPF_NOEXIST)) COUNT(s, rejected);
		return 0;
	}
	saved = bpf_map_lookup_elem(&maple_pending, &key);
	if (!saved) return 0;
	e = *saved; bpf_map_delete_elem(&maple_pending, &key);
	/* A real allocation may finish after the window. Retire its context and
	 * expose truncation, rather than calling an expected boundary corruption. */
	if (!same_window(&e.base, CIS_DIAG_ALLOCATOR, now)) {
		COUNT(s, expired); return 0;
	}
	if (phase != 2 ||
	    e.base.sequence_ns != BPF_CORE_READ(sample, begin_ns) ||
	    e.base.object != (u64)BPF_CORE_READ(sample, tree) ||
	    e.cache != (u64)BPF_CORE_READ(sample, cache) ||
	    e.gfp != BPF_CORE_READ(sample, gfp) || e.requested != BPF_CORE_READ(sample, requested) ||
	    e.operation != BPF_CORE_READ(sample, operation)) { COUNT(s, rejected); return 0; }
	/* Unsampled allocation calls deliberately have no backend episode. */
	if (!e.base.weight) return 0;
	e.base.time_ns = now; e.base.cpu = bpf_get_smp_processor_id();
	e.count = BPF_CORE_READ(sample, count);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}

static __always_inline void maple_backend(struct cis_alloc_event *e)
{
	struct cis_maple_key key = { .tid = e->base.tid, .task_start = e->task_start };
	struct cis_maple_event *saved = bpf_map_lookup_elem(&maple_pending, &key);
	struct cis_bpf_stats *s = statistics();
	if (!saved) return;
	if (saved->base.weight || saved->cache != e->cache || saved->gfp != e->gfp ||
	    saved->requested != e->requested || saved->operation != e->operation ||
	    saved->base.id != e->base.id || saved->base.generation != e->base.generation ||
	    e->base.sequence_ns <= saved->base.sequence_ns) {
		bpf_map_delete_elem(&maple_pending, &key); COUNT(s, rejected); return;
	}
	saved->base.weight = e->base.sequence_ns;
}
