/* SPDX-License-Identifier: GPL-2.0 */
static __always_inline void tx_emit(void *ctx, struct cis_net_tx_event *e)
{
	struct cis_bpf_stats *s = statistics();
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e))) COUNT(s, lost);
	else COUNT(s, emitted);
}

SEC("raw_tp/cis_net_tx")
int net_tx(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_net_tx_sample *sample = (void *)ctx->args[0];
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_net_tx_event e = {}, *saved;
	struct cis_maple_key key = {};
	struct cis_identity id = {};
	struct cis_bpf_stats *s = statistics();
	u64 now = BPF_CORE_READ(sample, time_ns), skb = (u64)BPF_CORE_READ(sample, skb);
	u64 start = BPF_CORE_READ(sample, start_ns);
	u32 phase = BPF_CORE_READ(sample, phase);
	COUNT(s, received);
	if (!synchronous_context()) return 0;
	key.tid = bpf_get_current_pid_tgid();
	key.task_start = BPF_CORE_READ(task, start_boottime);
	if (phase == 6) {
		if (!identity(task, &id) || !allowed(&id, CIS_DIAG_NET, start) ||
		    !allowed(&id, CIS_DIAG_NET, now)) return 0;
		e.base.id = id.id; e.base.generation = id.generation;
		e.base.type = CIS_NET_TX_EVENT; e.base.sequence_ns = start;
		e.base.time_ns = now;
		e.base.tid = key.tid; e.task_start = key.task_start;
		e.cookie = BPF_CORE_READ(sample, cookie);
		e.socket = (u64)BPF_CORE_READ(sample, sk);
		e.gfp = BPF_CORE_READ(sample, gfp); e.requested = BPF_CORE_READ(sample, requested);
		e.netns = BPF_CORE_READ(sample, netns);
		e.phase = 6;
		if (!e.cookie || !start || now != start || skb) { COUNT(s, rejected); return 0; }
		if (bpf_map_lookup_elem(&net_tx_pending, &key)) {
			bpf_map_delete_elem(&net_tx_pending, &key); COUNT(s, nested); return 0;
		}
		if (bpf_map_update_elem(&net_tx_pending, &key, &e, BPF_NOEXIST)) COUNT(s, rejected);
		return 0;
	} else if (phase == 1 || phase == 4) {
		saved = bpf_map_lookup_elem(&net_tx_pending, &key);
		if (!saved) return 0; /* Begin may belong to a non-target task. */
		e = *saved;
		bpf_map_delete_elem(&net_tx_pending, &key);
		if (e.phase != 6 || e.base.sequence_ns != start || e.cookie != BPF_CORE_READ(sample, cookie) ||
		    (phase == 1 && !skb) || (phase == 4 && skb)) { COUNT(s, rejected); return 0; }
		if (!same_window(&e.base, CIS_DIAG_NET, now)) { COUNT(s, expired); return 0; }
		e.base.object = skb; e.phase = phase;
		e.backend_ns = BPF_CORE_READ(sample, backend_ns);
		e.base.duration_ns = BPF_CORE_READ(sample, alloc_ns);
		if (e.backend_ns != now || e.base.duration_ns < start || now < e.base.duration_ns) { COUNT(s, rejected); return 0; }
		if (phase == 1) {
			if (bpf_map_update_elem(&net_tx_pending, &key, &e, BPF_NOEXIST)) { COUNT(s, rejected); return 0; }
			if (bpf_map_update_elem(&net_tx_live, &skb, &e, BPF_NOEXIST)) {
				/* A stale live address cannot be associated with its new use. */
				bpf_map_delete_elem(&net_tx_live, &skb);
				bpf_map_delete_elem(&net_tx_pending, &key); COUNT(s, rejected); return 0;
			}
		}
	} else if (phase == 2 || phase == 3) {
		saved = bpf_map_lookup_elem(&net_tx_pending, &key);
		if (!saved) return 0;
		e = *saved;
		bpf_map_delete_elem(&net_tx_pending, &key);
		if (e.phase != 1 || e.base.sequence_ns != start || e.base.object != skb ||
		    e.cookie != BPF_CORE_READ(sample, cookie) ||
		    e.backend_ns != BPF_CORE_READ(sample, backend_ns) ||
		    e.base.duration_ns != BPF_CORE_READ(sample, alloc_ns)) { COUNT(s, rejected); return 0; }
		if (!same_window(&e.base, CIS_DIAG_NET, now)) { COUNT(s, expired); return 0; }
	} else { COUNT(s, rejected); return 0; }
	e.base.time_ns = now; e.phase = phase;
	e.base.cpu = bpf_get_smp_processor_id();
	e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	e.actor_id = e.base.id; e.actor_generation = e.base.generation;
	e.actor_tid = key.tid; e.actor_start = key.task_start;
	tx_emit(ctx, &e);
	return 0;
}

static __noinline void net_tx_release(void *ctx, struct cis_net_sample *sample)
{
	u64 skb = (u64)BPF_CORE_READ(sample, skb), now = BPF_CORE_READ(sample, time_ns);
	struct cis_net_tx_event *saved, e;
	struct cis_bpf_stats *s = statistics();
	struct task_struct *task = (void *)bpf_get_current_task();
	struct cis_identity id = {};
	struct cis_net_free_key key = { .skb = skb };
	u32 phase = BPF_CORE_READ(sample, phase);

	if (phase == 12) {
		key.release_ns = BPF_CORE_READ(sample, release_start_ns);
		saved = bpf_map_lookup_elem(&net_tx_free, &key);
		if (!saved) return;
		e = *saved;
		bpf_map_delete_elem(&net_tx_free, &key);
		if (!same_window(&e.base, CIS_DIAG_NET, now)) { COUNT(s, expired); return; }
		e.phase = 7; e.base.time_ns = now;
		e.release_backend_ns = BPF_CORE_READ(sample, release_backend_ns);
		e.release_flags = BPF_CORE_READ(sample, flags);
		if (e.release_backend_ns < key.release_ns || now < e.release_backend_ns ||
		    BPF_CORE_READ(sample, context) != e.base.flags) { COUNT(s, rejected); return; }
		tx_emit(ctx, &e);
		return;
	}
	if (phase != 9) { COUNT(s, rejected); return; }

	saved = bpf_map_lookup_elem(&net_tx_live, &skb);
	if (!saved) return;
	e = *saved;
	bpf_map_delete_elem(&net_tx_live, &skb);
	if (!same_window(&e.base, CIS_DIAG_NET, now)) { COUNT(s, expired); return; }
	e.phase = 5; e.base.time_ns = now;
	e.release_ns = now;
	e.release_flags = BPF_CORE_READ(sample, flags);
	e.base.cpu = bpf_get_smp_processor_id();
	e.base.flags = BPF_CORE_READ(sample, context);
	e.base.stack_id = bpf_get_stackid(ctx, &stacks, 0);
	e.actor_id = 0; e.actor_generation = 0; e.actor_tid = 0; e.actor_start = 0;
	if (!e.base.flags) {
		e.actor_tid = bpf_get_current_pid_tgid();
		e.actor_start = BPF_CORE_READ(task, start_boottime);
		if (identity(task, &id)) { e.actor_id = id.id; e.actor_generation = id.generation; }
	}
	if (e.release_flags & 1) {
		key.release_ns = now;
		if (BPF_CORE_READ(sample, release_start_ns) != now ||
		    bpf_map_update_elem(&net_tx_free, &key, &e, BPF_NOEXIST)) {
			COUNT(s, rejected); return;
		}
	}
	tx_emit(ctx, &e);
}
