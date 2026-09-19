/* SPDX-License-Identifier: GPL-2.0 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct tag_key);
	__type(value, struct cis_writeback_event);
} wb_pending SEC(".maps");

static __always_inline void wb_inode(struct cis_writeback_event *e, struct inode *inode)
{
	e->base.object = (__u64)inode;
	e->base.ip = BPF_CORE_READ(inode, i_ino);
	e->base.flags = BPF_CORE_READ(inode, i_generation);
	e->base.nesting = BPF_CORE_READ(inode, i_sb, s_dev);
}

static __noinline void wb_origin(struct writeback_control *wbc, struct cis_writeback_event *e)
{
	struct kernfs_node *kn = BPF_CORE_READ(wbc, wb, memcg_css, cgroup, kn);
	e->memcg = BPF_CORE_READ(kn, id);
#pragma clang loop unroll(disable)
	for (int i = 0; i < 32; i++) {
		struct cis_identity *origin;
		__u64 cg;
		if (!kn) break;
		cg = BPF_CORE_READ(kn, id); origin = bpf_map_lookup_elem(&roots, &cg);
		if (origin) {
			e->wb_owner_id = origin->id; e->wb_owner_generation = origin->generation;
			break;
		}
		kn = BPF_CORE_READ(kn, parent);
	}
}

SEC("raw_tp/writeback_dirty_folio")
int wb_dirty(struct bpf_raw_tracepoint_args *ctx)
{
	struct cis_writeback_event e = {};
	struct cis_bpf_stats *s = statistics();
	struct cis_identity id = {};
	struct task_struct *task = (void *)bpf_get_current_task();
	struct address_space *mapping = (void *)ctx->args[1];
	struct folio *folio = (void *)ctx->args[0];
	struct inode *inode;
	__u64 now = bpf_ktime_get_ns();
	COUNT(s, received);
	if (BPF_CORE_READ(task, thread_info.preempt_count) & 0x00ff0100U) return 0;
	if (!identity(task, &id) || !allowed(&id, CIS_DIAG_BLOCK, now)) return 0;
	inode = BPF_CORE_READ(mapping, host);
	if (!inode) { COUNT(s, rejected); return 0; }
	e.base.id = id.id; e.base.generation = id.generation;
	e.actor_id = id.id; e.actor_generation = id.generation;
	e.base.tid = bpf_get_current_pid_tgid(); e.task_start = BPF_CORE_READ(task, start_boottime);
	e.base.time_ns = now; e.base.sequence_ns = now;
	e.base.type = CIS_WRITEBACK_EVENT; e.base.reserved = 1;
	e.base.weight = BPF_CORE_READ(folio, index); wb_inode(&e, inode);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}

static __always_inline int wb_event(void *ctx, struct inode *inode,
				   struct writeback_control *wbc, __u32 phase)
{
	struct cis_writeback_event e = {}, *saved;
	struct cis_bpf_stats *s = statistics();
	struct cis_identity id = {}, executor = {};
	struct task_struct *task = (void *)bpf_get_current_task();
	struct tag_key key = { bpf_get_current_pid_tgid(), BPF_CORE_READ(task, start_boottime) };
	__u64 now = bpf_ktime_get_ns();
	COUNT(s, received);
	if (!inode || !wbc || (BPF_CORE_READ(task, thread_info.preempt_count) & 0x00ff0100U)) return 0;
	if (phase == 2) {
		/* Recursion invalidates the outer context too, rather than attributing
		 * a nested request to an unrelated outer inode. */
		if (bpf_map_lookup_elem(&wb_pending, &key)) {
			bpf_map_delete_elem(&wb_pending, &key); COUNT(s, nested); return 0;
		}
		identity(task, &executor); wb_origin(wbc, &e); id = executor;
		if (!allowed(&id, CIS_DIAG_BLOCK, now)) {
			id.id = e.wb_owner_id; id.generation = e.wb_owner_generation;
			if (!id.id || !allowed(&id, CIS_DIAG_BLOCK, now)) return 0;
		}
		e.base.id = id.id; e.base.generation = id.generation;
		e.actor_id = executor.id; e.actor_generation = executor.generation;
		e.base.tid = key.tid; e.task_start = key.start;
		e.base.sequence_ns = now; e.wbc = (__u64)wbc; wb_inode(&e, inode);
	} else {
		saved = bpf_map_lookup_elem(&wb_pending, &key);
		if (!saved) { COUNT(s, unmatched); return 0; }
		e = *saved; bpf_map_delete_elem(&wb_pending, &key);
		if (!same_window(&e.base, CIS_DIAG_BLOCK, now)) { COUNT(s, expired); return 0; }
		if (e.base.object != (__u64)inode || e.wbc != (__u64)wbc) { COUNT(s, rejected); return 0; }
	}
	e.base.type = CIS_WRITEBACK_EVENT; e.base.reserved = phase; e.base.time_ns = now;
	e.request = 0; e.request_episode = 0;
	if (phase == 2 && bpf_map_update_elem(&wb_pending, &key, &e, BPF_NOEXIST)) {
		COUNT(s, rejected); return 0;
	}
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e))) COUNT(s, lost);
	else COUNT(s, emitted);
	return 0;
}

SEC("raw_tp/writeback_single_inode_start")
int wb_begin(struct bpf_raw_tracepoint_args *ctx)
{ return wb_event(ctx, (void *)ctx->args[0], (void *)ctx->args[1], 2); }
SEC("raw_tp/writeback_single_inode")
int wb_end(struct bpf_raw_tracepoint_args *ctx)
{ return wb_event(ctx, (void *)ctx->args[0], (void *)ctx->args[1], 3); }

static __noinline void wb_request(void *ctx, const struct cis_block_event *request)
{
	struct tag_key key = { request->base.tid, request->submitter_start };
	struct cis_writeback_event *e = bpf_map_lookup_elem(&wb_pending, &key);
	struct cis_bpf_stats *s = statistics();
	if (!e || !same_window(&e->base, CIS_DIAG_BLOCK, request->base.time_ns)) return;
	/* Same synchronous task context only. Mutate the map record to avoid an
	 * extra event-sized BPF stack frame; the immutable episode is retained. */
	e->base.time_ns = request->base.time_ns; e->base.reserved = 4;
	e->request = request->base.object; e->request_episode = request->base.sequence_ns;
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e))) COUNT(s, lost);
	else COUNT(s, emitted);
}
