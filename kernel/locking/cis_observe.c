// SPDX-License-Identifier: GPL-2.0
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/user_namespace.h>
#include <linux/bitmap.h>
#include <linux/hash.h>
#include <linux/page_counter.h>
#include <linux/ktime.h>
#ifdef CONFIG_CIS_OBSERVE_NET
#include <linux/sock_diag.h>
#endif
#define CREATE_TRACE_POINTS
#include <linux/cis_observe.h>
#undef CREATE_TRACE_POINTS
#include <linux/cis_rwsem.h>
#include <linux/cis_slub.h>

static DEFINE_PER_CPU(bool, cis_in_trace);
static DEFINE_PER_CPU(unsigned long, cis_skipped);
static DEFINE_PER_CPU(unsigned long, cis_gate_filtered);
static DEFINE_PER_CPU(unsigned long, cis_rwsem_entries);
static DEFINE_PER_CPU(unsigned long, cis_rwsem_filtered);

static int cis_rwsem_audit_show(struct seq_file *m, void *unused)
{
	int cpu;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_puts(m, "version=1\n");
	for_each_possible_cpu(cpu)
		seq_printf(m, "cpu=%d entries=%lu filtered=%lu\n", cpu,
			READ_ONCE(per_cpu(cis_rwsem_entries, cpu)),
			READ_ONCE(per_cpu(cis_rwsem_filtered, cpu)));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_rwsem_audit);

#ifdef CONFIG_BLOCK
DECLARE_TRACEPOINT(block_io_start);
DECLARE_TRACEPOINT(block_rq_insert);
DECLARE_TRACEPOINT(block_rq_issue);
DECLARE_TRACEPOINT(block_rq_requeue);
DECLARE_TRACEPOINT(block_rq_complete);
DECLARE_TRACEPOINT(block_rq_merge);
DECLARE_TRACEPOINT(block_rq_remap);
DECLARE_TRACEPOINT(block_tag_wait);
DECLARE_TRACEPOINT(block_merge_link);
DECLARE_TRACEPOINT(writeback_dirty_folio);
DECLARE_TRACEPOINT(writeback_single_inode_start);
DECLARE_TRACEPOINT(writeback_single_inode);
#define CIS_BLOCK_ON(name) tracepoint_enabled(name)
#else
#define CIS_BLOCK_ON(name) 0
#endif

static bool cis_block_active(void)
{
	return CIS_BLOCK_ON(block_io_start) || CIS_BLOCK_ON(block_rq_insert) ||
	       CIS_BLOCK_ON(block_rq_issue) || CIS_BLOCK_ON(block_rq_requeue) ||
	       CIS_BLOCK_ON(block_rq_complete) || CIS_BLOCK_ON(block_rq_merge) ||
	       CIS_BLOCK_ON(block_rq_remap) || CIS_BLOCK_ON(block_tag_wait) ||
	       CIS_BLOCK_ON(block_merge_link) || CIS_BLOCK_ON(writeback_dirty_folio) ||
	       CIS_BLOCK_ON(writeback_single_inode_start) || CIS_BLOCK_ON(writeback_single_inode);
}

/* Monotone one-bit membership: collisions only admit extra events. No deletes
 * while any probe is registered; another container's holder is never filtered
 * by its identity. BPF owner watches are created only by WAIT events. */
#define CIS_GATE_BITS 16
static unsigned long cis_waited[3][BITS_TO_LONGS(1U << CIS_GATE_BITS)];
static bool wait_gate;
module_param(wait_gate, bool, 0400);
MODULE_PARM_DESC(wait_gate, "Admit WAIT and all subsequent events for possibly waited objects");

int cis_observe_register(void)
{
	/* tracepoints_mutex serializes first-probe registration before enable.
	 * An old in-flight callback may only add false positives after this clear;
	 * tracepoint core synchronizes that generation before publishing new probes. */
	bitmap_zero(cis_waited[0], 1U << CIS_GATE_BITS);
	return 0;
}

void cis_observe_unregister(void)
{
	/* Do not clear while last-generation readers may still be returning. */
}

int cis_fd_observe_register(void)
{
	bitmap_zero(cis_waited[1], 1U << CIS_GATE_BITS);
	return 0;
}

void cis_fd_observe_unregister(void) { }

int cis_slub_observe_register(void)
{
	bitmap_zero(cis_waited[2], 1U << CIS_GATE_BITS);
	return 0;
}

void cis_slub_observe_unregister(void) { }

static bool cis_trace_active(void)
{
	return trace_cis_lock_state_enabled() || trace_cis_fdlock_state_enabled() ||
	       trace_cis_counter_step_enabled() || trace_cis_alloc_step_enabled() ||
	       trace_cis_alloc_release_enabled() || trace_cis_maple_alloc_enabled() || trace_cis_net_state_enabled() ||
	       trace_cis_net_skb_release_enabled() || trace_cis_net_tx_enabled() || trace_cis_rwsem_state_enabled() ||
	       trace_cis_slublock_state_enabled() || cis_block_active();
}

static bool cis_gate_allows(void *object, unsigned int kind, unsigned int phase)
{
	unsigned int bit = hash_long(((unsigned long)object >> 3) ^ kind, CIS_GATE_BITS);
	unsigned long *gate = cis_waited[kind == CIS_SLUBLOCK ? 2 : kind == CIS_FDLOCK];

	if (phase == CIS_WAIT) {
		if (!test_bit(bit, gate)) {
			set_bit(bit, gate);
			smp_mb__after_atomic();
		}
		return true;
	}
	return test_bit(bit, gate);
}

#define CIS_DIAG_SAMPLES 8
#define CIS_DIAG_PHASES 13
struct cis_recursion_sample {
	unsigned long object, outer_object, caller, count;
	unsigned int kind, phase, outer_kind, outer_phase, preempt_count;
};
struct cis_recursion_diag {
	unsigned long sync_skipped, irq_skipped;
	u64 slub_irqoff_calls, slub_irqoff_ns, slub_irqoff_max_ns;
	unsigned long by_phase[CIS_RESOURCE_END][CIS_DIAG_PHASES];
	void *outer_object;
	unsigned int outer_kind, outer_phase;
	struct cis_recursion_sample samples[CIS_DIAG_SAMPLES];
};
static DEFINE_PER_CPU(struct cis_recursion_diag, cis_recursion_diag);
/* Dedicated-VM diagnosis only. No allocations, output or stack walks in a hook. */
static bool diag;
module_param(diag, bool, 0400);
MODULE_PARM_DESC(diag, "Enable bounded CIS recursion diagnosis; not a performance mode");

static void cis_note_recursion(void *object, unsigned int kind,
		unsigned int phase, unsigned long caller)
{
	struct cis_recursion_diag *d = this_cpu_ptr(&cis_recursion_diag);
	unsigned long count = this_cpu_read(cis_skipped);
	struct cis_recursion_sample *s = &d->samples[(count - 1) % CIS_DIAG_SAMPLES];

	if (in_interrupt())
		d->irq_skipped++;
	else
		d->sync_skipped++;
	if (kind < CIS_RESOURCE_END && phase < CIS_DIAG_PHASES)
		d->by_phase[kind][phase]++;
	s->object = (unsigned long)object;
	s->outer_object = (unsigned long)d->outer_object;
	s->caller = caller;
	s->kind = kind; s->phase = phase;
	s->outer_kind = d->outer_kind; s->outer_phase = d->outer_phase;
	s->preempt_count = preempt_count();
	s->count = count;
}

static int cis_diag_show(struct seq_file *m, void *unused)
{
	int cpu, kind, phase, i;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (cis_trace_active())
		return -EBUSY;
	/* Last-link close only unregisters callbacks in this OLK. Complete the
	 * grace periods before userspace consumes terminal BPF/source counters.
	 * This is control-plane work, never part of a lock callback. */
	tracepoint_synchronize_unregister();
	if (cis_trace_active())
		return -EBUSY;
	seq_printf(m, "version=3 enabled=%u trace_active=%u synchronized=1 bytes_per_possible_cpu=%zu snapshot=non_atomic wait_gate=%u gate_bytes=%zu\n",
		   diag, cis_trace_active(), sizeof(struct cis_recursion_diag),
		   wait_gate, sizeof(cis_waited));
	for_each_possible_cpu(cpu) {
		struct cis_recursion_diag *d = per_cpu_ptr(&cis_recursion_diag, cpu);
		seq_printf(m, "cpu=%d skipped=%lu sync=%lu irq=%lu filtered=%lu\n", cpu,
			   per_cpu(cis_skipped, cpu), READ_ONCE(d->sync_skipped), READ_ONCE(d->irq_skipped),
			   per_cpu(cis_gate_filtered, cpu));
		seq_printf(m, "slub_irqoff cpu=%d calls=%llu body_ns=%llu max_body_ns=%llu debug_only=1\n",
			   cpu, READ_ONCE(d->slub_irqoff_calls), READ_ONCE(d->slub_irqoff_ns),
			   READ_ONCE(d->slub_irqoff_max_ns));
		for (kind = 0; kind < CIS_RESOURCE_END; kind++)
			for (phase = 0; phase < CIS_DIAG_PHASES; phase++)
				if (READ_ONCE(d->by_phase[kind][phase]))
					seq_printf(m, "phase cpu=%d kind=%d phase=%d count=%lu\n",
						   cpu, kind, phase, READ_ONCE(d->by_phase[kind][phase]));
		for (i = 0; i < CIS_DIAG_SAMPLES; i++) {
			struct cis_recursion_sample s = d->samples[i];
			if (s.count)
				seq_printf(m, "sample cpu=%d count=%lu object=%lx outer=%lx caller=%lx kind=%u phase=%u outer_kind=%u outer_phase=%u preempt=%x\n",
					   cpu, s.count, s.object, s.outer_object, s.caller, s.kind,
					   s.phase, s.outer_kind, s.outer_phase, s.preempt_count);
		}
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_diag);

static int cis_sources_show(struct seq_file *m, void *unused)
{
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	/* Control-plane point observations, not an atomic session acknowledgement. */
	seq_printf(m, "version=14 owner=%u fd=%u counter=%u allocator=%u allocator_release=%u net=%u net_release=%u block_start=%u block_insert=%u block_issue=%u block_requeue=%u block_complete=%u block_merge=%u block_remap=%u rwsem=%u slub=%u block_tag=%u rwsem_filter=%u block_link=%u wb_dirty=%u wb_begin=%u wb_end=%u maple=%u net_tx=%u\n",
		   trace_cis_lock_state_enabled(), trace_cis_fdlock_state_enabled(),
		   trace_cis_counter_step_enabled(), trace_cis_alloc_step_enabled(),
		   trace_cis_alloc_release_enabled(), trace_cis_net_state_enabled(),
		   trace_cis_net_skb_release_enabled(), CIS_BLOCK_ON(block_io_start),
		   CIS_BLOCK_ON(block_rq_insert), CIS_BLOCK_ON(block_rq_issue),
		   CIS_BLOCK_ON(block_rq_requeue), CIS_BLOCK_ON(block_rq_complete),
		   CIS_BLOCK_ON(block_rq_merge), CIS_BLOCK_ON(block_rq_remap),
		   trace_cis_rwsem_state_enabled(), trace_cis_slublock_state_enabled(),
		   CIS_BLOCK_ON(block_tag_wait), cis_rwsem_filter_active(),
		   CIS_BLOCK_ON(block_merge_link), CIS_BLOCK_ON(writeback_dirty_folio),
		   CIS_BLOCK_ON(writeback_single_inode_start), CIS_BLOCK_ON(writeback_single_inode),
		   trace_cis_maple_alloc_enabled(), trace_cis_net_tx_enabled());
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_sources);

#ifdef CONFIG_CIS_OBSERVE_COUNTER
static const struct file_operations cis_counter_audit_fops;
#endif
#ifdef CONFIG_CIS_OBSERVE_ALLOC
static const struct file_operations cis_alloc_audit_fops;
#endif
#ifdef CONFIG_CIS_OBSERVE_NET
static const struct file_operations cis_net_audit_fops;
#endif

static int __init cis_diag_init(void)
{
	debugfs_create_file("cis_recursion", 0400, NULL, NULL, &cis_diag_fops);
	debugfs_create_file("cis_sources", 0400, NULL, NULL, &cis_sources_fops);
	debugfs_create_file("cis_rwsem_audit", 0400, NULL, NULL, &cis_rwsem_audit_fops);
#ifdef CONFIG_CIS_OBSERVE_COUNTER
	debugfs_create_file("cis_counter_audit", 0400, NULL, NULL, &cis_counter_audit_fops);
#endif
#ifdef CONFIG_CIS_OBSERVE_ALLOC
	debugfs_create_file("cis_alloc_audit", 0400, NULL, NULL, &cis_alloc_audit_fops);
#endif
#ifdef CONFIG_CIS_OBSERVE_NET
	debugfs_create_file("cis_net_audit", 0400, NULL, NULL, &cis_net_audit_fops);
#endif
	return 0;
}
late_initcall(cis_diag_init);

/* Acquired/release callbacks bracket a conservative interior hold interval.
 * They do not read rwsem->owner (which is not a reader membership list). */
void __cis_rwsem_event(void *object, unsigned int phase)
{
	preempt_disable_notrace();
	this_cpu_inc(cis_rwsem_entries);
	if (!cis_rwsem_filter_allows(object)) {
		this_cpu_inc(cis_rwsem_filtered);
		preempt_enable_notrace();
		return;
	}
	if (this_cpu_read(cis_in_trace) || in_interrupt()) {
		this_cpu_inc(cis_skipped);
		preempt_enable_notrace();
		return;
	}
	this_cpu_write(cis_in_trace, true);
	trace_cis_rwsem_state(object, phase, this_cpu_read(cis_skipped));
	this_cpu_write(cis_in_trace, false);
	preempt_enable_notrace();
}

void __cis_lock_event(void *object, unsigned int kind, unsigned int phase,
		struct task_struct *owner, unsigned long flags)
{
	preempt_disable();
	if (wait_gate && !cis_gate_allows(object, kind, phase)) {
		this_cpu_inc(cis_gate_filtered);
		preempt_enable();
		return;
	}
	if (this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_skipped);
		if (diag)
			cis_note_recursion(object, kind, phase, _RET_IP_);
		preempt_enable();
		return;
	}
	this_cpu_write(cis_in_trace, true);
	if (diag) {
		struct cis_recursion_diag *d = this_cpu_ptr(&cis_recursion_diag);
		d->outer_object = object;
		d->outer_kind = kind;
		d->outer_phase = phase;
	}
	if (kind == CIS_SLUBLOCK)
		trace_cis_slublock_state(object, kind, phase, owner, flags, this_cpu_read(cis_skipped));
	else if (kind == CIS_FDLOCK)
		trace_cis_fdlock_state(object, kind, phase, owner, flags, this_cpu_read(cis_skipped));
	else
		trace_cis_lock_state(object, kind, phase, owner, flags, this_cpu_read(cis_skipped));
	this_cpu_write(cis_in_trace, false);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(__cis_lock_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_lock_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_fdlock_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_slublock_state);

#ifdef CONFIG_CIS_OBSERVE_COUNTER
static unsigned int counter_shift = 6;
module_param(counter_shift, uint, 0400);
MODULE_PARM_DESC(counter_shift, "Sample one in 2^shift page-counter calls per CPU (clamped to 16)");
static DEFINE_PER_CPU(unsigned long, cis_counter_calls);
static DEFINE_PER_CPU(unsigned long, cis_counter_entries);
static DEFINE_PER_CPU(unsigned long, cis_counter_sampled);
static DEFINE_PER_CPU(unsigned long, cis_counter_steps);
static DEFINE_PER_CPU(unsigned long, cis_counter_capped);
/* Initialization only: no shared sequence update on the charge hot path. */
static atomic64_t cis_counter_generation = ATOMIC64_INIT(0);

void cis_counter_init(struct page_counter *counter)
{
	s64 old = atomic64_read(&cis_counter_generation), next;

	counter->cis_owner_cgroup = 0;
	counter->cis_resource_kind = CIS_CC_UNKNOWN;
	for (;;) {
		if (unlikely(old == S64_MAX)) {
			counter->cis_generation = 0;
			return;
		}
		next = atomic64_cmpxchg(&cis_counter_generation, old, old + 1);
		if (next == old) {
			counter->cis_generation = old + 1;
			return;
		}
		old = next;
	}
}
EXPORT_SYMBOL_GPL(cis_counter_init);

/* Called once by the owning subsystem before publishing an online object.
 * No lookup or shared update is added to the charge/uncharge path. */
void cis_counter_bind(struct page_counter *counter, u64 owner, u32 kind)
{
	if (!owner || !kind || kind > CIS_CC_TCPMEM ||
	    WARN_ON_ONCE(READ_ONCE(counter->cis_owner_cgroup)))
		return;
	WRITE_ONCE(counter->cis_resource_kind, kind);
	smp_store_release(&counter->cis_owner_cgroup, owner);
}
EXPORT_SYMBOL_GPL(cis_counter_bind);

static int cis_counter_audit_show(struct seq_file *m, void *unused)
{
	int cpu;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_printf(m, "version=1 active=%u shift=%u snapshot=non_atomic sequence=%lld counter_bytes=%zu source_counter_bytes_per_cpu=%zu\n",
		trace_cis_counter_step_enabled(), min(counter_shift, 16U),
		(long long)atomic64_read(&cis_counter_generation), sizeof(struct page_counter),
		5 * sizeof(unsigned long));
	for_each_possible_cpu(cpu)
		seq_printf(m, "cpu=%d entries=%lu eligible=%lu sampled=%lu steps=%lu capped=%lu\n", cpu,
			READ_ONCE(per_cpu(cis_counter_entries, cpu)), READ_ONCE(per_cpu(cis_counter_calls, cpu)),
			READ_ONCE(per_cpu(cis_counter_sampled, cpu)), READ_ONCE(per_cpu(cis_counter_steps, cpu)),
			READ_ONCE(per_cpu(cis_counter_capped, cpu)));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_counter_audit);

void __cis_counter_step(struct cis_counter_ctx *ctx, struct page_counter *counter,
		u32 stage, u32 depth, unsigned long pages, long usage)
{
	struct cis_counter_sample sample;
	u32 ordinal = ctx->steps++;
	u64 owner;

	if (ordinal >= CIS_CC_STEPS && stage != CIS_CC_END) {
		preempt_disable();
		this_cpu_inc(cis_counter_capped);
		preempt_enable();
		return;
	}
	preempt_disable();
	if (this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_skipped);
		preempt_enable();
		return;
	}
	this_cpu_write(cis_in_trace, true);
	this_cpu_inc(cis_counter_steps);
	owner = smp_load_acquire(&counter->cis_owner_cgroup);
	sample = (struct cis_counter_sample) {
		.start_ns = ctx->start_ns, .time_ns = ktime_get_ns(),
		.leaf = ctx->leaf, .counter = counter, .parent = counter->parent,
		.leaf_generation = READ_ONCE(ctx->leaf->cis_generation),
		.generation = READ_ONCE(counter->cis_generation),
		.parent_generation = counter->parent ? READ_ONCE(counter->parent->cis_generation) : 0,
		.pages = pages, .usage = usage, .limit = READ_ONCE(counter->max),
		.op = ctx->op, .stage = stage, .depth = depth, .ordinal = ordinal,
		.sample_shift = min(counter_shift, 16U),
		.skipped = this_cpu_read(cis_skipped),
		.owner_cgroup = owner,
		.resource_kind = owner ? READ_ONCE(counter->cis_resource_kind) : CIS_CC_UNKNOWN,
	};
	trace_cis_counter_step(&sample);
	this_cpu_write(cis_in_trace, false);
	preempt_enable();
}

void __cis_counter_start(struct cis_counter_ctx *ctx, struct page_counter *leaf, u32 op)
{
	unsigned long n;

	preempt_disable();
	this_cpu_inc(cis_counter_entries);
	if (this_cpu_read(cis_in_trace) || in_interrupt()) {
		this_cpu_inc(cis_skipped);
		preempt_enable();
		return;
	}
	n = this_cpu_inc_return(cis_counter_calls);
	if (n & ((1UL << min(counter_shift, 16U)) - 1)) {
		preempt_enable();
		return;
	}
	this_cpu_inc(cis_counter_sampled);
	*ctx = (struct cis_counter_ctx) { .start_ns = ktime_get_ns(), .leaf = leaf, .op = op };
	preempt_enable();
	__cis_counter_step(ctx, leaf, CIS_CC_BEGIN, 0, 0, 0);
}
#endif

#ifdef CONFIG_CIS_OBSERVE_ALLOC
static char alloc_cache[64] = "maple_node";
module_param_string(alloc_cache, alloc_cache, sizeof(alloc_cache), 0400);
MODULE_PARM_DESC(alloc_cache, "Exact SLUB cache name admitted for short allocation diagnostics");
void __cis_slub_event(const char *name, void *cache, void *object,
		unsigned int phase)
{
	unsigned long irq_flags;
	u64 begin = 0;

	if (!name || strcmp(name, alloc_cache))
		return;
	/* An observed interrupt boundary is not lost data. Invalidate the
	 * object's open intervals without naming the interrupted task as owner.
	 * NMI/reentrant callbacks still report a genuine gap and fail closed. */
	if (in_nmi()) {
		preempt_disable_notrace();
		this_cpu_inc(cis_skipped);
		preempt_enable_notrace();
		return;
	}
	if (in_hardirq() || in_serving_softirq())
		phase = CIS_ESCAPE;
	/* Protect only this callback, never the native lock attempt or hold.
	 * Otherwise IRQ-exit softirq can reenter the same raw trace program.
	 * This adds IRQ-off work; debug accounting is not a latency bound. */
	preempt_disable_notrace();
	local_irq_save(irq_flags);
	if (diag)
		begin = ktime_get_ns();
	__cis_lock_event(object, CIS_SLUBLOCK, phase, NULL, (unsigned long)cache);
	if (diag) {
		struct cis_recursion_diag *d = this_cpu_ptr(&cis_recursion_diag);
		u64 elapsed = ktime_get_ns() - begin;

		d->slub_irqoff_calls++;
		d->slub_irqoff_ns += elapsed;
		d->slub_irqoff_max_ns = max(d->slub_irqoff_max_ns, elapsed);
	}
	local_irq_restore(irq_flags);
	preempt_enable_notrace();
}
EXPORT_SYMBOL_GPL(__cis_slub_event);
static unsigned int alloc_shift = 6;
module_param(alloc_shift, uint, 0400);
static DEFINE_PER_CPU(unsigned long, cis_alloc_entries);
static DEFINE_PER_CPU(unsigned long, cis_alloc_eligible);
static DEFINE_PER_CPU(unsigned long, cis_alloc_selected);
static DEFINE_PER_CPU(unsigned long, cis_alloc_steps);
static DEFINE_PER_CPU(unsigned long, cis_alloc_capped);
static DEFINE_PER_CPU(unsigned long, cis_alloc_irq_filtered);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_entries);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_items);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_capped);
struct cis_alloc_free_guard { bool active[3]; };
static DEFINE_PER_CPU(struct cis_alloc_free_guard, cis_alloc_free_guard);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_nested);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_nmi);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_irq);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_callback_calls);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_callback_ns);
static DEFINE_PER_CPU(unsigned long, cis_alloc_free_callback_max_ns);
static DEFINE_PER_CPU(unsigned long, cis_maple_entries);
static DEFINE_PER_CPU(unsigned long, cis_maple_callbacks);
static DEFINE_PER_CPU(unsigned long, cis_maple_callback_ns);
static DEFINE_PER_CPU(unsigned long, cis_maple_callback_max_ns);

static int cis_alloc_audit_show(struct seq_file *m, void *unused)
{
	int cpu;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_printf(m, "version=5 active=%u release_active=%u shift=%u cache=%s snapshot=non_atomic bytes_per_cpu=%zu guard_bytes_per_cpu=%zu maple_active=%u\n",
		trace_cis_alloc_step_enabled(), trace_cis_alloc_release_enabled(), min(alloc_shift, 16U), alloc_cache,
		19 * sizeof(unsigned long), sizeof(struct cis_alloc_free_guard), trace_cis_maple_alloc_enabled());
	for_each_possible_cpu(cpu)
		seq_printf(m, "cpu=%d entries=%lu eligible=%lu sampled=%lu steps=%lu capped=%lu irq_filtered=%lu free_entries=%lu free_items=%lu free_capped=%lu free_nested=%lu free_nmi=%lu free_irq=%lu free_callback_calls=%lu free_callback_ns=%lu free_callback_max_ns=%lu maple_entries=%lu maple_callbacks=%lu maple_callback_ns=%lu maple_callback_max_ns=%lu\n", cpu,
			READ_ONCE(per_cpu(cis_alloc_entries, cpu)), READ_ONCE(per_cpu(cis_alloc_eligible, cpu)),
			READ_ONCE(per_cpu(cis_alloc_selected, cpu)), READ_ONCE(per_cpu(cis_alloc_steps, cpu)),
			READ_ONCE(per_cpu(cis_alloc_capped, cpu)), READ_ONCE(per_cpu(cis_alloc_irq_filtered, cpu)),
			READ_ONCE(per_cpu(cis_alloc_free_entries, cpu)), READ_ONCE(per_cpu(cis_alloc_free_items, cpu)),
			READ_ONCE(per_cpu(cis_alloc_free_capped, cpu)), READ_ONCE(per_cpu(cis_alloc_free_nested, cpu)),
			READ_ONCE(per_cpu(cis_alloc_free_nmi, cpu)), READ_ONCE(per_cpu(cis_alloc_free_irq, cpu)),
			READ_ONCE(per_cpu(cis_alloc_free_callback_calls, cpu)), READ_ONCE(per_cpu(cis_alloc_free_callback_ns, cpu)),
			READ_ONCE(per_cpu(cis_alloc_free_callback_max_ns, cpu)),
			READ_ONCE(per_cpu(cis_maple_entries, cpu)), READ_ONCE(per_cpu(cis_maple_callbacks, cpu)),
			READ_ONCE(per_cpu(cis_maple_callback_ns, cpu)), READ_ONCE(per_cpu(cis_maple_callback_max_ns, cpu)));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_alloc_audit);

u64 __cis_maple_alloc(struct maple_tree *tree, struct kmem_cache *cache,
		unsigned long gfp, unsigned long requested, unsigned long count,
		u32 operation, u64 begin_ns)
{
	struct cis_maple_sample sample;
	u64 now, elapsed, result = 0;

	preempt_disable();
	this_cpu_inc(cis_maple_entries);
	if (strcmp(alloc_cache, "maple_node"))
		goto out;
	if (in_interrupt() || this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_skipped);
		goto out;
	}
	this_cpu_write(cis_in_trace, true);
	now = ktime_get_ns();
	result = begin_ns ?: now;
	sample = (struct cis_maple_sample) {
		.begin_ns = result, .time_ns = now, .tree = tree, .cache = cache,
		.gfp = gfp, .requested = requested, .count = count,
		.operation = operation, .phase = begin_ns ? 2 : 1,
	};
	trace_cis_maple_alloc(&sample);
	elapsed = ktime_get_ns() - now;
	this_cpu_inc(cis_maple_callbacks);
	this_cpu_add(cis_maple_callback_ns, elapsed);
	if (elapsed > this_cpu_read(cis_maple_callback_max_ns))
		this_cpu_write(cis_maple_callback_max_ns, elapsed);
	this_cpu_write(cis_in_trace, false);
out:
	preempt_enable();
	return result;
}

void __cis_alloc_release(struct kmem_cache *cache, const char *name,
		void **objects, int count, unsigned long caller)
{
	struct cis_alloc_release_sample sample;
	struct cis_alloc_free_guard *guard;
	unsigned long irq_flags, elapsed;
	u32 context;
	int i;
	preempt_disable();
	this_cpu_inc(cis_alloc_free_entries);
	if (!name || strcmp(name, alloc_cache))
		goto out;
	if (in_nmi()) {
		this_cpu_inc(cis_alloc_free_nmi);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	context = in_hardirq() ? 2 : in_serving_softirq() ? 1 : 0;
	guard = this_cpu_ptr(&cis_alloc_free_guard);
	/* A release may interrupt a different probe, but the same raw-tp BPF
	 * program cannot recurse even across execution levels on this CPU. */
	if (guard->active[0] || guard->active[1] || guard->active[2] ||
	    (!context && this_cpu_read(cis_in_trace))) {
		this_cpu_inc(cis_alloc_free_nested);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	if (count > CIS_CA_STEPS) {
		this_cpu_inc(cis_alloc_free_capped);
		/* A missed release could join a later reuse to an old allocation. */
		this_cpu_inc(cis_skipped);
	}
	if (context)
		this_cpu_inc(cis_alloc_free_irq);
	for (i = 0; i < min(count, CIS_CA_STEPS); i++) {
		/* The same raw-tp program must not reenter from an IRQ. Restore
		 * interrupts between objects, rather than guarding the whole batch.
		 * The callback timer is not a bound on complete IRQ-off latency. */
		local_irq_save(irq_flags);
		guard->active[context] = true;
		if (!context)
			this_cpu_write(cis_in_trace, true);
		sample = (struct cis_alloc_release_sample) {
			.time_ns = ktime_get_ns(), .cache = cache, .object = objects[i],
			.caller = caller, .context = context,
		};
		this_cpu_inc(cis_alloc_free_items);
		trace_cis_alloc_release(&sample);
		elapsed = ktime_get_ns() - sample.time_ns;
		this_cpu_inc(cis_alloc_free_callback_calls);
		this_cpu_add(cis_alloc_free_callback_ns, elapsed);
		if (elapsed > this_cpu_read(cis_alloc_free_callback_max_ns))
			this_cpu_write(cis_alloc_free_callback_max_ns, elapsed);
		if (!context)
			this_cpu_write(cis_in_trace, false);
		guard->active[context] = false;
		local_irq_restore(irq_flags);
	}
out:
	preempt_enable();
}

void __cis_alloc_step(struct cis_alloc_ctx *ctx, u32 stage, void *object,
		void *resource, int node, unsigned long count)
{
	struct cis_alloc_sample sample;
	u32 ordinal = ctx->steps++;
	preempt_disable();
	if (ordinal >= CIS_CA_STEPS && stage != CIS_CA_END) {
		this_cpu_inc(cis_alloc_capped);
		goto out;
	}
	if (this_cpu_read(cis_in_trace) || in_interrupt()) {
		this_cpu_inc(cis_skipped);
		goto out;
	}
	this_cpu_write(cis_in_trace, true);
	this_cpu_inc(cis_alloc_steps);
	sample = (struct cis_alloc_sample) {
		.start_ns = ctx->start_ns, .time_ns = ktime_get_ns(), .cache = ctx->cache,
		.object = object, .resource = resource, .gfp = ctx->gfp,
		.requested = ctx->requested, .count = count, .operation = ctx->operation,
		.stage = stage, .ordinal = ordinal, .sample_shift = min(alloc_shift, 16U),
		.requested_node = ctx->requested_node,
		.observed_node = (stage == CIS_CA_CPU_FAST || stage == CIS_CA_CPU_PARTIAL ||
			stage == CIS_CA_PARTIAL_END || stage == CIS_CA_NODE_DONE ||
			stage == CIS_CA_NEW_END) ? node : -1,
	};
	trace_cis_alloc_step(&sample);
	this_cpu_write(cis_in_trace, false);
out:
	preempt_enable();
}

void __cis_alloc_start(struct cis_alloc_ctx *ctx, struct kmem_cache *cache,
		const char *name, unsigned long gfp, int node, unsigned long requested, u32 operation)
{
	unsigned long n;
	preempt_disable();
	this_cpu_inc(cis_alloc_entries);
	if (!name || strcmp(name, alloc_cache))
		goto out;
	if (in_interrupt()) {
		this_cpu_inc(cis_alloc_irq_filtered);
		goto out;
	}
	if (this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_skipped);
		goto out;
	}
	n = this_cpu_inc_return(cis_alloc_eligible);
	if (n & ((1UL << min(alloc_shift, 16U)) - 1))
		goto out;
	this_cpu_inc(cis_alloc_selected);
	*ctx = (struct cis_alloc_ctx) { .start_ns = ktime_get_ns(), .cache = cache,
		.gfp = gfp, .requested = requested, .operation = operation, .requested_node = node };
out:
	preempt_enable();
	if (ctx->start_ns)
		__cis_alloc_step(ctx, CIS_CA_BEGIN, NULL, NULL, node, 0);
}
#endif

#ifdef CONFIG_CIS_OBSERVE_NET
static unsigned int net_shift = 6;
module_param(net_shift, uint, 0400);
MODULE_PARM_DESC(net_shift, "Select TCP socket lives by native cookie low bits (clamped to 16)");
static DEFINE_PER_CPU(unsigned long, cis_net_entries);
static DEFINE_PER_CPU(unsigned long, cis_net_eligible);
static DEFINE_PER_CPU(unsigned long, cis_net_selected);
static DEFINE_PER_CPU(unsigned long, cis_net_releases);
static DEFINE_PER_CPU(unsigned long, cis_net_skipped);
static DEFINE_PER_CPU(unsigned long, cis_tx_entries);
static DEFINE_PER_CPU(unsigned long, cis_tx_selected);
static DEFINE_PER_CPU(unsigned long, cis_tx_callbacks);
static DEFINE_PER_CPU(unsigned long, cis_tx_callback_ns);
static DEFINE_PER_CPU(unsigned long, cis_tx_callback_max_ns);
static DEFINE_PER_CPU(unsigned long, cis_tx_irq_filtered);
static DEFINE_PER_CPU(unsigned long, cis_tx_nested_skipped);
static DEFINE_PER_CPU(unsigned long, cis_net_release_ends);
static DEFINE_PER_CPU(unsigned long, cis_net_release_callback_ns);

static int cis_net_audit_show(struct seq_file *m, void *unused)
{
	int cpu;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_printf(m, "version=5 active=%u release_active=%u tx_active=%u shift=%u source_counter_bytes_per_cpu=%zu snapshot=non_atomic\n",
		trace_cis_net_state_enabled(), trace_cis_net_skb_release_enabled(),
		trace_cis_net_tx_enabled(), min(net_shift, 16U), 14 * sizeof(unsigned long));
	for_each_possible_cpu(cpu)
		seq_printf(m, "cpu=%d entries=%lu eligible=%lu selected=%lu releases=%lu skipped=%lu tx_entries=%lu tx_selected=%lu tx_callbacks=%lu tx_callback_ns=%lu tx_callback_max_ns=%lu tx_irq_filtered=%lu tx_nested_skipped=%lu release_ends=%lu release_callback_ns=%lu\n", cpu,
			READ_ONCE(per_cpu(cis_net_entries, cpu)), READ_ONCE(per_cpu(cis_net_eligible, cpu)),
			READ_ONCE(per_cpu(cis_net_selected, cpu)), READ_ONCE(per_cpu(cis_net_releases, cpu)),
			READ_ONCE(per_cpu(cis_net_skipped, cpu)),
			READ_ONCE(per_cpu(cis_tx_entries, cpu)), READ_ONCE(per_cpu(cis_tx_selected, cpu)),
			READ_ONCE(per_cpu(cis_tx_callbacks, cpu)), READ_ONCE(per_cpu(cis_tx_callback_ns, cpu)),
			READ_ONCE(per_cpu(cis_tx_callback_max_ns, cpu)),
			READ_ONCE(per_cpu(cis_tx_irq_filtered, cpu)), READ_ONCE(per_cpu(cis_tx_nested_skipped, cpu)),
			READ_ONCE(per_cpu(cis_net_release_ends, cpu)), READ_ONCE(per_cpu(cis_net_release_callback_ns, cpu)));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_net_audit);

void __cis_net_tx_begin(struct cis_net_tx_sample *sample, struct sock *sk,
		       u32 gfp, u32 requested)
{
	u64 cookie, begin, elapsed;

	preempt_disable();
	this_cpu_inc(cis_tx_entries);
	/* This adapter opens allocation episodes only in process context.  An
	 * IRQ-only call has no admitted requester or pending lifetime to lose. */
	if (in_interrupt()) {
		this_cpu_inc(cis_tx_irq_filtered);
		goto out;
	}
	if (this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_tx_nested_skipped);
		this_cpu_inc(cis_net_skipped);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	if ((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_protocol != IPPROTO_TCP || sk->sk_type != SOCK_STREAM)
		goto out;
	cookie = __sock_gen_cookie(sk);
	if (!cookie || (cookie & ((1ULL << min(net_shift, 16U)) - 1)))
		goto out;
	this_cpu_inc(cis_tx_selected);
	*sample = (struct cis_net_tx_sample) {
		.cookie = cookie, .sk = sk, .netns = sock_net(sk)->ns.inum,
		.gfp = gfp, .requested = requested,
	};
	/* Backend interval includes scheduling/interrupts, not exclusive CPU. */
	sample->start_ns = ktime_get_ns();
	sample->time_ns = sample->start_ns;
	sample->phase = CIS_TX_BEGIN;
	this_cpu_write(cis_in_trace, true);
	this_cpu_inc(cis_tx_callbacks);
	begin = ktime_get_ns();
	trace_cis_net_tx(sample);
	elapsed = ktime_get_ns() - begin;
	this_cpu_add(cis_tx_callback_ns, elapsed);
	if (elapsed > this_cpu_read(cis_tx_callback_max_ns))
		this_cpu_write(cis_tx_callback_max_ns, elapsed);
	this_cpu_write(cis_in_trace, false);
	/* Do not charge the identity callback to the backend wall interval. */
	sample->alloc_ns = ktime_get_ns();
out:
	preempt_enable();
}

void __cis_net_tx_step(struct cis_net_tx_sample *sample, struct sk_buff *skb,
		      u32 phase)
{
	u64 now = ktime_get_ns(), begin, elapsed;

	preempt_disable();
	if (in_interrupt() || this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_net_skipped);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	sample->time_ns = now;
	sample->phase = phase;
	sample->skb = skb;
	if (phase == CIS_TX_BACKEND || phase == CIS_TX_FAILED)
		sample->backend_ns = now;
	this_cpu_write(cis_in_trace, true);
	this_cpu_inc(cis_tx_callbacks);
	begin = ktime_get_ns();
	trace_cis_net_tx(sample);
	elapsed = ktime_get_ns() - begin;
	this_cpu_add(cis_tx_callback_ns, elapsed);
	if (elapsed > this_cpu_read(cis_tx_callback_max_ns))
		this_cpu_write(cis_tx_callback_max_ns, elapsed);
	this_cpu_write(cis_in_trace, false);
out:
	preempt_enable();
}

static u32 cis_net_context(void)
{
	return in_hardirq() ? 2 : in_serving_softirq() ? 1 : 0;
}

void __cis_net_event(struct sock *sk, struct sk_buff *skb, u32 phase)
{
	struct cis_net_sample sample = { };
	u64 cookie;

	preempt_disable();
	this_cpu_inc(cis_net_entries);
	if ((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_protocol != IPPROTO_TCP || sk->sk_type != SOCK_STREAM)
		goto out;
	this_cpu_inc(cis_net_eligible);
	if (in_nmi() || this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_net_skipped);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	/* Native socket-life identity, not an observation epoch or owner ID. */
	cookie = __sock_gen_cookie(sk);
	if (!cookie || (cookie & ((1ULL << min(net_shift, 16U)) - 1)))
		goto out;
	this_cpu_write(cis_in_trace, true);
	this_cpu_inc(cis_net_selected);
	sample = (struct cis_net_sample) {
		.time_ns = ktime_get_ns(), .cookie = cookie, .sk = sk, .skb = skb,
		.phase = phase, .context = cis_net_context(), .netns = sock_net(sk)->ns.inum,
		.backlog_bytes = READ_ONCE(sk->sk_backlog.len),
	};
	/* SERVICE_END may carry an already-freed skb address. Never dereference it. */
	if (skb && (phase == CIS_CN_QUEUED || phase == CIS_CN_SERVICE_BEGIN)) {
		sample.bytes = skb->len;
		sample.flags = (skb_cloned(skb) ? 1 : 0) |
			(skb_is_gso(skb) ? 2 : 0) | (skb_is_nonlinear(skb) ? 4 : 0);
	}
	trace_cis_net_state(&sample);
	this_cpu_write(cis_in_trace, false);
out:
	preempt_enable();
}
EXPORT_SYMBOL_GPL(__cis_net_event);

void __cis_net_skb_release(struct sk_buff *skb, struct cis_net_sample *backend)
{
	struct cis_net_sample sample;
	u64 begin;

	preempt_disable();
	this_cpu_inc(cis_net_releases);
	if (in_nmi() || this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_net_skipped);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	this_cpu_write(cis_in_trace, true);
	sample = (struct cis_net_sample) { .time_ns = ktime_get_ns(),
		.skb = skb, .phase = CIS_CN_SKB_RELEASE, .context = cis_net_context() };
	if (backend) {
		sample.release_start_ns = sample.time_ns;
		sample.flags = CIS_RELEASE_BACKEND |
			(skb->cloned ? CIS_RELEASE_CLONED : 0) |
			(skb_is_gso(skb) ? CIS_RELEASE_GSO : 0) |
			(skb_is_nonlinear(skb) ? CIS_RELEASE_NONLINEAR : 0) |
			(skb->fclone == SKB_FCLONE_ORIG ? CIS_RELEASE_FCLONE_ORIG : 0) |
			(skb->fclone == SKB_FCLONE_CLONE ? CIS_RELEASE_FCLONE_CLONE : 0);
	}
	begin = ktime_get_ns();
	trace_cis_net_skb_release(&sample);
	this_cpu_add(cis_net_release_callback_ns, ktime_get_ns() - begin);
	if (backend) {
		*backend = sample;
		backend->release_backend_ns = ktime_get_ns();
	}
	this_cpu_write(cis_in_trace, false);
out:
	preempt_enable();
}
EXPORT_SYMBOL_GPL(__cis_net_skb_release);

void __cis_net_skb_release_end(struct cis_net_sample *sample, bool returned)
{
	u64 now = ktime_get_ns(), begin;

	preempt_disable();
	this_cpu_inc(cis_net_release_ends);
	if (in_nmi() || this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_net_skipped);
		this_cpu_inc(cis_skipped);
		goto out;
	}
	/* No dereference of sample->skb after native free. */
	sample->time_ns = now;
	sample->phase = CIS_CN_SKB_RELEASE_END;
	sample->context = cis_net_context();
	sample->flags |= returned ? CIS_RELEASE_HEADER_RETURNED : CIS_RELEASE_PAIR_RETAINED;
	this_cpu_write(cis_in_trace, true);
	begin = ktime_get_ns();
	trace_cis_net_skb_release(sample);
	this_cpu_add(cis_net_release_callback_ns, ktime_get_ns() - begin);
	this_cpu_write(cis_in_trace, false);
out:
	preempt_enable();
}
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_net_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_net_skb_release);
#endif

void __cis_mutex_wait(struct mutex *lock)
{
	unsigned long first, second;
	struct task_struct *owner;
	/* Mirror this OLK non-RT mutex's owner encoding. RCU protects task life;
	 * the second read rejects a changed owner. This remains a point observation. */
	rcu_read_lock();
	first = atomic_long_read(&lock->owner);
	owner = (void *)(first & ~7UL);
	second = atomic_long_read(&lock->owner);
	if (first != second || (first & 6UL))
		owner = NULL;
	__cis_lock_event(lock, CIS_MUTEX, CIS_WAIT, owner,
			first == second ? (first & 7UL) : 8UL);
	rcu_read_unlock();
}
