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
#define CREATE_TRACE_POINTS
#include <linux/cis_observe.h>

static DEFINE_PER_CPU(bool, cis_in_trace);
static DEFINE_PER_CPU(unsigned long, cis_skipped);
static DEFINE_PER_CPU(unsigned long, cis_gate_filtered);

/* Monotone one-bit membership: collisions only admit extra events. No deletes
 * while any probe is registered; another container's holder is never filtered
 * by its identity. BPF owner watches are created only by WAIT events. */
#define CIS_GATE_BITS 16
static unsigned long cis_waited[2][BITS_TO_LONGS(1U << CIS_GATE_BITS)];
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

static bool cis_trace_active(void)
{
	return trace_cis_lock_state_enabled() || trace_cis_fdlock_state_enabled() ||
	       trace_cis_counter_step_enabled() || trace_cis_alloc_step_enabled();
}

static bool cis_gate_allows(void *object, unsigned int kind, unsigned int phase)
{
	unsigned int bit = hash_long(((unsigned long)object >> 3) ^ kind, CIS_GATE_BITS);
	unsigned long *gate = cis_waited[kind == CIS_FDLOCK];

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
	seq_printf(m, "version=3 owner=%u fd=%u counter=%u allocator=%u\n",
		   trace_cis_lock_state_enabled(), trace_cis_fdlock_state_enabled(),
		   trace_cis_counter_step_enabled(), trace_cis_alloc_step_enabled());
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_sources);

#ifdef CONFIG_CIS_OBSERVE_COUNTER
static const struct file_operations cis_counter_audit_fops;
#endif
#ifdef CONFIG_CIS_OBSERVE_ALLOC
static const struct file_operations cis_alloc_audit_fops;
#endif

static int __init cis_diag_init(void)
{
	debugfs_create_file("cis_recursion", 0400, NULL, NULL, &cis_diag_fops);
	debugfs_create_file("cis_sources", 0400, NULL, NULL, &cis_sources_fops);
#ifdef CONFIG_CIS_OBSERVE_COUNTER
	debugfs_create_file("cis_counter_audit", 0400, NULL, NULL, &cis_counter_audit_fops);
#endif
#ifdef CONFIG_CIS_OBSERVE_ALLOC
	debugfs_create_file("cis_alloc_audit", 0400, NULL, NULL, &cis_alloc_audit_fops);
#endif
	return 0;
}
late_initcall(cis_diag_init);

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
	if (kind == CIS_FDLOCK)
		trace_cis_fdlock_state(object, kind, phase, owner, flags, this_cpu_read(cis_skipped));
	else
		trace_cis_lock_state(object, kind, phase, owner, flags, this_cpu_read(cis_skipped));
	this_cpu_write(cis_in_trace, false);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(__cis_lock_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_lock_state);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_fdlock_state);

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
static unsigned int alloc_shift = 6;
module_param(alloc_shift, uint, 0400);
static DEFINE_PER_CPU(unsigned long, cis_alloc_entries);
static DEFINE_PER_CPU(unsigned long, cis_alloc_eligible);
static DEFINE_PER_CPU(unsigned long, cis_alloc_selected);
static DEFINE_PER_CPU(unsigned long, cis_alloc_steps);
static DEFINE_PER_CPU(unsigned long, cis_alloc_capped);

static int cis_alloc_audit_show(struct seq_file *m, void *unused)
{
	int cpu;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_printf(m, "version=1 active=%u shift=%u cache=%s snapshot=non_atomic bytes_per_cpu=%zu\n",
		trace_cis_alloc_step_enabled(), min(alloc_shift, 16U), alloc_cache,
		5 * sizeof(unsigned long));
	for_each_possible_cpu(cpu)
		seq_printf(m, "cpu=%d entries=%lu eligible=%lu sampled=%lu steps=%lu capped=%lu\n", cpu,
			READ_ONCE(per_cpu(cis_alloc_entries, cpu)), READ_ONCE(per_cpu(cis_alloc_eligible, cpu)),
			READ_ONCE(per_cpu(cis_alloc_selected, cpu)), READ_ONCE(per_cpu(cis_alloc_steps, cpu)),
			READ_ONCE(per_cpu(cis_alloc_capped, cpu)));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(cis_alloc_audit);

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
	if (this_cpu_read(cis_in_trace) || in_interrupt()) {
		this_cpu_inc(cis_skipped);
		goto out;
	}
	if (!name || strcmp(name, alloc_cache))
		goto out;
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
