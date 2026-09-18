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
#define CREATE_TRACE_POINTS
#include <linux/cis_observe.h>

static DEFINE_PER_CPU(bool, cis_in_trace);
static DEFINE_PER_CPU(unsigned long, cis_skipped);
static DEFINE_PER_CPU(unsigned long, cis_gate_filtered);

/* Monotone one-bit membership: collisions only admit extra events. No deletes
 * while any probe is registered; another container's holder is never filtered
 * by its identity. BPF owner watches are created only by WAIT events. */
#define CIS_GATE_BITS 16
static DECLARE_BITMAP(cis_waited, 1U << CIS_GATE_BITS);
static bool wait_gate;
module_param(wait_gate, bool, 0400);
MODULE_PARM_DESC(wait_gate, "Admit WAIT and all subsequent events for possibly waited objects");

int cis_observe_register(void)
{
	/* tracepoints_mutex serializes first-probe registration before enable.
	 * An old in-flight callback may only add false positives after this clear;
	 * tracepoint core synchronizes that generation before publishing new probes. */
	bitmap_zero(cis_waited, 1U << CIS_GATE_BITS);
	return 0;
}

void cis_observe_unregister(void)
{
	/* Do not clear while last-generation readers may still be returning. */
}

static bool cis_gate_allows(void *object, unsigned int kind, unsigned int phase)
{
	unsigned int bit = hash_long(((unsigned long)object >> 3) ^ kind, CIS_GATE_BITS);

	if (phase == CIS_WAIT) {
		if (!test_bit(bit, cis_waited)) {
			set_bit(bit, cis_waited);
			smp_mb__after_atomic();
		}
		return true;
	}
	return test_bit(bit, cis_waited);
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
	if (trace_cis_lock_state_enabled())
		return -EBUSY;
	/* Last-link close only unregisters callbacks in this OLK. Complete the
	 * grace periods before userspace consumes terminal BPF/source counters.
	 * This is control-plane work, never part of a lock callback. */
	tracepoint_synchronize_unregister();
	if (trace_cis_lock_state_enabled())
		return -EBUSY;
	seq_printf(m, "version=3 enabled=%u trace_active=%u synchronized=1 bytes_per_possible_cpu=%zu snapshot=non_atomic wait_gate=%u gate_bytes=%zu\n",
		   diag, trace_cis_lock_state_enabled(), sizeof(struct cis_recursion_diag),
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

static int __init cis_diag_init(void)
{
	debugfs_create_file("cis_recursion", 0400, NULL, NULL, &cis_diag_fops);
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
	trace_cis_lock_state(object, kind, phase, owner, flags,
			     this_cpu_read(cis_skipped));
	this_cpu_write(cis_in_trace, false);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(__cis_lock_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_lock_state);

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
