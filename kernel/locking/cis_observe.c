// SPDX-License-Identifier: GPL-2.0
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#define CREATE_TRACE_POINTS
#include <linux/cis_observe.h>

static DEFINE_PER_CPU(bool, cis_in_trace);
static DEFINE_PER_CPU(unsigned long, cis_skipped);

void __cis_lock_event(void *object, unsigned int kind, unsigned int phase,
		struct task_struct *owner, unsigned long flags)
{
	preempt_disable();
	if (this_cpu_read(cis_in_trace)) {
		this_cpu_inc(cis_skipped);
		preempt_enable();
		return;
	}
	this_cpu_write(cis_in_trace, true);
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
