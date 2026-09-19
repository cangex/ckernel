/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_OBSERVE_H
#define _LINUX_CIS_OBSERVE_H
#include <linux/types.h>
struct mutex;
struct task_struct;
enum cis_resource { CIS_MUTEX = 1, CIS_LOCKREF = 2, CIS_FDLOCK = 3, CIS_SLUBLOCK = 4,
	CIS_RESOURCE_END };
enum cis_phase { CIS_RESET = 1, CIS_WAIT, CIS_ACQUIRE,
	CIS_RELEASE_BEGIN, CIS_RELEASE_END, CIS_SNAPSHOT,
	CIS_ESCAPE, CIS_RETIRE,
	/* 9--11 are userspace protocol scheduler/prefix records. */
	CIS_ABORT = 12 };
#ifdef CONFIG_CIS_OBSERVE
#include <trace/events/cis.h>
void __cis_lock_event(void *, unsigned int, unsigned int, struct task_struct *, unsigned long);
void __cis_mutex_wait(struct mutex *);
static inline void cis_lock_event(void *object, unsigned int kind,
		unsigned int phase, struct task_struct *owner, unsigned long flags)
{
	if (kind == CIS_SLUBLOCK ? trace_cis_slublock_state_enabled() :
	    kind == CIS_FDLOCK ? trace_cis_fdlock_state_enabled() : trace_cis_lock_state_enabled())
		__cis_lock_event(object, kind, phase, owner, flags);
}
static inline void cis_mutex_wait(struct mutex *lock)
{
	if (trace_cis_lock_state_enabled())
		__cis_mutex_wait(lock);
}
#else
static inline void cis_lock_event(void *object, unsigned int kind,
		unsigned int phase, struct task_struct *owner, unsigned long flags) {}
static inline void cis_mutex_wait(struct mutex *lock) {}
#endif
#endif
