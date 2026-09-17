/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_OBSERVE_H
#define _LINUX_CIS_OBSERVE_H
#include <linux/types.h>
struct mutex;
struct task_struct;
enum cis_resource { CIS_MUTEX = 1, CIS_LOCKREF = 2 };
enum cis_phase { CIS_RESET = 1, CIS_WAIT, CIS_ACQUIRE,
	CIS_RELEASE_BEGIN, CIS_RELEASE_END, CIS_SNAPSHOT,
	CIS_ESCAPE, CIS_RETIRE };
#ifdef CONFIG_CIS_OBSERVE
#include <trace/events/cis.h>
void __cis_lock_event(void *, unsigned int, unsigned int, struct task_struct *, unsigned long);
void __cis_mutex_wait(struct mutex *);
static inline void cis_lock_event(void *object, unsigned int kind,
		unsigned int phase, struct task_struct *owner, unsigned long flags)
{
	if (trace_cis_lock_state_enabled())
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
