/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_RWSEM_H
#define _LINUX_CIS_RWSEM_H
#include <linux/types.h>
enum cis_rwsem_phase {
	CIS_RW_INIT = 1, CIS_RW_READ_BEGIN, CIS_RW_WRITE_BEGIN,
	CIS_RW_READ_ACQUIRED, CIS_RW_WRITE_ACQUIRED,
	CIS_RW_READ_RELEASE, CIS_RW_WRITE_RELEASE,
	CIS_RW_READ_ABORT, CIS_RW_WRITE_ABORT,
	CIS_RW_ANONYMOUS_BEGIN, CIS_RW_ANONYMOUS_END,
	CIS_RW_DOWNGRADE_BEGIN, CIS_RW_DOWNGRADE_END,
	CIS_RW_READ_TRY, CIS_RW_WRITE_TRY, CIS_RW_TRY_FAILED,
};
#ifdef CONFIG_CIS_OBSERVE
bool cis_rwsem_filter_active(void);
bool cis_rwsem_filter_allows(void *object);
int cis_rwsem_observe_register(void);
void cis_rwsem_observe_unregister(void);
#endif
#if defined(CONFIG_CIS_OBSERVE) && !defined(CONFIG_PREEMPT_RT)
#include <trace/events/cis.h>
void __cis_rwsem_event(void *object, unsigned int phase);
static inline void cis_rwsem_event(void *object, unsigned int phase)
{
	if (trace_cis_rwsem_state_enabled())
		__cis_rwsem_event(object, phase);
}
#else
static inline void cis_rwsem_event(void *object, unsigned int phase) {}
#endif
#endif
