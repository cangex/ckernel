/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_SLUB_H
#define _LINUX_CIS_SLUB_H
#include <linux/cis_observe.h>
#ifdef CONFIG_CIS_OBSERVE_ALLOC
void __cis_slub_event(const char *, void *, void *, unsigned int);
static inline void cis_slub_event(const char *name, void *cache,
		void *object, unsigned int phase)
{
	if (trace_cis_slublock_state_enabled())
		__cis_slub_event(name, cache, object, phase);
}
#else
static inline void cis_slub_event(const char *name, void *cache,
		void *object, unsigned int phase) { }
#endif
#endif
