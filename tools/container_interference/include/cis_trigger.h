/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_TRIGGER_H
#define CIS_TRIGGER_H
#include <string.h>

static inline int cis_fast_lock_candidate_symbol(const char *name)
{
	/* Generic acquisition and rwsem names do not establish a supported
	 * contended path. A slowpath sample is still not ownership evidence. */
	return strstr(name,"queued_spin_lock_slowpath") ||
	       strstr(name,"mutex_optimistic_spin") ||
	       strstr(name,"mutex_spin_on_owner") ||
	       strstr(name,"__mutex_lock_slowpath") ||
	       strstr(name,"__mutex_lock_common");
}
#endif
