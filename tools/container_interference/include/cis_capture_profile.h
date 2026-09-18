/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_CAPTURE_PROFILE_H
#define CIS_CAPTURE_PROFILE_H
#include <string.h>

static inline int cis_profile_buffer_pages(unsigned int profile, unsigned int cpus)
{
	unsigned int pages = 2;
	unsigned int limit = profile == 8 ? 128 : 16;

	if (!cpus || cpus > 512)
		return 0;
	/* Allocation stage bursts use the existing global 4 MiB payload budget. */
	while (pages < limit && (unsigned long long)pages * 2 * 4096 * cpus <= (4ULL << 20))
		pages *= 2;
	return pages;
}

static inline int cis_profile_program(unsigned int profile, const char *name)
{
	if (!profile)
		return 1; /* Existing explicit continuous tool, not periodic mode. */
	if (profile == 1)
		return !strcmp(name, "sample_ip");
	if (profile == 3)
		return !strcmp(name, "sched_wait");
	if (profile == 4)
		return !strcmp(name, "reclaim_begin") || !strcmp(name, "reclaim_end") ||
		       !strcmp(name, "memcg_begin") || !strcmp(name, "memcg_end");
	if (profile == 5)
		return !strcmp(name, "lock_begin") || !strcmp(name, "lock_end");
	if (profile == 7)
		return !strcmp(name, "counter_step");
	if (profile == 8)
		return !strcmp(name, "alloc_step");
	return (profile == 2 || profile == 6) && (!strcmp(name, "owner_state") || !strcmp(name, "owner_switch"));
}

static inline int cis_profile_map(unsigned int profile, const char *name)
{
	if (!profile)
		return 1;
	if (profile < 1 || profile > 8)
		return 0;
	if (!strcmp(name, "session_window") || !strcmp(name, "roots") ||
	    !strcmp(name, "events") || !strcmp(name, "stats"))
		return 1;
	if (profile == 3)
		return !strcmp(name, "targets");
	if (profile == 4 || profile == 5 || profile == 7 || profile == 8)
		return !strcmp(name, "targets") || !strcmp(name, "stacks") || !strcmp(name, "pending");
	return (profile == 2 || profile == 6) && (!strcmp(name, "targets") || !strcmp(name, "stacks") ||
		!strcmp(name, "watched") || !strcmp(name, "holders") ||
		!strcmp(name, "holder_tasks") || !strcmp(name, "owner_attempts"));
}
#endif
