/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_PAGE_BACKEND_H
#define _LINUX_CIS_PAGE_BACKEND_H
#include <linux/types.h>
struct zone;
enum cis_page_operation { CIS_PB_REFILL = 1, CIS_PB_DRAIN, CIS_PB_ALLOC, CIS_PB_FREE };
struct cis_page_sample {
	u64 begin_ns, acquired_ns, releasing_ns, end_ns;
	struct zone *zone;
	u64 requested_pages, completed_pages;
	u64 cgroup_id;
	u32 operation, sample_shift;
	s32 node, zone_index, order;
};
#ifdef CONFIG_CIS_OBSERVE_ALLOC
#include <linux/ktime.h>
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_page_backend);
void __cis_page_begin(struct cis_page_sample *, struct zone *, u32, int, u64);
void __cis_page_end(struct cis_page_sample *, u64);
static inline void cis_page_begin(struct cis_page_sample *s, struct zone *zone,
		u32 op, int order, u64 pages)
{
	s->begin_ns = 0;
	if (tracepoint_enabled(cis_page_backend))
		__cis_page_begin(s, zone, op, order, pages);
}
static inline void cis_page_acquired(struct cis_page_sample *s)
{
	if (s->begin_ns)
		s->acquired_ns = ktime_get_ns();
}
static inline void cis_page_releasing(struct cis_page_sample *s)
{
	if (s->begin_ns)
		s->releasing_ns = ktime_get_ns();
}
static inline void cis_page_end(struct cis_page_sample *s, u64 pages)
{
	if (s->begin_ns)
		__cis_page_end(s, pages);
}
#else
static inline void cis_page_begin(struct cis_page_sample *s, struct zone *zone,
		u32 op, int order, u64 pages) { s->begin_ns = 0; }
static inline void cis_page_acquired(struct cis_page_sample *s) { }
static inline void cis_page_releasing(struct cis_page_sample *s) { }
static inline void cis_page_end(struct cis_page_sample *s, u64 pages) { }
#endif
#endif
