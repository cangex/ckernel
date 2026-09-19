/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_MAPLE_H
#define _LINUX_CIS_MAPLE_H
#include <linux/types.h>
struct maple_tree;
struct kmem_cache;
struct cis_maple_sample {
	u64 begin_ns, time_ns;
	struct maple_tree *tree;
	struct kmem_cache *cache;
	unsigned long gfp, requested, count;
	u32 operation, phase;
};
#ifdef CONFIG_CIS_OBSERVE_ALLOC
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_maple_alloc);
u64 __cis_maple_alloc(struct maple_tree *, struct kmem_cache *, unsigned long,
		unsigned long, unsigned long, u32, u64);
static inline u64 cis_maple_alloc(struct maple_tree *tree, struct kmem_cache *cache,
		unsigned long gfp, unsigned long requested, unsigned long count,
		u32 operation, u64 begin_ns)
{
	if (tracepoint_enabled(cis_maple_alloc))
		return __cis_maple_alloc(tree, cache, gfp, requested, count, operation, begin_ns);
	return 0;
}
#else
static inline u64 cis_maple_alloc(struct maple_tree *tree, struct kmem_cache *cache,
		unsigned long gfp, unsigned long requested, unsigned long count,
		u32 operation, u64 begin_ns) { return 0; }
#endif
#endif
