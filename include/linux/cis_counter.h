/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_COUNTER_H
#define _LINUX_CIS_COUNTER_H
#include <linux/types.h>
struct page_counter;
enum cis_counter_resource { CIS_CC_UNKNOWN, CIS_CC_MEMORY, CIS_CC_SWAP,
	CIS_CC_KMEM, CIS_CC_TCPMEM };
enum cis_counter_op { CIS_CC_CANCEL = 1, CIS_CC_CHARGE, CIS_CC_TRY,
	CIS_CC_UNCHARGE, CIS_CC_SET_MIN, CIS_CC_SET_LOW };
enum cis_counter_stage { CIS_CC_BEGIN = 1, CIS_CC_ADD, CIS_CC_SUB,
	CIS_CC_LIMIT_REVERSE, CIS_CC_ROLLBACK, CIS_CC_CHILD_MIN,
	CIS_CC_CHILD_LOW, CIS_CC_CORRECT, CIS_CC_END };
#define CIS_CC_STEPS 64
struct cis_counter_ctx {
	u64 start_ns;
	struct page_counter *leaf;
	u32 op, steps;
};
struct cis_counter_sample {
	u64 start_ns, time_ns;
	u64 leaf_generation, generation, parent_generation;
	struct page_counter *leaf, *counter, *parent;
	unsigned long pages, limit;
	long usage;
	u32 op, stage, depth, ordinal, sample_shift;
	unsigned long skipped;
	u64 owner_cgroup;
	u32 resource_kind;
};
#ifdef CONFIG_CIS_OBSERVE_COUNTER
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_counter_step);
void cis_counter_bind(struct page_counter *, u64, u32);
void __cis_counter_start(struct cis_counter_ctx *, struct page_counter *, u32);
void __cis_counter_step(struct cis_counter_ctx *, struct page_counter *, u32, u32,
		       unsigned long, long);
static inline void cis_counter_start(struct cis_counter_ctx *ctx,
		struct page_counter *leaf, u32 op)
{
	ctx->start_ns = 0;
	if (tracepoint_enabled(cis_counter_step))
		__cis_counter_start(ctx, leaf, op);
}
static inline void cis_counter_step(struct cis_counter_ctx *ctx,
		struct page_counter *counter, u32 stage, u32 depth,
		unsigned long pages, long usage)
{
	if (ctx->start_ns)
		__cis_counter_step(ctx, counter, stage, depth, pages, usage);
}
#else
static inline void cis_counter_bind(struct page_counter *counter, u64 owner,
		u32 resource_kind) { }
static inline void cis_counter_start(struct cis_counter_ctx *ctx,
		struct page_counter *leaf, u32 op) { ctx->start_ns = 0; }
static inline void cis_counter_step(struct cis_counter_ctx *ctx,
		struct page_counter *counter, u32 stage, u32 depth,
		unsigned long pages, long usage) { }
#endif
#endif
