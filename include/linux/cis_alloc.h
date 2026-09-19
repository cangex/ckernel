/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_ALLOC_H
#define _LINUX_CIS_ALLOC_H
#include <linux/types.h>
struct kmem_cache;
enum cis_alloc_stage {
	CIS_CA_BEGIN = 1, CIS_CA_PRE_BEGIN, CIS_CA_PRE_END,
	CIS_CA_SLOW_BEGIN, CIS_CA_SLOW_END, CIS_CA_CPU_FAST,
	CIS_CA_CPU_PARTIAL, CIS_CA_PARTIAL_BEGIN, CIS_CA_PARTIAL_END,
	CIS_CA_NODE_WAIT, CIS_CA_NODE_HELD, CIS_CA_NODE_DONE,
	CIS_CA_NEW_BEGIN, CIS_CA_NEW_END, CIS_CA_POST_BEGIN, CIS_CA_POST_END,
	CIS_CA_BULK_ITEM, CIS_CA_BULK_ROLLBACK, CIS_CA_KFENCE, CIS_CA_END,
	/* Append only: existing captures retain their original stage values. */
	CIS_CA_NODE_RELEASE,
};
#define CIS_CA_STEPS 64
struct cis_alloc_ctx {
	u64 start_ns;
	struct kmem_cache *cache;
	unsigned long gfp, requested;
	u32 operation, steps;
	s32 requested_node;
};
struct cis_alloc_sample {
	u64 start_ns, time_ns;
	struct kmem_cache *cache;
	void *object, *resource;
	unsigned long gfp, requested, count;
	u32 operation, stage, ordinal, sample_shift;
	s32 requested_node, observed_node;
};
struct cis_alloc_release_sample {
	u64 time_ns;
	struct kmem_cache *cache;
	void *object;
	unsigned long caller;
	u32 context;
};
#ifdef CONFIG_CIS_OBSERVE_ALLOC
#include <linux/tracepoint-defs.h>
DECLARE_TRACEPOINT(cis_alloc_step);
DECLARE_TRACEPOINT(cis_alloc_release);
void __cis_alloc_release(struct kmem_cache *, const char *, void **, int, unsigned long);
static inline void cis_alloc_release(struct kmem_cache *cache, const char *name,
		void **objects, int count, unsigned long caller)
{
	if (tracepoint_enabled(cis_alloc_release))
		__cis_alloc_release(cache, name, objects, count, caller);
}
void __cis_alloc_start(struct cis_alloc_ctx *, struct kmem_cache *,
		const char *, unsigned long, int, unsigned long, u32);
void __cis_alloc_step(struct cis_alloc_ctx *, u32, void *, void *, int,
		unsigned long);
static inline void cis_alloc_start(struct cis_alloc_ctx *ctx,
		struct kmem_cache *cache, const char *name, unsigned long gfp,
		int node, unsigned long requested, u32 operation)
{
	ctx->start_ns = 0;
	if (tracepoint_enabled(cis_alloc_step))
		__cis_alloc_start(ctx, cache, name, gfp, node, requested, operation);
}
static inline void cis_alloc_step(struct cis_alloc_ctx *ctx, u32 stage,
		void *object, void *resource, int node, unsigned long count)
{
	if (ctx && ctx->start_ns)
		__cis_alloc_step(ctx, stage, object, resource, node, count);
}
#else
static inline void cis_alloc_release(struct kmem_cache *cache, const char *name,
		void **objects, int count, unsigned long caller) { }
static inline void cis_alloc_start(struct cis_alloc_ctx *ctx,
		struct kmem_cache *cache, const char *name, unsigned long gfp,
		int node, unsigned long requested, u32 operation) { ctx->start_ns = 0; }
static inline void cis_alloc_step(struct cis_alloc_ctx *ctx, u32 stage,
		void *object, void *resource, int node, unsigned long count) { }
#endif
#endif
