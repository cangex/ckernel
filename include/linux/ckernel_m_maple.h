/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CKERNEL_M_MAPLE_H
#define _LINUX_CKERNEL_M_MAPLE_H
#include <linux/maple_tree.h>
#include <linux/slab.h>

#ifdef CONFIG_CKERNEL_M_MAPLE
void *ckm_maple_alloc(struct maple_tree *mt, struct kmem_cache *cache, gfp_t gfp);
bool ckm_maple_free(void *node);
void ckm_maple_retire(void *node);
#else
static inline void *ckm_maple_alloc(struct maple_tree *mt,
				  struct kmem_cache *cache, gfp_t gfp)
{
	return kmem_cache_alloc(cache, gfp);
}
static inline bool ckm_maple_free(void *node) { return false; }
static inline void ckm_maple_retire(void *node) { }
#endif
#endif
