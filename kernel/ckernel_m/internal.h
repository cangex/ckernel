/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CKM_INTERNAL_H
#define _CKM_INTERNAL_H
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/cpumask.h>
#include <linux/ckernel_m.h>
#include <linux/ckernel_m_vfs.h>
#include <linux/ckernel_m_security.h>
#include <linux/ckernel_m_fd.h>
#include <linux/ckernel_m_net.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/nodemask.h>
#include <linux/percpu.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
#include <uapi/linux/ckernel_m.h>

struct ckm_counters {
	u64 hits_cpu, hits_numa, misses, fallbacks, returned;
	u64 reasons[CKM_FB_COUNT];
	u64 bulk_calls, bulk_requested, bulk_completed, bulk_failed;
	u64 registered, alloc_failed, dispose_inactive, dispose_full;
};

struct ckm_instance {
	refcount_t refs;
	u64 cookie;
	u32 features, max_nodes;
	atomic_t state, tasks, mms, nodes;
	struct cgroup *cgroup;
	struct obj_cgroup *objcg;
	cpumask_var_t cpus;
	nodemask_t mems;
	struct ckm_counters __percpu *stats;
	struct work_struct revoke_work, release_work;
	struct xarray numa_pools;
	raw_spinlock_t records_lock;
	struct list_head records;
#ifdef CONFIG_CKERNEL_M_VFS
	struct ckm_vfs_state *vfs;
#endif
#ifdef CONFIG_CKERNEL_M_SECURITY
	struct ckm_security_state *security;
#endif
#ifdef CONFIG_CKERNEL_M_FD
	struct ckm_fd_pool *fd_pool;
#endif
#ifdef CONFIG_CKERNEL_M_NET
	struct ckm_net_state *net;
#endif
};

struct ckm_instance *ckm_create_instance(const struct ckm_create *req);
void ckm_get(struct ckm_instance *inst);
void ckm_put(struct ckm_instance *inst);
void ckm_revoke(struct ckm_instance *inst);
int ckm_bind_current(struct ckm_instance *inst);
int ckm_locality_init(struct ckm_instance *inst);
bool ckm_locality_compatible(struct ckm_instance *inst, int nid, gfp_t gfp);
enum ckm_fallback_reason ckm_locality_reason(struct ckm_instance *inst,
					    int nid, gfp_t gfp);
void ckm_query_instance(struct ckm_instance *inst, struct ckm_query *q);
void ckm_query_diagnostics(struct ckm_instance *inst, struct ckm_diagnostics *q);
static inline bool ckm_active(struct ckm_instance *inst)
{
	return atomic_read(&inst->state) == CKM_ACTIVE;
}
#ifdef CONFIG_CKERNEL_M_MAPLE
void ckm_maple_drain(struct ckm_instance *inst);
void ckm_maple_destroy(struct ckm_instance *inst);
void ckm_maple_snapshot(struct ckm_instance *inst, struct ckm_query *q);
#else
static inline void ckm_maple_drain(struct ckm_instance *i) {}
static inline void ckm_maple_destroy(struct ckm_instance *i) {}
static inline void ckm_maple_snapshot(struct ckm_instance *i, struct ckm_query *q) {}
#endif
#endif
