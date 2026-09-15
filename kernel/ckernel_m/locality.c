// SPDX-License-Identifier: GPL-2.0
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/sched.h>
#include "internal.h"

int ckm_locality_init(struct ckm_instance *i)
{
	if (!zalloc_cpumask_var(&i->cpus, GFP_KERNEL_ACCOUNT))
		return -ENOMEM;
	task_lock(current);
	cpumask_copy(i->cpus, current->cpus_ptr);
	i->mems = current->mems_allowed;
	task_unlock(current);
	return 0;
}

enum ckm_fallback_reason ckm_locality_reason(struct ckm_instance *i,
					    int nid, gfp_t gfp)
{
	enum ckm_fallback_reason reason = CKM_FB_NONE;

	if (!ckm_active(i))
		return CKM_FB_INACTIVE;
	if (current->ckm_instance != i)
		return CKM_FB_TASK_OWNER;
	if (!cpumask_subset(current->cpus_ptr, i->cpus))
		return CKM_FB_CPU_MASK;
	if (current->mempolicy)
		return CKM_FB_MEMPOLICY;
	if (current->active_memcg)
		return CKM_FB_ACTIVE_MEMCG;
	if (!node_isset(nid, i->mems))
		return CKM_FB_NODE_MASK;
	if (!cpuset_node_allowed(nid, gfp))
		return CKM_FB_CPUSET;
	rcu_read_lock();
	if (task_dfl_cgroup(current) != i->cgroup)
		reason = CKM_FB_CGROUP;
	else if (current_obj_cgroup() != i->objcg)
		reason = CKM_FB_OBJCG;
	rcu_read_unlock();
	return reason;
}

bool ckm_locality_compatible(struct ckm_instance *i, int nid, gfp_t gfp)
{
	return ckm_locality_reason(i, nid, gfp) == CKM_FB_NONE;
}
