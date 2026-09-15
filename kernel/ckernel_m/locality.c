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

bool ckm_locality_compatible(struct ckm_instance *i, int nid, gfp_t gfp)
{
	bool same;

	if (!ckm_active(i) || current->ckm_instance != i ||
	    !cpumask_subset(current->cpus_ptr, i->cpus) ||
	    current->mempolicy || current->active_memcg ||
	    !node_isset(nid, i->mems) ||
	    !cpuset_node_allowed(nid, gfp))
		return false;
	rcu_read_lock();
	same = task_dfl_cgroup(current) == i->cgroup &&
		current_obj_cgroup() == i->objcg;
	rcu_read_unlock();
	return same;
}
