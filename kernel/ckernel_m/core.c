// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/slab.h>
#include "internal.h"
#define CREATE_TRACE_POINTS
#include <trace/events/ckernel_m.h>

static atomic64_t next_cookie = ATOMIC64_INIT(0);
static atomic_t instances = ATOMIC_INIT(0);

static void ckm_release_work(struct work_struct *work)
{
	struct ckm_instance *i = container_of(work, struct ckm_instance, release_work);

	WARN_ON(atomic_read(&i->tasks) || atomic_read(&i->mms) ||
		atomic_read(&i->nodes));
	ckm_maple_destroy(i);
	ckm_vfs_destroy(i);
	ckm_security_destroy(i);
	ckm_fd_destroy(i);
	atomic_set(&i->state, CKM_DEAD);
	trace_ckm_lifecycle(i->cookie, CKM_DEAD);
	if (i->objcg)
		obj_cgroup_put(i->objcg);
	cgroup_put(i->cgroup);
	free_cpumask_var(i->cpus);
	free_percpu(i->stats);
	atomic_dec(&instances);
	kfree(i);
}

void ckm_get(struct ckm_instance *i)
{
	refcount_inc(&i->refs);
}

void ckm_put(struct ckm_instance *i)
{
	if (refcount_dec_and_test(&i->refs))
		schedule_work(&i->release_work);
}

static void ckm_revoke_work(struct work_struct *work)
{
	struct ckm_instance *i = container_of(work, struct ckm_instance, revoke_work);

	atomic_set(&i->state, CKM_DRAINING);
	trace_ckm_lifecycle(i->cookie, CKM_DRAINING);
	ckm_maple_drain(i);
	ckm_vfs_drain(i);
	ckm_security_drain(i);
	ckm_fd_drain(i);
	ckm_put(i);
}

void ckm_revoke(struct ckm_instance *i)
{
	if (atomic_cmpxchg(&i->state, CKM_ACTIVE, CKM_REVOKING) != CKM_ACTIVE)
		return;
	ckm_get(i);
	trace_ckm_lifecycle(i->cookie, CKM_REVOKING);
	schedule_work(&i->revoke_work);
}

struct ckm_instance *ckm_create_instance(const struct ckm_create *r)
{
	struct ckm_instance *i;
	int ret = -ENOMEM;

	if (atomic_inc_return(&instances) > 256) {
		atomic_dec(&instances);
		return ERR_PTR(-ENOSPC);
	}
	i = kzalloc(sizeof(*i), GFP_KERNEL_ACCOUNT);
	if (!i)
		goto fail_count;
	i->stats = alloc_percpu_gfp(struct ckm_counters, GFP_KERNEL_ACCOUNT);
	if (!i->stats)
		goto fail_alloc;
	if (ckm_locality_init(i))
		goto fail_stats;
	rcu_read_lock();
	i->cgroup = task_dfl_cgroup(current);
	cgroup_get(i->cgroup);
	rcu_read_unlock();
	i->objcg = get_obj_cgroup_from_current();
	i->cookie = atomic64_inc_return(&next_cookie);
	i->features = r->features;
	i->max_nodes = r->max_nodes;
	refcount_set(&i->refs, 1);
	atomic_set(&i->state, CKM_ACTIVE);
	INIT_WORK(&i->revoke_work, ckm_revoke_work);
	INIT_WORK(&i->release_work, ckm_release_work);
	xa_init(&i->numa_pools);
	raw_spin_lock_init(&i->records_lock);
	INIT_LIST_HEAD(&i->records);
	ret = ckm_vfs_init(i);
	if (!ret)
		ret = ckm_security_init(i);
	if (!ret)
		ret = ckm_fd_init(i);
	if (ret) {
		ckm_security_drain(i);
		ckm_security_destroy(i);
		ckm_vfs_destroy(i);
		if (i->objcg)
			obj_cgroup_put(i->objcg);
		cgroup_put(i->cgroup);
		free_cpumask_var(i->cpus);
		goto fail_stats;
	}
	trace_ckm_lifecycle(i->cookie, CKM_ACTIVE);
	return i;
fail_stats:
	free_percpu(i->stats);
fail_alloc:
	kfree(i);
fail_count:
	atomic_dec(&instances);
	return ERR_PTR(ret);
}
