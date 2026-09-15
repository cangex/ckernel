// SPDX-License-Identifier: GPL-2.0
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include "internal.h"

int ckm_bind_current(struct ckm_instance *i)
{
	bool same;

	if (!ckm_active(i))
		return -ESHUTDOWN;
	if (current->ckm_instance || !current->mm ||
	    !thread_group_empty(current) || atomic_read(&current->mm->mm_users) != 1 ||
	    !current->files || atomic_read(&current->files->count) != 1)
		return -EBUSY;
	rcu_read_lock();
	same = task_dfl_cgroup(current) == i->cgroup;
	rcu_read_unlock();
	if (!same || !cpumask_subset(current->cpus_ptr, i->cpus))
		return -EXDEV;
	ckm_get(i);
	atomic_inc(&i->tasks);
	WRITE_ONCE(current->ckm_instance, i);
	/* Existing mm retains its original allocator until exec or fork. */
	return 0;
}

void ckm_task_fork(struct task_struct *task, struct task_struct *parent)
{
	struct ckm_instance *i = READ_ONCE(parent->ckm_instance);

	task->ckm_instance = i;
	if (i) {
		ckm_get(i);
		atomic_inc(&i->tasks);
	}
}

void ckm_task_free(struct task_struct *task)
{
	struct ckm_instance *i = task->ckm_instance;

	if (!i)
		return;
	task->ckm_instance = NULL;
	if (atomic_dec_and_test(&i->tasks))
		ckm_revoke(i);
	ckm_put(i);
}

void ckm_mm_init(struct mm_struct *mm, struct task_struct *task)
{
#ifdef CONFIG_CKERNEL_M_MAPLE
	struct ckm_instance *i = READ_ONCE(task->ckm_instance);

	if (!i || !ckm_active(i) || !(i->features & CKM_FEATURE_MAPLE))
		return;
	ckm_get(i);
	atomic_inc(&i->mms);
	mm->mm_mt.ma_ckm_owner = i;
#endif
}

void ckm_mm_exit(struct mm_struct *mm)
{
#ifdef CONFIG_CKERNEL_M_MAPLE
	struct ckm_instance *i = mm->mm_mt.ma_ckm_owner;

	if (!i)
		return;
	/* Tree contents are gone; outstanding nodes carry independent refs. */
	mm->mm_mt.ma_ckm_owner = NULL;
	atomic_dec(&i->mms);
	ckm_put(i);
#endif
}
