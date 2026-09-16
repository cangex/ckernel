// SPDX-License-Identifier: GPL-2.0
#include <linux/interrupt.h>
#include <linux/page_counter.h>
#include <linux/slab.h>
#include "internal.h"

struct ckm_fd_stats {
	u64 local_alloc, local_free, native_alloc, refill, rescue, drained, contended;
};

struct ckm_fd_pool {
	struct ckm_instance *owner;
	struct cgroup_subsys_state *css;
	struct page_counter *counter;
	struct list_head registry;
	spinlock_t lock;
	unsigned int idle;
	bool frozen, stopped;
	struct ckm_fd_stats __percpu *stats;
};

/* No successful local operation acquires this coordination lock. */
static DEFINE_SPINLOCK(control_lock);
static LIST_HEAD(pools);
static unsigned int freeze_depth;
static bool accounting_disabled;

static struct ckm_fd_pool *current_pool(struct page_counter *counter)
{
	struct ckm_instance *i = READ_ONCE(current->ckm_instance);
	struct ckm_fd_pool *p;
	bool same;

	if (!i || !ckm_active(i) || current->flags & PF_KTHREAD || in_interrupt())
		return NULL;
	p = i->fd_pool;
	if (!p || p->counter != counter)
		return NULL;
	rcu_read_lock();
	same = task_dfl_cgroup(current) == i->cgroup;
	rcu_read_unlock();
	return same ? p : NULL;
}

static void freeze_all(void)
{
	struct ckm_fd_pool *p;

	lockdep_assert_held(&control_lock);
	list_for_each_entry(p, &pools, registry) {
		spin_lock(&p->lock);
		p->frozen = true;
		if (p->idle) {
			this_cpu_add(p->stats->drained, p->idle);
			page_counter_uncharge(p->counter, p->idle);
			p->idle = 0;
		}
		spin_unlock(&p->lock);
	}
}

static void thaw_all(void)
{
	struct ckm_fd_pool *p;

	lockdep_assert_held(&control_lock);
	list_for_each_entry(p, &pools, registry) {
		spin_lock(&p->lock);
		p->frozen = false;
		spin_unlock(&p->lock);
	}
}

unsigned long ckm_fd_quiesce_begin(void)
{
	unsigned long flags;

	spin_lock_irqsave(&control_lock, flags);
	freeze_depth++;
	freeze_all();
	return flags;
}

void ckm_fd_quiesce_end(unsigned long flags)
{
	if (!--freeze_depth)
		thaw_all();
	spin_unlock_irqrestore(&control_lock, flags);
}

int ckm_fd_set_max(struct page_counter *counter, unsigned long maximum)
{
	unsigned long flags = ckm_fd_quiesce_begin();
	int ret;

	/* page_counter_set_max may cond_resched: retain only the freeze, not a lock. */
	spin_unlock_irqrestore(&control_lock, flags);
	ret = page_counter_set_max(counter, maximum);
	spin_lock_irqsave(&control_lock, flags);
	ckm_fd_quiesce_end(flags);
	return ret;
}

void ckm_fd_disable_locked(void)
{
	struct ckm_fd_pool *p;

	lockdep_assert_held(&control_lock);
	accounting_disabled = true;
	list_for_each_entry(p, &pools, registry) {
		spin_lock(&p->lock);
		p->stopped = true;
		spin_unlock(&p->lock);
	}
}

static bool native_charge(struct page_counter *counter, unsigned long n,
			  struct ckm_fd_pool *p)
{
	struct page_counter *fail;
	unsigned long flags;
	bool ok;

	if (p)
		this_cpu_add(p->stats->native_alloc, n);
	if (page_counter_try_charge(counter, n, &fail))
		return true;
	/* A nonparticipant must also reclaim siblings' idle reservations. */
	flags = ckm_fd_quiesce_begin();
	if (p)
		this_cpu_inc(p->stats->rescue);
	ok = page_counter_try_charge(counter, n, &fail);
	ckm_fd_quiesce_end(flags);
	return ok;
}

bool ckm_fd_alloc(struct page_counter *counter, unsigned long n)
{
	struct ckm_fd_pool *p = current_pool(counter);
	struct page_counter *fail;
	unsigned long flags;
	bool ok = false;

	if (!n)
		return true;
	if (!p || n > CKM_FD_MAX_IDLE)
		return native_charge(counter, n, p);
	local_irq_save(flags);
	if (!spin_trylock(&p->lock)) {
		this_cpu_inc(p->stats->contended);
		local_irq_restore(flags);
		return native_charge(counter, n, p);
	}
	if (!p->stopped && !p->frozen && ckm_active(p->owner) && p->idle >= n) {
		p->idle -= n;
		this_cpu_add(p->stats->local_alloc, n);
		ok = true;
	}
	spin_unlock(&p->lock);
	local_irq_restore(flags);
	if (ok)
		return true;
	/* Only single-FD allocation refills. Fork/bulk charges stay native. */
	if (n != 1)
		return native_charge(counter, n, p);
	spin_lock_irqsave(&control_lock, flags);
	spin_lock(&p->lock);
	if (!p->stopped && !p->frozen && ckm_active(p->owner)) {
		if (p->idle) {
			p->idle--;
			ok = true;
		} else if (page_counter_try_charge(counter, CKM_FD_MAX_IDLE, &fail)) {
			p->idle = CKM_FD_MAX_IDLE - 1;
			this_cpu_inc(p->stats->refill);
			ok = true;
		}
		if (ok)
			this_cpu_inc(p->stats->local_alloc);
	}
	spin_unlock(&p->lock);
	spin_unlock_irqrestore(&control_lock, flags);
	return ok || native_charge(counter, n, p);
}

bool ckm_fd_free(struct page_counter *counter, unsigned long n)
{
	struct ckm_fd_pool *p = current_pool(counter);
	unsigned long flags;
	bool cached = false;

	if (!n)
		return true;
	if (!p || n > CKM_FD_MAX_IDLE)
		return false;
	local_irq_save(flags);
	if (!spin_trylock(&p->lock)) {
		this_cpu_inc(p->stats->contended);
		local_irq_restore(flags);
		return false;
	}
	if (!p->stopped && !p->frozen && ckm_active(p->owner) &&
	    n <= CKM_FD_MAX_IDLE - p->idle) {
		p->idle += n;
		this_cpu_add(p->stats->local_free, n);
		cached = true;
	}
	spin_unlock(&p->lock);
	local_irq_restore(flags);
	return cached;
}

int ckm_fd_register(struct ckm_instance *i, struct cgroup_subsys_state *css,
		    struct page_counter *counter)
{
	struct ckm_fd_pool *p, *other;
	unsigned long flags;
	int ret = 0;

	p = kzalloc(sizeof(*p), GFP_KERNEL_ACCOUNT);
	if (!p)
		return -ENOMEM;
	p->stats = alloc_percpu_gfp(struct ckm_fd_stats, GFP_KERNEL_ACCOUNT);
	if (!p->stats) {
		kfree(p);
		return -ENOMEM;
	}
	p->owner = i;
	p->css = css;
	p->counter = counter;
	spin_lock_init(&p->lock);
	spin_lock_irqsave(&control_lock, flags);
	if (accounting_disabled) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}
	list_for_each_entry(other, &pools, registry) {
		if (other->counter == counter) {
			ret = -EBUSY;
			goto unlock;
		}
	}
	css_get(css);
	p->frozen = freeze_depth != 0;
	list_add_tail(&p->registry, &pools);
	i->fd_pool = p;
unlock:
	spin_unlock_irqrestore(&control_lock, flags);
	if (ret) {
		free_percpu(p->stats);
		kfree(p);
	}
	return ret;
}

int ckm_fd_init(struct ckm_instance *i)
{
	return i->features & CKM_FEATURE_FD ? files_cgroup_ckm_prepare(i) : 0;
}

void ckm_fd_drain(struct ckm_instance *i)
{
	struct ckm_fd_pool *p = i->fd_pool;
	unsigned long flags;

	if (!p)
		return;
	spin_lock_irqsave(&control_lock, flags);
	spin_lock(&p->lock);
	p->stopped = true;
	if (p->idle) {
		this_cpu_add(p->stats->drained, p->idle);
		page_counter_uncharge(p->counter, p->idle);
		p->idle = 0;
	}
	list_del_init(&p->registry);
	spin_unlock(&p->lock);
	spin_unlock_irqrestore(&control_lock, flags);
}

void ckm_fd_destroy(struct ckm_instance *i)
{
	struct ckm_fd_pool *p = i->fd_pool;

	if (!p)
		return;
	WARN_ON(p->idle || !list_empty(&p->registry));
	css_put(p->css);
	free_percpu(p->stats);
	kfree(p);
}

void ckm_fd_query(struct ckm_instance *i, struct ckm_fd_query *q)
{
	struct ckm_fd_pool *p = i->fd_pool;
	unsigned long flags;
	int cpu;

	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	if (!p)
		return;
	q->capacity = CKM_FD_MAX_IDLE;
	q->management_bytes = sizeof(*p) + num_possible_cpus() * sizeof(*p->stats);
	spin_lock_irqsave(&p->lock, flags);
	q->idle = p->idle;
	q->stopped = p->stopped;
	spin_unlock_irqrestore(&p->lock, flags);
	for_each_possible_cpu(cpu) {
		struct ckm_fd_stats *s = per_cpu_ptr(p->stats, cpu);
#define SUM(field) q->field += READ_ONCE(s->field)
		SUM(local_alloc); SUM(local_free); SUM(native_alloc); SUM(refill);
		SUM(rescue); SUM(drained); SUM(contended);
#undef SUM
	}
}
