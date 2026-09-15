// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/ckernel_m_maple.h>
#include "internal.h"

#define CKM_BUCKET_BITS 12
#define CKM_CPU_OWNERS 4
#define CKM_CPU_NODES 2
#define CKM_NUMA_NODES 32
enum ckm_node_state { CKM_BORROWED, CKM_RETIRED, CKM_CACHED, CKM_RELEASED };

struct ckm_record {
	struct hlist_node index;
	struct list_head all, free;
	struct rcu_head rcu;
	struct ckm_instance *owner;
	struct kmem_cache *cache;
	void *node;
	gfp_t gfp;
	int nid, state;
	bool charged;
	bool poisoned;
};
struct ckm_bucket {
	raw_spinlock_t lock;
	struct hlist_head head;
};
struct ckm_cpu_slot {
	struct ckm_instance *owner;
	unsigned int nr;
	struct ckm_record *nodes[CKM_CPU_NODES];
};
struct ckm_cpu_pool {
	raw_spinlock_t lock;
	bool online;
	struct ckm_cpu_slot slots[CKM_CPU_OWNERS];
};
struct ckm_numa_pool {
	raw_spinlock_t lock;
	struct list_head free;
	unsigned int nr;
};
static struct ckm_bucket ckm_index[1 << CKM_BUCKET_BITS];
static DEFINE_PER_CPU(struct ckm_cpu_pool, ckm_cpu_pools);
static bool ckm_pools_ready;

static bool ckm_charge_matches(struct ckm_instance *i, void *object)
{
	struct mem_cgroup *actual, *expected;
	bool matches;

	rcu_read_lock();
	actual = mem_cgroup_from_slab_obj(object);
	expected = i->objcg ? obj_cgroup_memcg(i->objcg) : root_mem_cgroup;
	matches = actual == expected || (!actual && expected == root_mem_cgroup);
	rcu_read_unlock();
	return matches;
}

static struct ckm_bucket *ckm_bucket(void *node)
{
	return &ckm_index[hash_ptr(node, CKM_BUCKET_BITS)];
}

/* Caller holds RCU; owner and record outlive removal from this index. */
static struct ckm_record *ckm_find(void *node)
{
	struct ckm_record *r;

	hlist_for_each_entry_rcu(r, &ckm_bucket(node)->head, index)
		if (r->node == node)
			return r;
	return NULL;
}

static void ckm_record_release(struct rcu_head *head)
{
	struct ckm_record *r = container_of(head, struct ckm_record, rcu);
	struct ckm_instance *i = r->owner;
	unsigned long flags;

	raw_spin_lock_irqsave(&i->records_lock, flags);
	list_del(&r->all);
	raw_spin_unlock_irqrestore(&i->records_lock, flags);
	atomic_dec(&i->nodes);
	kfree(r);
	ckm_put(i);
}

/* No pool lock is held here; this is at the original safe release boundary. */
static void ckm_dispose(struct ckm_record *r)
{
	struct ckm_bucket *b = ckm_bucket(r->node);
	unsigned long flags;

	WRITE_ONCE(r->state, CKM_RELEASED);
	raw_spin_lock_irqsave(&b->lock, flags);
	hlist_del_rcu(&r->index);
	raw_spin_unlock_irqrestore(&b->lock, flags);
	if (r->poisoned)
		kasan_unpoison_range(r->node, sizeof(struct maple_node));
	if (r->charged)
		obj_cgroup_uncharge(r->owner->objcg, sizeof(struct maple_node));
	kmem_cache_free(r->cache, r->node);
	call_rcu(&r->rcu, ckm_record_release);
}

static struct ckm_numa_pool *ckm_numa_get(struct ckm_instance *i, int nid)
{
	struct ckm_numa_pool *p, *old;

	p = xa_load(&i->numa_pools, nid);
	if (p)
		return p;
	p = kzalloc_node(sizeof(*p), GFP_KERNEL_ACCOUNT, nid);
	if (!p)
		return NULL;
	if (!ckm_charge_matches(i, p)) {
		kfree(p);
		return NULL;
	}
	raw_spin_lock_init(&p->lock);
	INIT_LIST_HEAD(&p->free);
	old = xa_cmpxchg(&i->numa_pools, nid, NULL, p, GFP_KERNEL_ACCOUNT);
	if (old) {
		kfree(p);
		return xa_is_err(old) ? NULL : old;
	}
	return p;
}

static bool ckm_match(struct ckm_record *r, struct ckm_instance *i,
		      struct kmem_cache *cache, gfp_t gfp, int nid)
{
	return r->owner == i && r->cache == cache && r->nid == nid &&
		(r->gfp & ~__GFP_ZERO) == (gfp & ~__GFP_ZERO);
}

static struct ckm_record *ckm_cpu_take(struct ckm_instance *i,
				       struct kmem_cache *cache, gfp_t gfp, int nid)
{
	struct ckm_cpu_pool *p;
	struct ckm_record *r = NULL;
	unsigned long flags;
	unsigned int s, n;

	preempt_disable();
	p = this_cpu_ptr(&ckm_cpu_pools);
	raw_spin_lock_irqsave(&p->lock, flags);
	if (p->online && ckm_active(i))
		for (s = 0; s < CKM_CPU_OWNERS && !r; s++) {
			struct ckm_cpu_slot *slot = &p->slots[s];

			if (slot->owner != i)
				continue;
			for (n = 0; n < slot->nr; n++)
				if (ckm_match(slot->nodes[n], i, cache, gfp, nid)) {
					r = slot->nodes[n];
					slot->nodes[n] = slot->nodes[--slot->nr];
					if (!slot->nr)
						slot->owner = NULL;
					WRITE_ONCE(r->state, CKM_BORROWED);
					this_cpu_inc(i->stats->hits_cpu);
					break;
				}
		}
	raw_spin_unlock_irqrestore(&p->lock, flags);
	preempt_enable();
	return r;
}

static bool ckm_cpu_return(struct ckm_record *r)
{
	struct ckm_cpu_pool *p;
	unsigned int s;
	int available = -1;
	unsigned long flags;
	bool done = false;

	preempt_disable();
	p = this_cpu_ptr(&ckm_cpu_pools);
	raw_spin_lock_irqsave(&p->lock, flags);
	if (p->online && r->nid == numa_node_id() && ckm_active(r->owner)) {
		for (s = 0; s < CKM_CPU_OWNERS; s++) {
			struct ckm_cpu_slot *slot = &p->slots[s];

			if (slot->owner == r->owner) {
				available = slot->nr < CKM_CPU_NODES ? s : -1;
				break;
			}
			if (!slot->owner && available < 0)
				available = s;
		}
		if (available >= 0) {
			struct ckm_cpu_slot *slot = &p->slots[available];

			slot->owner = r->owner;
			slot->nodes[slot->nr++] = r;
			WRITE_ONCE(r->state, CKM_CACHED);
			done = true;
		}
	}
	raw_spin_unlock_irqrestore(&p->lock, flags);
	preempt_enable();
	return done;
}

static struct ckm_record *ckm_numa_take(struct ckm_instance *i,
					struct kmem_cache *cache, gfp_t gfp, int nid)
{
	struct ckm_numa_pool *p = xa_load(&i->numa_pools, nid);
	struct ckm_record *r, *found = NULL;
	unsigned long flags;

	if (!p)
		return NULL;
	raw_spin_lock_irqsave(&p->lock, flags);
	if (ckm_active(i))
		list_for_each_entry(r, &p->free, free)
			if (ckm_match(r, i, cache, gfp, nid)) {
				list_del_init(&r->free);
				p->nr--;
				WRITE_ONCE(r->state, CKM_BORROWED);
				found = r;
				break;
			}
	raw_spin_unlock_irqrestore(&p->lock, flags);
	if (found) {
		preempt_disable();
		this_cpu_inc(i->stats->hits_numa);
		preempt_enable();
	}
	return found;
}

static bool ckm_numa_return(struct ckm_record *r)
{
	struct ckm_numa_pool *p = xa_load(&r->owner->numa_pools, r->nid);
	unsigned long flags;
	bool done = false;

	if (!p)
		return false;
	raw_spin_lock_irqsave(&p->lock, flags);
	if (ckm_active(r->owner) && p->nr < CKM_NUMA_NODES) {
		list_add(&r->free, &p->free);
		p->nr++;
		WRITE_ONCE(r->state, CKM_CACHED);
		done = true;
	}
	raw_spin_unlock_irqrestore(&p->lock, flags);
	return done;
}

void *ckm_maple_alloc(struct maple_tree *mt, struct kmem_cache *cache, gfp_t gfp)
{
	struct ckm_instance *i = mt->ma_ckm_owner;
	struct ckm_record *r;
	struct ckm_bucket *b;
	unsigned long flags;
	void *node;
	int nid = numa_node_id();
	bool charged = false;

	/* Narrow GFP contract: unsupported policies use the unchanged allocator. */
	if (!READ_ONCE(ckm_pools_ready) || !i ||
	    (gfp & ~(__GFP_ZERO | __GFP_ACCOUNT)) != GFP_KERNEL ||
	    !ckm_locality_compatible(i, nid, gfp))
		goto native;
	r = ckm_cpu_take(i, cache, gfp, nid);
	if (!r)
		r = ckm_numa_take(i, cache, gfp, nid);
	if (r) {
		kasan_unpoison_range(r->node, sizeof(struct maple_node));
		r->poisoned = false;
		/* Conservatively honor allocation/free initialization hardening. */
		memset(r->node, 0, sizeof(struct maple_node));
		return r->node;
	}
	preempt_disable();
	this_cpu_inc(i->stats->misses);
	preempt_enable();
	if (atomic_inc_return(&i->nodes) > i->max_nodes) {
		atomic_dec(&i->nodes);
		goto native;
	}
	r = kzalloc(sizeof(*r), GFP_KERNEL_ACCOUNT);
	if (!r)
		goto unreserve;
	if (!ckm_charge_matches(i, r))
		goto free_record;
	if (!ckm_numa_get(i, nid))
		goto free_record;
	/* Existing accounted SLUB objects keep their original charge. */
	if (!(gfp & __GFP_ACCOUNT) && i->objcg) {
		if (obj_cgroup_charge(i->objcg, GFP_KERNEL, sizeof(struct maple_node)))
			goto free_record;
		charged = true;
	}
	node = kmem_cache_alloc(cache, gfp);
	if (!node) {
		if (charged)
			obj_cgroup_uncharge(i->objcg, sizeof(struct maple_node));
		kfree(r);
		atomic_dec(&i->nodes);
		return NULL;
	}
	if (page_to_nid(virt_to_page(node)) != nid ||
	    !ckm_locality_compatible(i, nid, gfp) ||
	    ((gfp & __GFP_ACCOUNT) && !ckm_charge_matches(i, node))) {
		if (charged)
			obj_cgroup_uncharge(i->objcg, sizeof(struct maple_node));
		kfree(r);
		atomic_dec(&i->nodes);
		return node;
	}
	r->owner = i;
	r->node = node;
	r->cache = cache;
	r->nid = nid;
	r->gfp = gfp;
	r->charged = charged;
	INIT_LIST_HEAD(&r->free);
	ckm_get(i);
	raw_spin_lock_irqsave(&i->records_lock, flags);
	list_add(&r->all, &i->records);
	raw_spin_unlock_irqrestore(&i->records_lock, flags);
	b = ckm_bucket(node);
	raw_spin_lock_irqsave(&b->lock, flags);
	hlist_add_head_rcu(&r->index, &b->head);
	raw_spin_unlock_irqrestore(&b->lock, flags);
	return node;
free_record:
	kfree(r);
unreserve:
	atomic_dec(&i->nodes);
native:
	if (i) {
		preempt_disable();
		this_cpu_inc(i->stats->fallbacks);
		preempt_enable();
	}
	return kmem_cache_alloc(cache, gfp);
}

bool ckm_maple_free(void *node)
{
	struct ckm_record *r;

	if (!READ_ONCE(ckm_pools_ready))
		return false;
	rcu_read_lock();
	r = ckm_find(node);
	if (r) {
		preempt_disable();
		this_cpu_inc(r->owner->stats->returned);
		preempt_enable();
		memset(r->node, 0, sizeof(struct maple_node));
		kasan_slab_free_mempool(r->node);
		r->poisoned = true;
		if (!ckm_cpu_return(r) && !ckm_numa_return(r))
			ckm_dispose(r);
	}
	rcu_read_unlock();
	return !!r;
}

void ckm_maple_retire(void *node)
{
	struct ckm_record *r;

	if (!READ_ONCE(ckm_pools_ready))
		return;
	rcu_read_lock();
	r = ckm_find(node);
	if (r)
		WRITE_ONCE(r->state, CKM_RETIRED);
	rcu_read_unlock();
}

static void ckm_drain_cpu(unsigned int cpu, struct ckm_instance *owner)
{
	struct ckm_cpu_pool *p = per_cpu_ptr(&ckm_cpu_pools, cpu);
	struct ckm_record *nodes[CKM_CPU_OWNERS * CKM_CPU_NODES];
	unsigned int s, nr = 0;
	unsigned long flags;

	raw_spin_lock_irqsave(&p->lock, flags);
	for (s = 0; s < CKM_CPU_OWNERS; s++)
		if (!owner || p->slots[s].owner == owner) {
			while (p->slots[s].nr)
				nodes[nr++] = p->slots[s].nodes[--p->slots[s].nr];
			p->slots[s].owner = NULL;
		}
	raw_spin_unlock_irqrestore(&p->lock, flags);
	while (nr) {
		struct ckm_record *r = nodes[--nr];

		if (owner || !ckm_numa_return(r))
			ckm_dispose(r);
	}
}

void ckm_maple_drain(struct ckm_instance *i)
{
	struct ckm_numa_pool *p;
	struct ckm_record *r;
	unsigned int cpu;
	unsigned long nid, flags;

	for_each_possible_cpu(cpu) {
		ckm_drain_cpu(cpu, i);
		cond_resched();
	}
	xa_for_each(&i->numa_pools, nid, p) {
		for (;;) {
			raw_spin_lock_irqsave(&p->lock, flags);
			r = list_first_entry_or_null(&p->free, struct ckm_record, free);
			if (r) {
				list_del_init(&r->free);
				p->nr--;
			}
			raw_spin_unlock_irqrestore(&p->lock, flags);
			if (!r)
				break;
			ckm_dispose(r);
			cond_resched();
		}
	}
}

void ckm_maple_destroy(struct ckm_instance *i)
{
	struct ckm_numa_pool *p;
	unsigned long nid;

	WARN_ON(!list_empty(&i->records));
	xa_for_each(&i->numa_pools, nid, p) {
		WARN_ON(p->nr);
		kfree(p);
	}
	xa_destroy(&i->numa_pools);
}

void ckm_maple_snapshot(struct ckm_instance *i, struct ckm_query *q)
{
	struct ckm_record *r;
	struct ckm_numa_pool *p;
	unsigned long nid;
	unsigned long flags;

	raw_spin_lock_irqsave(&i->records_lock, flags);
	list_for_each_entry(r, &i->records, all) {
		int state = READ_ONCE(r->state);

		q->metadata_bytes += sizeof(*r);
		if (state != CKM_RELEASED)
			q->node_bytes += sizeof(struct maple_node);
		if (state == CKM_CACHED)
			q->cached++;
		else if (state == CKM_BORROWED)
			q->borrowed++;
		else if (state == CKM_RETIRED)
			q->retired++;
		else
			q->pending_metadata++;
	}
	raw_spin_unlock_irqrestore(&i->records_lock, flags);
	xa_for_each(&i->numa_pools, nid, p)
		q->metadata_bytes += sizeof(*p);
}

static int ckm_cpu_offline(unsigned int cpu)
{
	struct ckm_cpu_pool *p = per_cpu_ptr(&ckm_cpu_pools, cpu);
	unsigned long flags;

	raw_spin_lock_irqsave(&p->lock, flags);
	p->online = false;
	raw_spin_unlock_irqrestore(&p->lock, flags);
	ckm_drain_cpu(cpu, NULL);
	return 0;
}

static int ckm_cpu_online(unsigned int cpu)
{
	struct ckm_cpu_pool *p = per_cpu_ptr(&ckm_cpu_pools, cpu);
	unsigned long flags;

	raw_spin_lock_irqsave(&p->lock, flags);
	p->online = true;
	raw_spin_unlock_irqrestore(&p->lock, flags);
	return 0;
}

static int __init ckm_maple_init(void)
{
	unsigned int cpu, n;
	int ret;

	for (n = 0; n < ARRAY_SIZE(ckm_index); n++) {
		raw_spin_lock_init(&ckm_index[n].lock);
		INIT_HLIST_HEAD(&ckm_index[n].head);
	}
	for_each_possible_cpu(cpu)
		raw_spin_lock_init(&per_cpu_ptr(&ckm_cpu_pools, cpu)->lock);
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
		"ckernel_m/maple:online", ckm_cpu_online, ckm_cpu_offline);
	if (ret < 0)
		return ret;
	WRITE_ONCE(ckm_pools_ready, true);
	return 0;
}
subsys_initcall(ckm_maple_init);
