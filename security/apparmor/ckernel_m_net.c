// SPDX-License-Identifier: GPL-2.0
#include <linux/ckernel_m_net.h>
#include <linux/hash.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include "include/cred.h"
#include "include/net.h"
#include "include/policy.h"
#include "../../kernel/ckernel_m/internal.h"

#define CKM_NET_BUCKET_BITS 4
#define CKM_NET_BUCKETS (1U << CKM_NET_BUCKET_BITS)
enum record_state { RECORD_FREE, RECORD_LIVE, RECORD_RETIRING };

struct ckm_net_record {
	struct hlist_node hash;
	struct rcu_head rcu;
	struct ckm_net_state *state;
	const struct sock *sk;
	const struct cred *cred;
	struct aa_label *label;
	enum record_state status;
	bool unmediated;
};

struct ckm_net_stats {
	u64 created, cloned, released, send_hits, recv_hits;
	u64 native, missing, subject, stale, mediated, full, contended;
	u64 owner_search_steps;
};

struct ckm_net_state {
	struct ckm_instance *owner;
	struct list_head registry;
	spinlock_t lock;
	bool stopped;
	unsigned int live, retiring;
	struct hlist_head buckets[CKM_NET_BUCKETS];
	struct ckm_net_record records[CKM_NET_MAX_SOCKETS];
	struct ckm_net_stats __percpu *stats;
};

/* Only enrollment/final destruction take this lock, never a socket operation. */
static DEFINE_MUTEX(registry_lock);
static LIST_HEAD(registry);

static bool supported(const struct sock *sk)
{
	return sk && (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
		(sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_DGRAM);
}

static struct ckm_net_state *current_state(void)
{
	struct ckm_instance *i = READ_ONCE(current->ckm_instance);
	bool same;

	if (!i || !ckm_active(i) || !i->net || in_interrupt() ||
	    current->flags & PF_KTHREAD)
		return NULL;
	rcu_read_lock();
	same = task_dfl_cgroup(current) == i->cgroup;
	rcu_read_unlock();
	return same ? i->net : NULL;
}

static struct hlist_head *bucket(struct ckm_net_state *s, const struct sock *sk)
{
	return &s->buckets[hash_ptr(sk, CKM_NET_BUCKET_BITS)];
}

static struct ckm_net_record *lookup(struct ckm_net_state *s, const struct sock *sk)
{
	struct ckm_net_record *e;

	hlist_for_each_entry_rcu(e, bucket(s, sk), hash)
		if (e->sk == sk)
			return e;
	return NULL;
}

static bool unmediated(struct aa_label *label)
{
	struct aa_profile *profile;
	struct label_it it;

	/* Match aa_profile_af_perm's first-ruleset early return, not signal policy. */
	label_for_each(it, label, profile) {
		struct aa_ruleset *rules = list_first_entry(&profile->rules,
							  struct aa_ruleset, list);
		if (!profile_unconfined(profile) && RULE_MEDIATES(rules, AA_CLASS_NET))
			return false;
	}
	return true;
}

static void record_socket(struct ckm_net_state *s, struct sock *sk,
			  const struct cred *cred, struct aa_label *label,
			  bool qualified, bool clone)
{
	struct ckm_net_record *e = NULL;
	unsigned long flags;
	unsigned int n;

	local_irq_save(flags);
	if (!spin_trylock(&s->lock)) {
		this_cpu_inc(s->stats->contended);
		local_irq_restore(flags);
		return;
	}
	if (s->stopped || !ckm_active(s->owner))
		goto unlock;
	for (n = 0; n < CKM_NET_MAX_SOCKETS; n++) {
		if (s->records[n].status == RECORD_FREE) {
			e = &s->records[n];
			break;
		}
	}
	if (!e) {
		this_cpu_inc(s->stats->full);
		goto unlock;
	}
	ckm_get(s->owner);
	e->sk = sk;
	e->cred = get_cred(cred);
	e->label = aa_get_label(label);
	e->unmediated = qualified;
	e->status = RECORD_LIVE;
	s->live++;
	hlist_add_head_rcu(&e->hash, bucket(s, sk));
	if (clone)
		this_cpu_inc(s->stats->cloned);
	else
		this_cpu_inc(s->stats->created);
unlock:
	spin_unlock(&s->lock);
	local_irq_restore(flags);
}

void aa_ckm_net_created(struct sock *sk)
{
	struct ckm_net_state *s = current_state();
	struct aa_label *label;

	if (!s || !supported(sk) || current_cred() != current_real_cred())
		return;
	label = __begin_current_label_crit_section();
	record_socket(s, sk, current_cred(), label, unmediated(label), false);
	__end_current_label_crit_section(label);
}

void aa_ckm_net_clone(const struct sock *old, struct sock *new)
{
	struct ckm_net_state *s;
	struct ckm_net_record *e;
	unsigned int steps = 0;

	if (!supported(old) || !supported(new))
		return;
	rcu_read_lock();
	list_for_each_entry_rcu(s, &registry, registry) {
		steps++;
		e = lookup(s, old);
		if (!e)
			continue;
		/* Native clone pins old; its LIVE ownership record cannot disappear. */
		this_cpu_add(s->stats->owner_search_steps, steps);
		record_socket(s, new, e->cred, e->label, e->unmediated, true);
		break;
	}
	rcu_read_unlock();
}

static void release_record(struct rcu_head *rcu)
{
	struct ckm_net_record *e = container_of(rcu, struct ckm_net_record, rcu);
	struct ckm_net_state *s = e->state;
	struct ckm_instance *owner = s->owner;
	unsigned long flags;

	aa_put_label(e->label);
	put_cred(e->cred);
	spin_lock_irqsave(&s->lock, flags);
	e->label = NULL;
	e->cred = NULL;
	e->sk = NULL;
	e->status = RECORD_FREE;
	s->retiring--;
	this_cpu_inc(s->stats->released);
	spin_unlock_irqrestore(&s->lock, flags);
	/* The slot can be reused now; no subsequent access to e is permitted. */
	ckm_put(owner);
}

void aa_ckm_net_free(struct sock *sk)
{
	struct ckm_net_state *s;
	struct ckm_net_record *e;
	unsigned long flags;
	unsigned int steps = 0;

	if (!supported(sk))
		return;
	rcu_read_lock();
	list_for_each_entry_rcu(s, &registry, registry) {
		steps++;
		e = lookup(s, sk);
		if (!e)
			continue;
		spin_lock_irqsave(&s->lock, flags);
		/* Native final free owns this sk; no second final free may race it. */
		WARN_ON_ONCE(e->status != RECORD_LIVE);
		hlist_del_rcu(&e->hash);
		e->status = RECORD_RETIRING;
		s->live--;
		s->retiring++;
		this_cpu_add(s->stats->owner_search_steps, steps);
		spin_unlock_irqrestore(&s->lock, flags);
		call_rcu(&e->rcu, release_record);
		break;
	}
	rcu_read_unlock();
}

bool aa_ckm_net_allowed(struct sock *sk, u32 request)
{
	struct ckm_net_state *s;
	struct ckm_net_record *e;
	struct aa_label *label;
	bool allow = false;

	if ((request != AA_MAY_SEND && request != AA_MAY_RECEIVE) || !supported(sk))
		return false;
	s = current_state();
	if (!s)
		return false;
	rcu_read_lock();
	e = lookup(s, sk);
	if (!e) {
		this_cpu_inc(s->stats->missing);
		goto out;
	}
	if (e->cred != current_cred() || current_cred() != current_real_cred() ||
	    current->nsproxy->net_ns != sock_net(sk)) {
		this_cpu_inc(s->stats->subject);
		goto out;
	}
	label = aa_current_raw_label();
	if (label != e->label || label_is_stale(label)) {
		this_cpu_inc(s->stats->stale);
		goto out;
	}
	if (!e->unmediated) {
		this_cpu_inc(s->stats->mediated);
		goto out;
	}
	allow = !READ_ONCE(s->stopped) && ckm_active(s->owner);
out:
	if (!allow)
		this_cpu_inc(s->stats->native);
	else if (request == AA_MAY_SEND)
		this_cpu_inc(s->stats->send_hits);
	else
		this_cpu_inc(s->stats->recv_hits);
	rcu_read_unlock();
	return allow;
}

int ckm_net_init(struct ckm_instance *i)
{
	struct ckm_net_state *s;
	unsigned int n;

	if (!(i->features & CKM_FEATURE_NET))
		return 0;
	s = kzalloc(sizeof(*s), GFP_KERNEL_ACCOUNT);
	if (!s)
		return -ENOMEM;
	s->stats = alloc_percpu_gfp(struct ckm_net_stats, GFP_KERNEL_ACCOUNT);
	if (!s->stats) {
		kfree(s);
		return -ENOMEM;
	}
	s->owner = i;
	spin_lock_init(&s->lock);
	for (n = 0; n < CKM_NET_MAX_SOCKETS; n++)
		s->records[n].state = s;
	mutex_lock(&registry_lock);
	list_add_tail_rcu(&s->registry, &registry);
	mutex_unlock(&registry_lock);
	i->net = s;
	return 0;
}

void ckm_net_drain(struct ckm_instance *i)
{
	struct ckm_net_state *s = i->net;
	unsigned long flags;

	if (!s)
		return;
	spin_lock_irqsave(&s->lock, flags);
	s->stopped = true;
	spin_unlock_irqrestore(&s->lock, flags);
}

void ckm_net_destroy(struct ckm_instance *i)
{
	struct ckm_net_state *s = i->net;

	if (!s)
		return;
	WARN_ON(s->live || s->retiring);
	mutex_lock(&registry_lock);
	list_del_rcu(&s->registry);
	mutex_unlock(&registry_lock);
	synchronize_rcu();
	free_percpu(s->stats);
	kfree(s);
}

void ckm_net_query(struct ckm_instance *i, struct ckm_net_query *q)
{
	struct ckm_net_state *s = i->net;
	unsigned long flags;
	int cpu;

	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	if (!s)
		return;
	q->capacity = CKM_NET_MAX_SOCKETS;
	q->management_bytes = sizeof(*s) + num_possible_cpus() * sizeof(*s->stats);
	spin_lock_irqsave(&s->lock, flags);
	q->live = s->live;
	q->retiring = s->retiring;
	q->stopped = s->stopped;
	spin_unlock_irqrestore(&s->lock, flags);
	for_each_possible_cpu(cpu) {
		struct ckm_net_stats *c = per_cpu_ptr(s->stats, cpu);
#define SUM(field) q->field += READ_ONCE(c->field)
		SUM(created); SUM(cloned); SUM(released); SUM(send_hits); SUM(recv_hits);
		SUM(native); SUM(missing); SUM(subject); SUM(stale); SUM(mediated);
		SUM(full); SUM(contended); SUM(owner_search_steps);
#undef SUM
	}
}
