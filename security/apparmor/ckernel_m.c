// SPDX-License-Identifier: GPL-2.0
#include <linux/ckernel_m_security.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include "include/ckernel_m.h"
#include "include/cred.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/policy.h"
#include "../../kernel/ckernel_m/internal.h"

struct aa_ckm_entry {
	struct aa_label *label;
	struct ckm_security_state *state;
	refcount_t refs;
	bool self_signal;
};

struct aa_ckm_counters {
	u64 signal_hits, signal_native;
	u64 label_hits, label_native, label_released, open_borrowed, label_learned;
	u64 full, contended, stale;
};

struct ckm_security_state {
	struct ckm_instance *owner;
	unsigned int registry_slot;
	spinlock_t lock;
	bool stopped;
	struct aa_ckm_entry entries[CKM_SECURITY_MAX_LABELS];
	struct aa_ckm_counters __percpu *stats;
};

/* Core admits at most 256 live instances. Only create/destroy take this lock. */
static DEFINE_MUTEX(registry_lock);
static struct ckm_security_state *registry[256];

static int register_state(struct ckm_security_state *s)
{
	unsigned int n;
	int ret = -ENOSPC;

	mutex_lock(&registry_lock);
	for (n = 0; n < ARRAY_SIZE(registry); n++) {
		if (registry[n])
			continue;
		s->registry_slot = n;
		WRITE_ONCE(registry[n], s);
		ret = 0;
		break;
	}
	mutex_unlock(&registry_lock);
	return ret;
}

static struct aa_ckm_entry *file_entry(u32 token)
{
	unsigned int owner = token >> 8, slot = token & 255;
	struct ckm_security_state *s;

	if (!token)
		return NULL;
	if (WARN_ON_ONCE(!owner || owner > ARRAY_SIZE(registry) || slot >= CKM_SECURITY_MAX_LABELS))
		return NULL;
	/* The file's loan holds this instance alive; its slot cannot be recycled. */
	s = READ_ONCE(registry[owner - 1]);
	if (WARN_ON_ONCE(!s))
		return NULL;
	return &s->entries[slot];
}

static struct ckm_security_state *current_state(void)
{
	struct ckm_instance *i = READ_ONCE(current->ckm_instance);
	bool compatible;

	if (!i || !ckm_active(i) || !i->security || current->flags & PF_KTHREAD ||
	    in_interrupt())
		return NULL;
	rcu_read_lock();
	compatible = task_dfl_cgroup(current) == i->cgroup;
	rcu_read_unlock();
	return compatible ? i->security : NULL;
}

static bool signal_unmediated(struct aa_label *label)
{
	struct aa_profile *profile;
	struct label_it it;

	/* Exactly the native profile_signal_perm early return, for BOTH sides. */
	label_for_each(it, label, profile) {
		if (!profile_unconfined(profile) &&
		    ANY_RULE_MEDIATES(&profile->rules, AA_CLASS_SIGNAL))
			return false;
	}
	return true;
}

static void entry_put(struct aa_ckm_entry *e)
{
	if (refcount_dec_and_test(&e->refs))
		aa_put_label(e->label);
}

static struct aa_ckm_entry *borrow_label(struct ckm_security_state *s,
					struct aa_label *label)
{
	struct aa_ckm_entry *e, *free = NULL;
	struct aa_label *old = NULL;
	unsigned int n;

	if (READ_ONCE(label->flags) & FLAG_STALE) {
		this_cpu_inc(s->stats->stale);
		return NULL;
	}
	if (!spin_trylock(&s->lock)) {
		this_cpu_inc(s->stats->contended);
		return NULL;
	}
	if (s->stopped || !ckm_active(s->owner))
		goto unavailable;
	for (n = 0; n < CKM_SECURITY_MAX_LABELS; n++) {
		e = &s->entries[n];
		if (e->label == label) {
			refcount_inc(&e->refs);
			ckm_get(s->owner);
			spin_unlock(&s->lock);
			return e;
		}
		if (!e->label || (refcount_read(&e->refs) == 1 &&
				 (READ_ONCE(e->label->flags) & FLAG_STALE)))
			free = e;
	}
	if (!free) {
		this_cpu_inc(s->stats->full);
		goto unavailable;
	}
	old = free->label;
	free->label = aa_get_label(label);
	free->state = s;
	free->self_signal = signal_unmediated(label);
	refcount_set(&free->refs, 2); /* cache and caller */
	ckm_get(s->owner);
	spin_unlock(&s->lock);
	this_cpu_inc(s->stats->label_learned);
	aa_put_label(old);
	return free;
unavailable:
	spin_unlock(&s->lock);
	return NULL;
}

static void release_label(struct aa_ckm_entry *e)
{
	struct ckm_instance *owner = e->state->owner;

	entry_put(e);
	ckm_put(owner);
}

bool aa_ckm_self_subject(struct task_struct *target, const struct cred *cred)
{
	/* get_task_cred(target) uses objective, not overridden subjective creds. */
	return target == current && !cred && current_cred() == current_real_cred();
}

bool aa_ckm_self_signal(struct task_struct *target, const struct cred *cred)
{
	struct ckm_security_state *s = current_state();
	struct aa_ckm_entry *e;
	struct aa_label *label;
	bool allowed = false;

	if (!s)
		return false;
	if (!aa_ckm_self_subject(target, cred))
		goto native;
	label = __begin_current_label_crit_section();
	e = borrow_label(s, label);
	if (e) {
		allowed = e->self_signal && !(READ_ONCE(label->flags) & FLAG_STALE);
		release_label(e);
	}
	__end_current_label_crit_section(label);
	if (allowed) {
		this_cpu_inc(s->stats->signal_hits);
		return true;
	}
native:
	this_cpu_inc(s->stats->signal_native);
	return false;
}

void aa_ckm_file_init(struct aa_file_ctx *ctx, struct aa_label *label)
{
	struct ckm_security_state *s = current_state();
	struct aa_ckm_entry *e = s ? borrow_label(s, label) : NULL;

	ctx->ckm_token = e ? ((s->registry_slot + 1) << 8) | (e - s->entries) : 0;
	if (e) {
		rcu_assign_pointer(ctx->label, label);
		this_cpu_inc(s->stats->label_hits);
	} else {
		rcu_assign_pointer(ctx->label, aa_get_label(label));
		if (s)
			this_cpu_inc(s->stats->label_native);
	}
}

void aa_ckm_file_drop(struct aa_file_ctx *ctx, struct aa_label *label)
{
	u32 token = ctx->ckm_token;
	struct aa_ckm_entry *e;

	ctx->ckm_token = 0;
	if (token) {
		e = file_entry(token);
		if (!e)
			return; /* Corrupt internal token was warned; never put an unowned label. */
		this_cpu_inc(e->state->stats->label_released);
		release_label(e);
	} else {
		aa_put_label(label);
	}
}

bool aa_ckm_file_open_label(struct file *file, struct aa_label **label)
{
	struct aa_file_ctx *ctx = file_ctx(file);
	struct aa_ckm_entry *e = file_entry(ctx->ckm_token);

	/* Before publication: this file's context cannot be merged concurrently. */
	if (!e || e->label != cred_label(file->f_cred) ||
	    READ_ONCE(e->label->flags) & FLAG_STALE)
		return false;
	*label = e->label;
	this_cpu_inc(e->state->stats->open_borrowed);
	return true;
}

int ckm_security_init(struct ckm_instance *inst)
{
	struct ckm_security_state *s;
	int ret;

	if (!(inst->features & CKM_FEATURE_SECURITY))
		return 0;
	s = kzalloc(sizeof(*s), GFP_KERNEL_ACCOUNT);
	if (!s)
		return -ENOMEM;
	s->stats = alloc_percpu_gfp(struct aa_ckm_counters, GFP_KERNEL_ACCOUNT);
	if (!s->stats) {
		kfree(s);
		return -ENOMEM;
	}
	s->owner = inst;
	spin_lock_init(&s->lock);
	ret = register_state(s);
	if (ret) {
		free_percpu(s->stats);
		kfree(s);
		return ret;
	}
	inst->security = s;
	return 0;
}

void ckm_security_drain(struct ckm_instance *inst)
{
	struct ckm_security_state *s = inst->security;
	unsigned int n;

	if (!s)
		return;
	spin_lock(&s->lock);
	s->stopped = true;
	spin_unlock(&s->lock);
	/* Cache refs only; borrowers retain entry and instance until last close. */
	for (n = 0; n < CKM_SECURITY_MAX_LABELS; n++)
		if (s->entries[n].label)
			entry_put(&s->entries[n]);
}

void ckm_security_destroy(struct ckm_instance *inst)
{
	struct ckm_security_state *s = inst->security;
	unsigned int n;

	if (!s)
		return;
	for (n = 0; n < CKM_SECURITY_MAX_LABELS; n++)
		WARN_ON(refcount_read(&s->entries[n].refs));
	/* All file loans pin the instance, so no token reader can remain here. */
	mutex_lock(&registry_lock);
	WARN_ON(registry[s->registry_slot] != s);
	WRITE_ONCE(registry[s->registry_slot], NULL);
	mutex_unlock(&registry_lock);
	free_percpu(s->stats);
	kfree(s);
}

void ckm_security_query(struct ckm_instance *inst, struct ckm_security_query *q)
{
	struct ckm_security_state *s = inst->security;
	int cpu;

	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	if (!s)
		return;
	q->management_bytes = sizeof(*s) + num_possible_cpus() * sizeof(*s->stats);
	for_each_possible_cpu(cpu) {
		struct aa_ckm_counters *c = per_cpu_ptr(s->stats, cpu);

#define SUM(field) q->field += READ_ONCE(c->field)
		SUM(signal_hits); SUM(signal_native); SUM(label_hits); SUM(label_native);
		SUM(label_released); SUM(open_borrowed); SUM(full); SUM(contended); SUM(stale);
		SUM(label_learned);
#undef SUM
	}
}
