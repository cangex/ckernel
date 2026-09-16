// SPDX-License-Identifier: GPL-2.0
#include <linux/ckernel_m_vfs.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/percpu.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include "mount.h"
#include "../kernel/ckernel_m/internal.h"

struct ckm_vfs_counters {
	u64 hits, retries, native, full;
};

struct ckm_vfs_entry {
	struct dentry *dentry;
	refcount_t refs;
};

struct ckm_vfs_state {
	struct ckm_instance *owner;
	struct rw_semaphore guard;
	struct fs_pin pin;
	struct rcu_head rcu;
	struct vfsmount *mount;
	struct ckm_vfs_entry entries[CKM_VFS_MAX_ENTRIES];
	struct ckm_vfs_counters __percpu *counters;
	unsigned int capacity, count;
	bool initialized, stopped;
};

static void ckm_vfs_entry_put(struct ckm_vfs_entry *entry)
{
	if (refcount_dec_and_test(&entry->refs))
		dput(entry->dentry);
}

static void ckm_vfs_pin_kill(struct fs_pin *pin)
{
	struct ckm_vfs_state *s = container_of(pin, struct ckm_vfs_state, pin);
	unsigned int n, count;

	down_write(&s->guard);
	s->stopped = true;
	s->mount = NULL;
	count = s->count;
	s->count = 0;
	up_write(&s->guard);
	/* No instance lock held while eviction reenters filesystem teardown. */
	for (n = 0; n < count; n++)
		ckm_vfs_entry_put(&s->entries[n]);
	pin_remove(pin);
	ckm_put(s->owner);
}

void ckm_vfs_before_write_remount(struct super_block *sb)
{
	/* Registration takes the read side. No new cache can enter this transition. */
	lockdep_assert_held(&sb->s_umount);
	group_pin_kill_matching(&sb->s_pins, ckm_vfs_pin_kill);
}

int ckm_vfs_init(struct ckm_instance *inst)
{
	struct ckm_vfs_state *s;

	if (!(inst->features & CKM_FEATURE_VFS))
		return 0;
	s = kzalloc(sizeof(*s), GFP_KERNEL_ACCOUNT);
	if (!s)
		return -ENOMEM;
	s->counters = alloc_percpu_gfp(struct ckm_vfs_counters, GFP_KERNEL_ACCOUNT);
	if (!s->counters) {
		kfree(s);
		return -ENOMEM;
	}
	s->owner = inst;
	init_rwsem(&s->guard);
	init_fs_pin(&s->pin, ckm_vfs_pin_kill);
	inst->vfs = s;
	return 0;
}

int ckm_vfs_register(struct ckm_instance *inst, int fd, unsigned int capacity)
{
	struct ckm_vfs_state *s = inst->vfs;
	struct fd f;
	struct path *p;
	int ret = 0;

	if (!s)
		return -EOPNOTSUPP;
	if (!capacity || capacity > CKM_VFS_MAX_ENTRIES)
		return -EINVAL;
	f = fdget_raw(fd);
	if (!f.file)
		return -EBADF;
	p = &f.file->f_path;
	down_read(&p->mnt->mnt_sb->s_umount);
	down_write(&s->guard);
	if (!ckm_active(inst))
		ret = -ESHUTDOWN;
	else if (s->initialized || atomic_read(&inst->tasks))
		ret = -EBUSY;
	else if (p->mnt->mnt_sb->s_magic != TMPFS_MAGIC ||
		 p->dentry != p->mnt->mnt_root || !d_is_dir(p->dentry) ||
		 !(READ_ONCE(p->mnt->mnt_flags) & MNT_READONLY) ||
		 !sb_rdonly(p->mnt->mnt_sb) ||
		 !is_mounted(p->mnt))
		ret = -EOPNOTSUPP;
	else {
		s->mount = p->mnt;
		s->capacity = capacity;
		s->initialized = true;
		ckm_get(inst);
		/* fs_pin, unlike mntget, does not make ordinary umount busy. */
		pin_insert(&s->pin, p->mnt);
	}
	up_write(&s->guard);
	up_read(&p->mnt->mnt_sb->s_umount);
	fdput(f);
	return ret;
}

void ckm_vfs_drain(struct ckm_instance *inst)
{
	struct ckm_vfs_state *s = inst->vfs;
	bool initialized;

	if (!s)
		return;
	down_write(&s->guard);
	initialized = s->initialized;
	up_write(&s->guard);
	if (initialized) {
		rcu_read_lock();
		pin_kill(&s->pin);
	}
}

int ckm_vfs_bind(struct ckm_instance *inst)
{
	struct ckm_vfs_state *s = inst->vfs;
	int ret;

	if (!s)
		return ckm_bind_current(inst);
	down_write(&s->guard);
	ret = ckm_bind_current(inst);
	up_write(&s->guard);
	return ret;
}

void ckm_vfs_destroy(struct ckm_instance *inst)
{
	struct ckm_vfs_state *s = inst->vfs;

	if (!s)
		return;
	WARN_ON(s->count || (s->initialized && !s->stopped));
	for (unsigned int n = 0; n < s->capacity; n++)
		WARN_ON(refcount_read(&s->entries[n].refs));
	free_percpu(s->counters);
	/* pin_kill callers may still inspect pin->done under RCU. */
	kfree_rcu(s, rcu);
}

void ckm_vfs_begin(struct ckm_path_lease *lease)
{
	struct ckm_instance *inst = READ_ONCE(current->ckm_instance);
	struct ckm_vfs_state *s;
	bool same;

	memset(lease, 0, sizeof(*lease));
	if (!inst || !ckm_active(inst) || !inst->vfs)
		return;
	rcu_read_lock();
	same = task_dfl_cgroup(current) == inst->cgroup;
	rcu_read_unlock();
	if (!same)
		return;
	s = inst->vfs;
	lease->state = s;
}

int ckm_vfs_complete_rcu(struct ckm_path_lease *lease, const struct path *path,
			 unsigned int seq, unsigned int mseq)
{
	struct ckm_vfs_state *s = lease->state;
	unsigned int n;
	int ret;

	if (!s || !down_read_trylock(&s->guard))
		return 0;
	if (!ckm_active(s->owner) || s->stopped || !s->initialized ||
	    path->mnt != s->mount || !d_is_reg(path->dentry) ||
	    !(READ_ONCE(path->mnt->mnt_flags) & MNT_READONLY) ||
	    !sb_rdonly(path->mnt->mnt_sb))
		goto native;
	for (n = 0; n < s->count; n++)
		if (s->entries[n].dentry == path->dentry)
			break;
	if (n == s->count)
		goto native;
	ret = __legitimize_mnt(path->mnt, mseq);
	if (ret || read_seqcount_retry(&path->dentry->d_seq, seq)) {
		if (ret <= 0)
			lease->pending_mnt = path->mnt;
		this_cpu_inc(s->counters->retries);
		up_read(&s->guard);
		return -ECHILD;
	}
	lease->borrowed = true;
	lease->entry = &s->entries[n];
	refcount_inc(&lease->entry->refs);
	this_cpu_inc(s->counters->hits);
	/* Never hold the guard across getattr/LSM or filesystem operations. */
	up_read(&s->guard);
	return 1;
native:
	up_read(&s->guard);
	return 0;
}

static void ckm_vfs_learn(struct ckm_vfs_state *s, const struct path *p)
{
	unsigned int n;

	/* Cache insertion is optional, including inside a nested native lookup. */
	if (!down_write_trylock(&s->guard))
		return;
	if (!ckm_active(s->owner) || s->stopped || p->mnt != s->mount ||
	    !d_is_reg(p->dentry) || !(READ_ONCE(p->mnt->mnt_flags) & MNT_READONLY) ||
	    !sb_rdonly(p->mnt->mnt_sb))
		goto out;
	for (n = 0; n < s->count; n++)
		if (s->entries[n].dentry == p->dentry)
			goto out;
	if (s->count == s->capacity) {
		this_cpu_inc(s->counters->full);
		goto out;
	}
	s->entries[s->count].dentry = dget(p->dentry);
	refcount_set(&s->entries[s->count].refs, 1);
	s->count++;
out:
	up_write(&s->guard);
}

void ckm_vfs_end(struct ckm_path_lease *lease, struct path *path)
{
	struct ckm_vfs_state *s = lease->state;

	if (s) {
		if (!lease->borrowed)
			this_cpu_inc(s->counters->native);
		if (path && !lease->borrowed)
			ckm_vfs_learn(s, path);
	}
	/* Retired loans retain only the references a native in-flight lookup needs. */
	if (path) {
		if (lease->borrowed) {
			ckm_vfs_entry_put(lease->entry);
			mntput(path->mnt);
		} else
			path_put(path);
	}
	if (lease->pending_mnt)
		mntput(lease->pending_mnt);
}

void ckm_vfs_query(struct ckm_instance *inst, struct ckm_vfs_query *q)
{
	struct ckm_vfs_state *s = inst->vfs;
	int cpu;

	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	if (!s)
		return;
	down_read(&s->guard);
	q->capacity = s->capacity;
	q->cached = s->count;
	q->registered = s->initialized;
	q->stopped = s->stopped;
	q->metadata_payload_bytes = sizeof(*s) +
		num_possible_cpus() * sizeof(struct ckm_vfs_counters);
	for_each_possible_cpu(cpu) {
		struct ckm_vfs_counters *c = per_cpu_ptr(s->counters, cpu);

		q->hits += READ_ONCE(c->hits);
		q->retries += READ_ONCE(c->retries);
		q->native += READ_ONCE(c->native);
		q->full += READ_ONCE(c->full);
	}
	up_read(&s->guard);
}
