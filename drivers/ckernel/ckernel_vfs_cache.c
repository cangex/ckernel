// SPDX-License-Identifier: GPL-2.0
#include <linux/ckernel.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/percpu-refcount.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time64.h>

#include "ckernel_driver.h"

#define CK_VFS_HASH_BITS	6
#define CK_VFS_MAX_ENTRIES	128
#define CK_VFS_PATH_HASH_BITS	8
#define CK_VFS_PATH_MAX_ENTRIES	256
#define CK_VFS_PATH_MAX_DEPTH	32

static unsigned long ckernel_vfs_cache_max_bytes = 2 * 1024 * 1024;
module_param(ckernel_vfs_cache_max_bytes, ulong, 0644);
MODULE_PARM_DESC(ckernel_vfs_cache_max_bytes,
		 "Maximum size of one CKernel VFS shadow object");

struct ck_vfs_object_entry {
	struct hlist_node node;
	struct inode *source_inode;
	loff_t size;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct file *shadow;
};

struct ck_vfs_path_component {
	struct dentry *dentry;
	struct dentry *parent;
	unsigned int seq;
};

struct ck_vfs_path_entry {
	struct ck_vfs_ref ref;
	struct hlist_node node;
	struct percpu_ref refs;
	u32 hash;
	char *name;
	struct path path;
	struct path root;
	const struct cred *cred;
	bool immutable_lease;
	unsigned int rename_seq;
	unsigned int mount_seq;
	unsigned int depth;
	struct ck_vfs_path_component components[CK_VFS_PATH_MAX_DEPTH];
};

enum ck_vfs_lease_event {
	CK_VFS_LEASE_HIT,
	CK_VFS_LEASE_MISS,
	CK_VFS_LEASE_FALLBACK,
	CK_VFS_LEASE_STALE,
	CK_VFS_LEASE_LEARN,
	CK_VFS_LEASE_OPEN_FAST,
	CK_VFS_LEASE_REF,
};

static void ck_vfs_lease_count(struct ckernel *ck,
			       enum ck_vfs_lease_event event)
{
	struct ck_vfs_lease_stats *stats;

	if (!ck || !READ_ONCE(ck->immutable_path_lease_enabled) ||
	    !READ_ONCE(ck->vfs_lease_stats))
		return;

	preempt_disable();
	stats = this_cpu_ptr(ck->vfs_lease_stats);
	switch (event) {
	case CK_VFS_LEASE_HIT:
		stats->hits++;
		break;
	case CK_VFS_LEASE_MISS:
		stats->misses++;
		break;
	case CK_VFS_LEASE_FALLBACK:
		stats->fallbacks++;
		break;
	case CK_VFS_LEASE_STALE:
		stats->stale++;
		break;
	case CK_VFS_LEASE_LEARN:
		stats->learns++;
		break;
	case CK_VFS_LEASE_OPEN_FAST:
		stats->open_fast++;
		break;
	case CK_VFS_LEASE_REF:
		stats->refs++;
		break;
	}
	preempt_enable();
}

struct ck_vfs_domain {
	DECLARE_HASHTABLE(objects, CK_VFS_HASH_BITS);
	DECLARE_HASHTABLE(paths, CK_VFS_PATH_HASH_BITS);
	struct ck_vfs_path_entry __rcu *hot[1 << CK_VFS_PATH_HASH_BITS];
	struct mutex lock;
	unsigned int nr_objects;
	unsigned int nr_paths;
};

static u32 ck_vfs_path_hash(const char *name, const struct cred *cred)
{
	return jhash(name, strlen(name), hash_ptr(cred, 32));
}

static bool ck_vfs_source_eligible(struct file *source)
{
	struct inode *inode = file_inode(source);
	const char *fs_name;
	loff_t size;

	if (!(source->f_mode & FMODE_READ) ||
	    (source->f_mode & FMODE_WRITE) ||
	    (source->f_flags & (O_DIRECT | O_PATH)) ||
	    !S_ISREG(inode->i_mode))
		return false;

	size = i_size_read(inode);
	if (size <= 0 || size > READ_ONCE(ckernel_vfs_cache_max_bytes))
		return false;

	/* The first version targets immutable container image objects only. */
	if (!inode->i_sb || !inode->i_sb->s_type ||
	    !inode->i_sb->s_type->name)
		return false;
	fs_name = inode->i_sb->s_type->name;
	if (strcmp(fs_name, "overlay"))
		return false;

	/* Never snapshot a file while it has a writer. */
	return atomic_read(&inode->i_writecount) == 0;
}

static bool ck_vfs_object_current(struct ck_vfs_object_entry *entry,
				  struct inode *inode)
{
	struct timespec64 mtime = inode_get_mtime(inode);
	struct timespec64 ctime = inode_get_ctime(inode);

	return entry->source_inode == inode &&
	       entry->size == i_size_read(inode) &&
	       timespec64_equal(&entry->mtime, &mtime) &&
	       timespec64_equal(&entry->ctime, &ctime) &&
	       atomic_read(&inode->i_writecount) == 0;
}

static void ck_vfs_object_free(struct ck_vfs_object_entry *entry)
{
	fput(entry->shadow);
	iput(entry->source_inode);
	kfree(entry);
}

static struct ck_vfs_object_entry *ck_vfs_object_build(struct file *source)
{
	struct inode *inode = file_inode(source);
	struct ck_vfs_object_entry *entry;
	struct file *shadow;
	char *buf;
	loff_t src_pos = 0;
	loff_t dst_pos = 0;
	loff_t size = i_size_read(inode);
	struct timespec64 mtime = inode_get_mtime(inode);
	struct timespec64 ctime = inode_get_ctime(inode);
	struct timespec64 now_mtime;
	struct timespec64 now_ctime;
	ssize_t done;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->source_inode = igrab(inode);
	if (!entry->source_inode)
		goto free_entry;

	shadow = shmem_file_setup("ckernel-vfs-object", size, 0);
	if (IS_ERR(shadow))
		goto put_inode;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		goto put_shadow;

	while (src_pos < size) {
		size_t chunk = min_t(loff_t, PAGE_SIZE, size - src_pos);

		done = kernel_read(source, buf, chunk, &src_pos);
		if (done <= 0)
			goto put_buffer;
		if (kernel_write(shadow, buf, done, &dst_pos) != done)
			goto put_buffer;
	}
	kfree(buf);
	now_mtime = inode_get_mtime(inode);
	now_ctime = inode_get_ctime(inode);
	if (size != i_size_read(inode) ||
	    !timespec64_equal(&mtime, &now_mtime) ||
	    !timespec64_equal(&ctime, &now_ctime) ||
	    atomic_read(&inode->i_writecount) != 0)
		goto put_shadow;

	entry->size = size;
	entry->mtime = mtime;
	entry->ctime = ctime;
	entry->shadow = shadow;
	return entry;

put_buffer:
	kfree(buf);
put_shadow:
	fput(shadow);
put_inode:
	iput(entry->source_inode);
free_entry:
	kfree(entry);
	return NULL;
}

static struct file *ck_vfs_cache_get(struct ckernel *ck, struct file *source)
{
	struct ck_vfs_domain *domain = READ_ONCE(ck->vfs_cache_domain);
	struct inode *inode = file_inode(source);
	struct ck_vfs_object_entry *entry;
	unsigned long key = (unsigned long)inode;
	struct file *shadow = NULL;

	if (!domain || !READ_ONCE(ck->vfs_cache_enabled)) {
		atomic_long_inc(&ck->vfs_cache_fallbacks);
		return NULL;
	}
	/* Ineligible files are the normal case for socket and private-tmpfs I/O. */
	if (!ck_vfs_source_eligible(source))
		return NULL;

	/* The current task keeps the instance and its shadow files alive. */
	rcu_read_lock();
	hash_for_each_possible_rcu(domain->objects, entry, node, key) {
		if (entry->source_inode != inode)
			continue;
		if (ck_vfs_object_current(entry, inode)) {
			shadow = entry->shadow;
			atomic_long_inc(&ck->vfs_cache_hits);
		} else {
			atomic_long_inc(&ck->vfs_cache_rebuilds);
			atomic_long_inc(&ck->vfs_cache_fallbacks);
		}
		rcu_read_unlock();
		return shadow;
	}
	rcu_read_unlock();

	mutex_lock(&domain->lock);
	hash_for_each_possible(domain->objects, entry, node, key) {
		if (entry->source_inode != inode)
			continue;
		if (ck_vfs_object_current(entry, inode)) {
			shadow = entry->shadow;
			atomic_long_inc(&ck->vfs_cache_hits);
		} else {
			atomic_long_inc(&ck->vfs_cache_rebuilds);
			atomic_long_inc(&ck->vfs_cache_fallbacks);
		}
		goto out;
	}

	if (domain->nr_objects >= CK_VFS_MAX_ENTRIES)
		goto fallback;

	entry = ck_vfs_object_build(source);
	if (!entry)
		goto fallback;

	hash_add_rcu(domain->objects, &entry->node, key);
	domain->nr_objects++;
	atomic_long_add(entry->size, &ck->vfs_cache_bytes);
	atomic_long_inc(&ck->vfs_cache_misses);
	shadow = entry->shadow;
	goto out;

fallback:
	atomic_long_inc(&ck->vfs_cache_fallbacks);
out:
	mutex_unlock(&domain->lock);
	return shadow;
}

static void ck_vfs_path_ref_release(struct percpu_ref *refs)
{
	struct ck_vfs_path_entry *entry;

	entry = container_of(refs, struct ck_vfs_path_entry, refs);
	percpu_ref_exit(&entry->refs);
	path_put(&entry->path);
	path_put(&entry->root);
	put_cred(entry->cred);
	kfree(entry->name);
	module_put(THIS_MODULE);
	kfree(entry);
}

static void ck_vfs_path_ref_put(struct ck_vfs_ref *ref)
{
	struct ck_vfs_path_entry *entry;

	entry = container_of(ref, struct ck_vfs_path_entry, ref);
	percpu_ref_put(&entry->refs);
}

static void ck_vfs_path_retire(struct ck_vfs_path_entry *entry)
{
	percpu_ref_kill(&entry->refs);
}

static bool ck_vfs_same_root(const struct ck_vfs_path_entry *entry)
{
	struct fs_struct *fs = current->fs;
	bool same;

	if (!fs)
		return false;
	spin_lock(&fs->lock);
	same = fs->root.mnt == entry->root.mnt &&
	       fs->root.dentry == entry->root.dentry;
	spin_unlock(&fs->lock);
	return same;
}

static bool ck_vfs_lease_type_supported(const struct dentry *dentry)
{
	return d_is_reg(dentry) || d_is_dir(dentry);
}

static bool ck_vfs_path_current(const struct ck_vfs_path_entry *entry)
{
	struct inode *inode = d_inode(entry->path.dentry);
	unsigned int i;

	if (entry->immutable_lease) {
		return inode && ck_vfs_lease_type_supported(entry->path.dentry) &&
		       !d_unhashed(entry->path.dentry) &&
		       !(entry->path.dentry->d_flags & DCACHE_OP_REVALIDATE) &&
		       entry->path.dentry->d_sb &&
		       entry->path.dentry->d_sb->s_type &&
		       !strcmp(entry->path.dentry->d_sb->s_type->name, "tmpfs") &&
		       __mnt_is_readonly(entry->path.mnt) &&
		       atomic_read(&inode->i_writecount) == 0 &&
		       current_cred() == entry->cred &&
		       ck_vfs_same_root(entry);
	}

	if (!inode || !S_ISREG(inode->i_mode) || d_unhashed(entry->path.dentry) ||
	    read_seqretry(&rename_lock, entry->rename_seq) ||
	    vfs_mount_seq_retry(entry->mount_seq) ||
	    !ck_vfs_same_root(entry))
		return false;

	for (i = 0; i < entry->depth; i++) {
		const struct ck_vfs_path_component *component;

		component = &entry->components[i];
		if (READ_ONCE(component->dentry->d_parent) != component->parent ||
		    read_seqcount_retry(&component->dentry->d_seq,
					component->seq))
			return false;
	}

	return !read_seqretry(&rename_lock, entry->rename_seq) &&
	       !vfs_mount_seq_retry(entry->mount_seq);
}

static bool ck_vfs_path_access_allowed(const struct ck_vfs_path_entry *entry)
{
	struct mnt_idmap *idmap = mnt_idmap(entry->path.mnt);
	struct dentry *last = NULL;
	unsigned int i;

	/*
	 * Cached lookup still has to enforce DAC and LSM search permission on
	 * every directory component. Directory modes can change without d_seq.
	 */
	for (i = 0; i < entry->depth; i++) {
		struct dentry *parent = entry->components[i].parent;
		struct inode *inode;

		if (parent == last)
			continue;
		inode = d_inode(parent);
		if (!inode || inode_permission(idmap, inode, MAY_EXEC))
			return false;
		last = parent;
	}
	return true;
}

static struct ck_vfs_path_entry *
ck_vfs_path_build(const char *name, const struct path *path,
		  bool immutable_lease)
{
	struct ck_vfs_path_entry *entry;
	struct path verified;
	struct path root;
	struct dentry *dentry;
	unsigned int depth = 0;
	unsigned int rename_seq;
	unsigned int mount_seq;
	int error;

	if (!name || name[0] != '/' || !path->mnt || !path->dentry ||
	    !path->dentry->d_sb ||
	    !path->dentry->d_sb->s_type ||
	    (path->dentry->d_flags & DCACHE_OP_REVALIDATE))
		return NULL;
	if (immutable_lease) {
		if (!ck_vfs_lease_type_supported(path->dentry) ||
		    strcmp(path->dentry->d_sb->s_type->name, "tmpfs") ||
		    !__mnt_is_readonly(path->mnt) ||
		    atomic_read(&d_inode(path->dentry)->i_writecount) != 0)
			return NULL;
	} else if (!d_is_reg(path->dentry) ||
		   strcmp(path->dentry->d_sb->s_type->name, "overlay")) {
		return NULL;
	}

	/*
	 * The immutable domain itself is a runck-created tmpfs submount, so the
	 * verification lookup must cross that one mount boundary.  The resolved
	 * object is still required to match the already-opened path exactly and
	 * to reside on a read-only tmpfs mount.
	 */
	error = kern_path(name, LOOKUP_FOLLOW | LOOKUP_NO_SYMLINKS |
			  LOOKUP_NO_MAGICLINKS, &verified);
	if (error)
		return NULL;
	if (verified.mnt != path->mnt || verified.dentry != path->dentry) {
		path_put(&verified);
		return NULL;
	}
	path_put(&verified);

	get_fs_root(current->fs, &root);
	if (!immutable_lease && path->mnt != root.mnt) {
		path_put(&root);
		return NULL;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		path_put(&root);
		return NULL;
	}
	entry->name = kstrdup(name, GFP_KERNEL);
	if (!entry->name)
		goto free_entry;

	rename_seq = 0;
	mount_seq = 0;
	if (!immutable_lease) {
		rename_seq = read_seqbegin(&rename_lock);
		mount_seq = vfs_mount_seq_begin();
		dentry = path->dentry;
		while (dentry != root.dentry) {
			struct dentry *parent;
			unsigned int seq;

			if (depth >= CK_VFS_PATH_MAX_DEPTH ||
			    (dentry->d_flags & DCACHE_OP_REVALIDATE))
				goto free_name;
			seq = read_seqcount_begin(&dentry->d_seq);
			parent = READ_ONCE(dentry->d_parent);
			if (read_seqcount_retry(&dentry->d_seq, seq))
				goto free_name;
			entry->components[depth].dentry = dentry;
			entry->components[depth].parent = parent;
			entry->components[depth].seq = seq;
			depth++;
			if (parent == dentry)
				goto free_name;
			dentry = parent;
		}
		if (read_seqretry(&rename_lock, rename_seq) ||
		    vfs_mount_seq_retry(mount_seq))
			goto free_name;
	}

	if (!try_module_get(THIS_MODULE))
		goto free_name;
	error = percpu_ref_init(&entry->refs, ck_vfs_path_ref_release, 0,
				GFP_KERNEL);
	if (error) {
		module_put(THIS_MODULE);
		goto free_name;
	}
	entry->ref.put = ck_vfs_path_ref_put;
	entry->ref.ckernel_cookie = READ_ONCE(current->ckernel->cookie);
	entry->ref.immutable_lease = immutable_lease;
	entry->hash = ck_vfs_path_hash(name, current_cred());
	entry->path = *path;
	path_get(&entry->path);
	entry->root = root;
	entry->cred = get_cred(current_cred());
	entry->immutable_lease = immutable_lease;
	entry->rename_seq = rename_seq;
	entry->mount_seq = mount_seq;
	entry->depth = depth;
	return entry;

free_name:
	kfree(entry->name);
free_entry:
	kfree(entry);
	path_put(&root);
	return NULL;
}

static struct ck_vfs_ref *
ck_vfs_ref_lookup(struct ckernel *ck, const char *name,
		  enum ck_vfs_ref_kind kind, struct path *path)
{
	struct ck_vfs_domain *domain = READ_ONCE(ck->vfs_cache_domain);
	struct ck_vfs_path_entry *entry;
	u32 hash;
	unsigned int slot;

	if (!domain || !READ_ONCE(ck->vfs_ref_enabled) || !name ||
	    name[0] != '/') {
		if (READ_ONCE(ck->immutable_path_lease_enabled))
			ck_vfs_lease_count(ck, CK_VFS_LEASE_FALLBACK);
		else
			atomic_long_inc(&ck->vfs_ref_fallbacks);
		return NULL;
	}

	hash = ck_vfs_path_hash(name, current_cred());
	slot = hash_32(hash, CK_VFS_PATH_HASH_BITS);
	rcu_read_lock();
	entry = rcu_dereference(domain->hot[slot]);
	if (entry && entry->hash == hash && !strcmp(entry->name, name)) {
		if (ck_vfs_path_current(entry) &&
		    percpu_ref_tryget_live(&entry->refs))
			goto hit;
		if (entry->immutable_lease)
			ck_vfs_lease_count(ck, CK_VFS_LEASE_STALE);
		else
			atomic_long_inc(&ck->vfs_ref_stale);
	}

	hash_for_each_possible_rcu(domain->paths, entry, node, hash) {
		if (entry->hash != hash || strcmp(entry->name, name))
			continue;
		if (!ck_vfs_path_current(entry)) {
			if (entry->immutable_lease)
				ck_vfs_lease_count(ck, CK_VFS_LEASE_STALE);
			else
				atomic_long_inc(&ck->vfs_ref_stale);
			continue;
		}
		if (percpu_ref_tryget_live(&entry->refs))
			goto hit;
	}
	rcu_read_unlock();
	if (READ_ONCE(ck->immutable_path_lease_enabled))
		ck_vfs_lease_count(ck, CK_VFS_LEASE_MISS);
	else
		atomic_long_inc(&ck->vfs_ref_misses);
	return NULL;

hit:
	*path = entry->path;
	rcu_assign_pointer(domain->hot[slot], entry);
	rcu_read_unlock();
	if (!entry->immutable_lease && !ck_vfs_path_access_allowed(entry)) {
		ck_vfs_path_ref_put(&entry->ref);
		atomic_long_inc(&ck->vfs_ref_fallbacks);
		return NULL;
	}
	if (entry->immutable_lease) {
		ck_vfs_lease_count(ck, CK_VFS_LEASE_HIT);
		ck_vfs_lease_count(ck, CK_VFS_LEASE_REF);
		if (kind == CK_VFS_REF_OPEN)
			ck_vfs_lease_count(ck, CK_VFS_LEASE_OPEN_FAST);
	} else {
		atomic_long_inc(&ck->vfs_ref_hits);
		atomic_long_inc(&ck->vfs_ref_dget_avoided);
		if (kind == CK_VFS_REF_OPEN)
			atomic_long_inc(&ck->vfs_ref_open_fast);
		else
			atomic_long_inc(&ck->vfs_ref_stat_fast);
	}
	return &entry->ref;
}

static void ck_vfs_ref_learn(struct ckernel *ck, const char *name,
			     const struct path *path)
{
	struct ck_vfs_domain *domain = READ_ONCE(ck->vfs_cache_domain);
	struct ck_vfs_path_entry *candidate = NULL;
	struct ck_vfs_path_entry *entry;
	struct ck_vfs_path_entry *stale = NULL;
	u32 hash;
	unsigned int slot;
	bool inserted = false;

	if (!domain || !READ_ONCE(ck->vfs_ref_enabled) || !name ||
	    name[0] != '/')
		return;

	/* Serialize only the cold learn path; lookups remain RCU/per-CPU. */
	hash = ck_vfs_path_hash(name, current_cred());
	mutex_lock(&domain->lock);
	hash_for_each_possible(domain->paths, entry, node, hash) {
		if (entry->hash != hash || strcmp(entry->name, name))
			continue;
		if (ck_vfs_path_current(entry))
			goto unlock;
		hash_del_rcu(&entry->node);
		slot = hash_32(hash, CK_VFS_PATH_HASH_BITS);
		if (rcu_access_pointer(domain->hot[slot]) == entry)
			RCU_INIT_POINTER(domain->hot[slot], NULL);
		domain->nr_paths--;
		stale = entry;
		break;
	}

	candidate = ck_vfs_path_build(name, path,
				      READ_ONCE(ck->immutable_path_lease_enabled));
	if (!candidate) {
		mutex_unlock(&domain->lock);
		if (stale) {
			synchronize_rcu();
			ck_vfs_path_retire(stale);
		}
		if (READ_ONCE(ck->immutable_path_lease_enabled))
			ck_vfs_lease_count(ck, CK_VFS_LEASE_FALLBACK);
		else
			atomic_long_inc(&ck->vfs_ref_fallbacks);
		return;
	}
	hash = candidate->hash;
	slot = hash_32(hash, CK_VFS_PATH_HASH_BITS);
	if (domain->nr_paths >= CK_VFS_PATH_MAX_ENTRIES)
		goto unlock;

	hash_add_rcu(domain->paths, &candidate->node, hash);
	rcu_assign_pointer(domain->hot[slot], candidate);
	domain->nr_paths++;
	inserted = true;
	if (candidate->immutable_lease)
		ck_vfs_lease_count(ck, CK_VFS_LEASE_LEARN);
	else
		atomic_long_inc(&ck->vfs_ref_learns);

unlock:
	mutex_unlock(&domain->lock);
	if (stale) {
		synchronize_rcu();
		ck_vfs_path_retire(stale);
	}
	if (candidate && !inserted)
		ck_vfs_path_retire(candidate);
}

int ck_vfs_domain_init(struct ckernel *ck, bool object_enabled,
		       bool ref_enabled, bool lease_enabled)
{
	struct ck_vfs_domain *domain;

	atomic_long_set(&ck->vfs_cache_hits, 0);
	atomic_long_set(&ck->vfs_cache_misses, 0);
	atomic_long_set(&ck->vfs_cache_fallbacks, 0);
	atomic_long_set(&ck->vfs_cache_rebuilds, 0);
	atomic_long_set(&ck->vfs_cache_bytes, 0);
	atomic_long_set(&ck->vfs_ref_hits, 0);
	atomic_long_set(&ck->vfs_ref_misses, 0);
	atomic_long_set(&ck->vfs_ref_fallbacks, 0);
	atomic_long_set(&ck->vfs_ref_stale, 0);
	atomic_long_set(&ck->vfs_ref_learns, 0);
	atomic_long_set(&ck->vfs_ref_open_fast, 0);
	atomic_long_set(&ck->vfs_ref_stat_fast, 0);
	atomic_long_set(&ck->vfs_ref_dget_avoided, 0);
	ck->vfs_cache_domain = NULL;
	ck->ck_vfs_cache_get = NULL;
	ck->ck_vfs_ref_lookup = NULL;
	ck->ck_vfs_ref_learn = NULL;
	ck->vfs_cache_enabled = false;
	ck->vfs_ref_enabled = false;
	ck->immutable_path_lease_enabled = false;
	ck->vfs_lease_stats = NULL;

	if (!object_enabled && !ref_enabled && !lease_enabled)
		return 0;
	if (lease_enabled) {
		ck->vfs_lease_stats = alloc_percpu(struct ck_vfs_lease_stats);
		if (!ck->vfs_lease_stats)
			return -ENOMEM;
	}

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain) {
		if (ck->vfs_lease_stats)
			free_percpu(ck->vfs_lease_stats);
		ck->vfs_lease_stats = NULL;
		return -ENOMEM;
	}

	hash_init(domain->objects);
	hash_init(domain->paths);
	mutex_init(&domain->lock);
	WRITE_ONCE(ck->vfs_cache_domain, domain);
	if (object_enabled) {
		ck->ck_vfs_cache_get = ck_vfs_cache_get;
		WRITE_ONCE(ck->vfs_cache_enabled, true);
	}
	if (ref_enabled || lease_enabled) {
		ck->ck_vfs_ref_lookup = ck_vfs_ref_lookup;
		ck->ck_vfs_ref_learn = ck_vfs_ref_learn;
		WRITE_ONCE(ck->vfs_ref_enabled, true);
	}
	WRITE_ONCE(ck->immutable_path_lease_enabled, lease_enabled);
	return 0;
}

void ck_vfs_domain_destroy(struct ckernel *ck)
{
	struct ck_vfs_domain *domain = READ_ONCE(ck->vfs_cache_domain);
	struct ck_vfs_object_entry *object;
	struct ck_vfs_path_entry *path_entry;
	struct hlist_node *tmp;
	int bucket;

	WRITE_ONCE(ck->vfs_cache_enabled, false);
	WRITE_ONCE(ck->vfs_ref_enabled, false);
	WRITE_ONCE(ck->immutable_path_lease_enabled, false);
	ck->ck_vfs_cache_get = NULL;
	ck->ck_vfs_ref_lookup = NULL;
	ck->ck_vfs_ref_learn = NULL;
	WRITE_ONCE(ck->vfs_cache_domain, NULL);
	if (!domain)
		return;
	synchronize_rcu();

	hash_for_each_safe(domain->objects, bucket, tmp, object, node) {
		hash_del(&object->node);
		ck_vfs_object_free(object);
	}
	hash_for_each_safe(domain->paths, bucket, tmp, path_entry, node) {
		hash_del(&path_entry->node);
		ck_vfs_path_retire(path_entry);
	}
	kfree(domain);
	if (ck->vfs_lease_stats)
		free_percpu(ck->vfs_lease_stats);
	ck->vfs_lease_stats = NULL;
}
