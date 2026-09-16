/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CKERNEL_M_VFS_H
#define _LINUX_CKERNEL_M_VFS_H
#include <linux/types.h>
struct ckm_instance;
struct ckm_vfs_state;
struct ckm_vfs_entry;
struct super_block;
struct path;
struct filename;
struct vfsmount;
struct ckm_vfs_query;
struct ckm_vfs_open_query;
struct file;
struct ckm_path_lease {
	struct ckm_vfs_state *state;
	struct vfsmount *pending_mnt;
	struct ckm_vfs_entry *entry;
	bool borrowed;
};

#ifdef CONFIG_CKERNEL_M_VFS_OPEN
bool ckm_vfs_file_get(struct file *file);
bool ckm_vfs_file_dput(struct file *file);
void ckm_vfs_open_query(struct ckm_instance *inst, struct ckm_vfs_open_query *q);
#else
static inline bool ckm_vfs_file_get(struct file *file) { return false; }
static inline bool ckm_vfs_file_dput(struct file *file) { return false; }
#endif

int filename_lookup_lease(int dfd, struct filename *name, unsigned int flags,
			  struct path *path, struct ckm_path_lease *lease);

#ifdef CONFIG_CKERNEL_M_VFS
int ckm_vfs_init(struct ckm_instance *inst);
void ckm_vfs_drain(struct ckm_instance *inst);
void ckm_vfs_destroy(struct ckm_instance *inst);
int ckm_vfs_register(struct ckm_instance *inst, int fd, unsigned int capacity);
int ckm_vfs_bind(struct ckm_instance *inst);
void ckm_vfs_query(struct ckm_instance *inst, struct ckm_vfs_query *query);
void ckm_vfs_begin(struct ckm_path_lease *lease);
int ckm_vfs_complete_rcu(struct ckm_path_lease *lease, const struct path *path,
			 unsigned int seq, unsigned int mseq);
void ckm_vfs_end(struct ckm_path_lease *lease, struct path *path);
void ckm_vfs_before_write_remount(struct super_block *sb);
#else
#include <linux/namei.h>
#include <linux/mount.h>
static inline int ckm_vfs_init(struct ckm_instance *inst) { return 0; }
static inline void ckm_vfs_drain(struct ckm_instance *inst) {}
static inline void ckm_vfs_destroy(struct ckm_instance *inst) {}
static inline void ckm_vfs_before_write_remount(struct super_block *sb) {}
static inline void ckm_vfs_begin(struct ckm_path_lease *lease) {}
static inline int ckm_vfs_complete_rcu(struct ckm_path_lease *lease,
		const struct path *path, unsigned int seq, unsigned int mseq) { return 0; }
static inline void ckm_vfs_end(struct ckm_path_lease *lease, struct path *path)
{
	if (path)
		path_put(path);
}
#endif
#endif
