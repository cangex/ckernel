#ifndef _LINUX_CKERNEL_H
#define _LINUX_CKERNEL_H

#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/path.h>
#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <linux/namei.h>
#include <linux/percpu.h>
#include <linux/preempt.h>

#define CK_HASH_BITS 10

#define CKERNEL_FEATURE_APPARMOR		BIT_ULL(0)
#define CKERNEL_FEATURE_ACCT		BIT_ULL(1)
#define CKERNEL_FEATURE_VFS		BIT_ULL(2)
#define CKERNEL_FEATURE_MEMCG		BIT_ULL(3)
#define CKERNEL_FEATURE_SOCKET		BIT_ULL(4)
#define CKERNEL_FEATURE_SHMEM_LARGE	BIT_ULL(5)
#define CKERNEL_FEATURE_SHMEM_HOT	BIT_ULL(6)
#define CKERNEL_FEATURE_MONITOR		BIT_ULL(7)

#define CKERNEL_FEATURE_STANDARD_ALL	GENMASK_ULL(7, 0)

struct ck_rule {
	u64 hash;
	char *path;
	struct hlist_node node;
};

typedef bool (*ck_check_path_fn)(struct ckernel *ck, const struct path *path);
typedef bool (*ck_check_file_fn)(struct ckernel *ck, const struct file *file);
typedef bool (*ck_net_allow_fn)(struct ckernel *ck, int family, int type);

struct socket;
typedef bool (*ck_socket_token_check_fn)(struct ckernel *ck,
						 const struct socket *sock);
typedef void (*ck_socket_token_learn_fn)(struct ckernel *ck,
						 const struct socket *sock);

/* file descriptor accounting hooks
 *
 * return semantics:
 *   1  -> handled & success
 *   0  -> handled but failed (e.g., limit exceeded)
 *  -1  -> not handled (fallback to default path)
 */
typedef int (*ck_file_inc_fn)(u64 n);
typedef int (*ck_file_dec_fn)(u64 n);

/* Return an instance-lifetime-protected read object, or NULL for fallback. */
typedef struct file *(*ck_vfs_cache_get_fn)(struct ckernel *ck,
					    struct file *source);

enum ck_vfs_ref_kind {
	CK_VFS_REF_OPEN,
	CK_VFS_REF_STAT,
};

/*
 * A borrowed VFS path is pinned by one domain-owned path reference. Users
 * hold this opaque reference instead of bouncing the shared dentry lockref.
 */
struct ck_vfs_ref {
	void (*put)(struct ck_vfs_ref *ref);
	u64 ckernel_cookie;
	bool immutable_lease;
};

typedef struct ck_vfs_ref *(*ck_vfs_ref_lookup_fn)(struct ckernel *ck,
						    const char *name,
						    enum ck_vfs_ref_kind kind,
						    struct path *path);
typedef void (*ck_vfs_ref_learn_fn)(struct ckernel *ck, const char *name,
					    const struct path *path);

struct address_space;
struct folio;
typedef struct folio *(*ck_shmem_cache_lookup_fn)(struct ckernel *ck,
						   struct address_space *mapping,
						   pgoff_t index);
typedef void (*ck_shmem_cache_insert_fn)(struct ckernel *ck,
					  struct address_space *mapping,
					  pgoff_t index, struct folio *folio);

typedef void (*ck_exit_fn)(void);
typedef void (*ck_attch_rdtgrp_fn)(struct task_struct *task);
typedef void (*ck_task_security_cache_destroy_fn)(struct ckernel *ck);

struct ck_mm_meta_stats {
	unsigned long hits;
	unsigned long misses;
	unsigned long returns;
	unsigned long evictions;
};

struct ck_vfs_lease_stats {
	unsigned long hits;
	unsigned long misses;
	unsigned long fallbacks;
	unsigned long stale;
	unsigned long learns;
	unsigned long open_fast;
	unsigned long refs;
};

struct ck_socket_stock_stats {
	unsigned long learns;
	unsigned long misses;
	unsigned long hook_fast;
	unsigned long file_perm_fast;
	unsigned long clone_inherits;
};

struct ckernel {
	pid_t owner_pid;
	struct module *owner_module;
	u64 cookie;
	refcount_t refs;

	/* runtime control */
	bool online;

	DECLARE_HASHTABLE(path_table, CK_HASH_BITS);
	bool fast_check;

	/* Common LSM socket fast path for safe ckernel sockets. */
	bool socket_lsm_fast;
	atomic_long_t socket_create_fast;
	atomic_long_t socket_bind_fast;
	atomic_long_t socket_connect_fast;
	atomic_long_t socket_fast_fallback;
	bool socket_token_enabled;
	void *socket_token_domain;
	ck_socket_token_check_fn ck_socket_token_check;
	ck_socket_token_learn_fn ck_socket_token_learn;
	atomic_long_t socket_token_learns;
	atomic_long_t socket_token_misses;
	atomic_long_t socket_token_evictions;
	atomic_long_t socket_listen_fast;
	atomic_long_t socket_accept_fast;
	atomic_long_t socket_option_fast;
	atomic_long_t socket_shutdown_fast;
	atomic_long_t socket_file_perm_fast;
	bool socket_stock_enabled;
	struct ck_socket_stock_stats __percpu *socket_stock_stats;

	/* file descriptor accounting */
	atomic_long_t file_usage;
	atomic_long_t file_max;

	/* Use a bounded larger per-CPU memory charge stock. */
	bool memcg_stock_batch;
	atomic_long_t memcg_restock_pages;
	atomic_long_t memcg_restock_fallback_pages;

	/* Opt-in larger folios for buffered writes to shmem/tmpfs. */
	bool shmem_large_folio;
	unsigned int shmem_folio_order;
	atomic_long_t shmem_large_allocs;
	atomic_long_t shmem_large_fallbacks;

	/* Small per-CPU cache for hot tmpfs folio lookups. */
	bool shmem_hot_cache_enabled;
	void *shmem_hot_cache_domain;
	ck_shmem_cache_lookup_fn ck_shmem_cache_lookup;
	ck_shmem_cache_insert_fn ck_shmem_cache_insert;
	atomic_long_t shmem_hot_cache_hits;
	atomic_long_t shmem_hot_cache_misses;
	atomic_long_t shmem_hot_cache_stale;
	atomic_long_t shmem_hot_cache_fills;
	atomic_long_t shmem_hot_cache_evictions;

	/* Instance-local read-only VFS object/page-cache domain. */
	bool vfs_cache_enabled;
	void *vfs_cache_domain;
	ck_vfs_cache_get_fn ck_vfs_cache_get;
	atomic_long_t vfs_cache_hits;
	atomic_long_t vfs_cache_misses;
	atomic_long_t vfs_cache_fallbacks;
	atomic_long_t vfs_cache_rebuilds;
	atomic_long_t vfs_cache_bytes;

	/* Instance-local stable path/reference domain. */
	bool vfs_ref_enabled;
	ck_vfs_ref_lookup_fn ck_vfs_ref_lookup;
	ck_vfs_ref_learn_fn ck_vfs_ref_learn;
	atomic_long_t vfs_ref_hits;
	atomic_long_t vfs_ref_misses;
	atomic_long_t vfs_ref_fallbacks;
	atomic_long_t vfs_ref_stale;
	atomic_long_t vfs_ref_learns;
	atomic_long_t vfs_ref_open_fast;
	atomic_long_t vfs_ref_stat_fast;
	atomic_long_t vfs_ref_dget_avoided;
	bool immutable_path_lease_enabled;
	struct ck_vfs_lease_stats __percpu *vfs_lease_stats;

	/*ckernel-specific operations*/
	ck_exit_fn ck_exit;

	/*
	 * attach task to rdtgroup (MPAM-like policy)
	 */
	ck_attch_rdtgrp_fn ck_attch_rdtgrp;

	ck_check_path_fn ck_check_path;
	ck_check_file_fn ck_check_file;
	ck_net_allow_fn ck_net_fast_allow;

	ck_file_inc_fn ck_file_inc;
	ck_file_dec_fn ck_file_dec;
	bool file_accounting_started;

	/* Per-instance feature and topology metadata. Keep at the ABI tail. */
	u64 feature_mask;
	int home_nid;
	int home_l3c;

	/* AppArmor signal permissions cached within one CKernel instance. */
	bool task_security_cache_enabled;
	void *task_security_cache_domain;
	ck_task_security_cache_destroy_fn ck_task_security_cache_destroy;
	unsigned long __percpu *task_security_cache_hits;
	atomic_long_t task_security_cache_misses;
	atomic_long_t task_security_cache_learns;
	atomic_long_t task_security_cache_fallbacks;

	/* Bounded instance-cookie keyed Maple metadata stock on each CPU. */
	bool mm_meta_domain_enabled;
	struct ck_mm_meta_stats __percpu *mm_meta_stats;
};

enum ck_socket_stock_event {
	CK_SOCKET_STOCK_LEARN,
	CK_SOCKET_STOCK_MISS,
	CK_SOCKET_STOCK_HOOK_FAST,
	CK_SOCKET_STOCK_FILE_PERM_FAST,
	CK_SOCKET_STOCK_CLONE_INHERIT,
};

static inline void ck_socket_stock_count(struct ckernel *ck,
					 enum ck_socket_stock_event event)
{
	struct ck_socket_stock_stats *stats;

	if (!ck || !READ_ONCE(ck->socket_stock_enabled) ||
	    !READ_ONCE(ck->socket_stock_stats))
		return;

	preempt_disable();
	stats = this_cpu_ptr(ck->socket_stock_stats);
	switch (event) {
	case CK_SOCKET_STOCK_LEARN:
		stats->learns++;
		break;
	case CK_SOCKET_STOCK_MISS:
		stats->misses++;
		break;
	case CK_SOCKET_STOCK_HOOK_FAST:
		stats->hook_fast++;
		break;
	case CK_SOCKET_STOCK_FILE_PERM_FAST:
		stats->file_perm_fast++;
		break;
	case CK_SOCKET_STOCK_CLONE_INHERIT:
		stats->clone_inherits++;
		break;
	}
	preempt_enable();
}

#endif
