#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/ckernel.h>
#include <linux/user_namespace.h>
#include <linux/moduleparam.h>
#include <linux/resctrl.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/percpu.h>
#include <linux/delay.h>
#include <linux/kernfs.h>
#include <linux/sched.h>
#include <linux/memcontrol.h>
#include <linux/string.h>
#include <linux/maple_tree.h>

#include "ckernel_driver.h"

extern int ckernel_device_init(void);
extern void ckernel_device_exit(void);

extern int ckernel_proc_init(void);
extern void ckernel_proc_exit(void);

extern int ckernel_debugfs_init(void);
extern void ckernel_debugfs_exit(void);

static atomic64_t ckernel_cookie = ATOMIC64_INIT(0);

static struct kernfs_node *ck_online_kn = NULL;
static struct kernfs_node *ck_offline_kn = NULL;

static int ckernel_monitor = 0;
module_param(ckernel_monitor, int, 0644);
static bool ckernel_monitor_resctrl_ready;

/*
 * Enable/disable AppArmor fast-path via module parameter.
 */
static int ckernel_apparmor = 0;
module_param(ckernel_apparmor, int, 0644);

static int ckernel_task_security_cache;
module_param(ckernel_task_security_cache, int, 0644);
MODULE_PARM_DESC(ckernel_task_security_cache,
		 "Cache audited AppArmor signal permissions per CKernel instance");

static int ckernel_mm_meta_domain;
module_param(ckernel_mm_meta_domain, int, 0444);
MODULE_PARM_DESC(ckernel_mm_meta_domain,
		 "Use a bounded per-CPU Maple metadata stock per CKernel cookie");

/*
 * Enable per-container file descriptor accounting.
 *
 * When enabled:
 *   - file allocation is first charged to ckernel
 *   - fallback to cgroup if not handled
 */
static int ckernel_acct = 0;
module_param(ckernel_acct, int, 0644);

/*
 * Keep immutable container-image read objects private to each CKernel
 * instance. Unsafe or unsupported files always use the native VFS path.
 */
static int ckernel_vfs_cache = 1;
module_param(ckernel_vfs_cache, int, 0644);
MODULE_PARM_DESC(ckernel_vfs_cache,
		 "Enable the instance-local read-only VFS object cache");

static int ckernel_vfs_ref_cache = 1;
module_param(ckernel_vfs_ref_cache, int, 0644);
MODULE_PARM_DESC(ckernel_vfs_ref_cache,
		 "Enable the instance-local stable VFS path reference cache");

static int ckernel_immutable_path_lease;
module_param(ckernel_immutable_path_lease, int, 0444);
MODULE_PARM_DESC(ckernel_immutable_path_lease,
		 "Lease fully checked paths on instance-private read-only tmpfs mounts");

static int ckernel_memcg_stock = 1;
module_param(ckernel_memcg_stock, int, 0644);
MODULE_PARM_DESC(ckernel_memcg_stock,
		 "Use a bounded larger per-CPU memcg charge stock for CKernel tasks");

static int ckernel_shmem_large_folio;
module_param(ckernel_shmem_large_folio, int, 0644);
MODULE_PARM_DESC(ckernel_shmem_large_folio,
		 "Use larger shmem folios for buffered writes from CKernel tasks");

static unsigned int ckernel_shmem_folio_order = 3;
module_param(ckernel_shmem_folio_order, uint, 0644);
MODULE_PARM_DESC(ckernel_shmem_folio_order,
		 "Preferred shmem folio order for CKernel buffered writes");

static int ckernel_shmem_hot_cache;
module_param(ckernel_shmem_hot_cache, int, 0644);
MODULE_PARM_DESC(ckernel_shmem_hot_cache,
		 "Cache hot tmpfs folio lookups per CKernel instance and CPU");

static int ckernel_socket_fast = 1;
module_param(ckernel_socket_fast, int, 0644);
MODULE_PARM_DESC(ckernel_socket_fast,
		 "Enable ckernel common LSM socket fast paths for safe sockets");

static int ckernel_file_socket_stock;
module_param(ckernel_file_socket_stock, int, 0444);
MODULE_PARM_DESC(ckernel_file_socket_stock,
		 "Use per-CPU file lease refs and lifetime-bound socket capabilities");

static int faascale_memory = 0;
module_param(faascale_memory, int, 0644);
MODULE_PARM_DESC(faascale_memory,
		 "Enable ckernel-bound faascale memory allocator");

static int faascale_task_domain = 0;
module_param(faascale_task_domain, int, 0644);
MODULE_PARM_DESC(faascale_task_domain,
		 "Enable ckernel-bound faascale task domain fast paths");

#define CKERNELIO 0xAF
#define CKERNEL_INIT	_IO(CKERNELIO, 0x01)

struct ckernel_init_args_v1 {
	__u32 version;
	__s32 online;
	__u64 feature_mask;
	__s32 home_nid;
	__s32 home_l3c;
};

#define CKERNEL_INIT_EX	_IOW(CKERNELIO, 0x02, struct ckernel_init_args_v1)

static u64 ckernel_available_feature_mask(void)
{
	u64 mask = 0;

	if (ckernel_apparmor)
		mask |= CKERNEL_FEATURE_APPARMOR;
	if (ckernel_acct)
		mask |= CKERNEL_FEATURE_ACCT;
	if (ckernel_vfs_cache)
		mask |= CKERNEL_FEATURE_VFS;
	if (ckernel_memcg_stock)
		mask |= CKERNEL_FEATURE_MEMCG;
	if (ckernel_socket_fast)
		mask |= CKERNEL_FEATURE_SOCKET;
	if (ckernel_shmem_large_folio)
		mask |= CKERNEL_FEATURE_SHMEM_LARGE;
	if (ckernel_shmem_hot_cache)
		mask |= CKERNEL_FEATURE_SHMEM_HOT;
	if (ckernel_monitor)
		mask |= CKERNEL_FEATURE_MONITOR;
	return mask;
}

static bool ckernel_resctrl_mounted(void)
{
	struct path path;
	int ret;

	/*
	 * Check whether /sys/fs/resctrl exists and is mounted.
	 */
	ret = kern_path("/sys/fs/resctrl", LOOKUP_FOLLOW, &path);
	if (ret)
		return false;

	if (!path.mnt || !path.dentry || !path.dentry->d_sb ||
	    !path.dentry->d_sb->s_type ||
	    strcmp(path.dentry->d_sb->s_type->name, "resctrl") ||
	    path.dentry != path.mnt->mnt_root) {
		path_put(&path);
		return false;
	}

	path_put(&path);
	return true;
}

static void ckernel_monitor_resctrl_fallback(const char *reason, int ret)
{
	if (ret)
		pr_warn("ckernel: resctrl unavailable (%s, ret=%d); monitor remains active with scheduler isolation\n",
			reason, ret);
	else
		pr_warn("ckernel: resctrl unavailable (%s); monitor remains active with scheduler isolation\n",
			reason);

	ckernel_monitor_resctrl_ready = false;
	ck_online_kn = NULL;
	ck_offline_kn = NULL;
}

static void ck_do_attch_rdtgrp(struct task_struct *task)
{
	if (!ckernel_monitor || !task || !task->ckernel ||
	    !(READ_ONCE(task->ckernel->feature_mask) & CKERNEL_FEATURE_MONITOR))
		return;

	/* Scheduler suppression remains available without MPAM/resctrl. */
	if (!task->ckernel->online)
		sched_set_task_cfs_quota(task, 10000);

	if (!ckernel_monitor_resctrl_ready)
		return;

	ck_rdtgroup_move_task(task, task->ckernel->online ?
				      ck_online_kn : ck_offline_kn);
}

static void ck_free_rules(struct ckernel *ck)
{
	struct ck_rule *rule;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(ck->path_table, bkt, tmp, rule, node) {
		hash_del(&rule->node);
		kfree(rule);
	}
}

static void ck_do_exit(void)
{
	struct ckernel *ck = current->ckernel;
	struct module *owner_module;

	if (!ck)
		return;

	/*
	 * Clear the namespace owner pointer when the owner exits, but retain
	 * the shared object until every task that inherited it has exited.
	 */
	if (task_pid_nr(current) == ck->owner_pid) {
		pr_info("ckernel owner<%d> exit\n", task_pid_nr(current));
		current_user_ns()->ckernel = NULL;
	}

	if (!refcount_dec_and_test(&ck->refs))
		return;

	if (READ_ONCE(ck->socket_lsm_fast))
		pr_info("ckernel socket fast stats: create=%ld bind=%ld connect=%ld listen=%ld accept=%ld option=%ld shutdown=%ld learn=%ld miss=%ld evict=%ld fallback=%ld\n",
			atomic_long_read(&ck->socket_create_fast),
			atomic_long_read(&ck->socket_bind_fast),
			atomic_long_read(&ck->socket_connect_fast),
			atomic_long_read(&ck->socket_listen_fast),
			atomic_long_read(&ck->socket_accept_fast),
			atomic_long_read(&ck->socket_option_fast),
			atomic_long_read(&ck->socket_shutdown_fast),
			atomic_long_read(&ck->socket_token_learns),
			atomic_long_read(&ck->socket_token_misses),
			atomic_long_read(&ck->socket_token_evictions),
			atomic_long_read(&ck->socket_fast_fallback));
	owner_module = ck->owner_module;
	ck_socket_domain_destroy(ck);
	ck_shmem_cache_destroy(ck);
	ck_vfs_domain_destroy(ck);
	if (READ_ONCE(ck->ck_task_security_cache_destroy))
		ck->ck_task_security_cache_destroy(ck);
	if (ck->task_security_cache_hits)
		free_percpu(ck->task_security_cache_hits);
	if (ck->mm_meta_stats)
		free_percpu(ck->mm_meta_stats);
	ck_free_rules(ck);
	kfree(ck);
	module_put(owner_module);
}

static bool ckernel_alloc(int online_flag, u64 feature_mask,
			  int home_nid, int home_l3c)
{
	/*
	   Allocate and attach a per-task ckernel context.
	   This is intended to be called once per task (owner).
	 */
	struct ckernel *ck;

	/* //todo avoid double-alloc problem
	struct user_namespace *ns = current_user_ns();
	if (ns->ckernel) {
		current->ckernel = ns->ckernel;
		return true;
	}*/

	if (current->ckernel) {
		pr_warn("ckernel_alloc while current->ckernel \n");
		return true;
	}

	ck = kzalloc(sizeof(*ck), GFP_KERNEL);
	if (!ck)
		return false;

	ck->cookie = atomic64_inc_return(&ckernel_cookie);
	refcount_set(&ck->refs, 1);
	ck->feature_mask = feature_mask;
	ck->home_nid = home_nid;
	ck->home_l3c = home_l3c;
	hash_init(ck->path_table);
	/*
	 * Initialize ckernel instance.
	 *
	 * When fast-path is enabled:
	 *   - Install fast-check callbacks
	 *   - Enable fast_check flag
	 *
	 * Otherwise:
	 *   - Install no-op (skip) handlers
	 */
	if (ckernel_apparmor &&
	    (feature_mask & CKERNEL_FEATURE_APPARMOR)) {
		ck_init_rules(ck);
		ck->ck_check_path = ck_check_path;
		ck->ck_check_file = ck_check_file;
		ck->ck_net_fast_allow = ck_net_fast_allow;
		ck->fast_check = true;
	} else {
		ck->ck_check_path = ck_skip_check_path;
                ck->ck_check_file = ck_skip_check_file;
                ck->ck_net_fast_allow = ck_skip_net_fast_allow;
		ck->fast_check = false;
	}
	ck->task_security_cache_enabled = ckernel_task_security_cache != 0 &&
		ck->fast_check;
	ck->task_security_cache_domain = NULL;
	ck->ck_task_security_cache_destroy = NULL;
	ck->task_security_cache_hits = NULL;
	if (ck->task_security_cache_enabled) {
		ck->task_security_cache_hits = alloc_percpu(unsigned long);
		if (!ck->task_security_cache_hits)
			ck->task_security_cache_enabled = false;
	}
	atomic_long_set(&ck->task_security_cache_misses, 0);
	atomic_long_set(&ck->task_security_cache_learns, 0);
	atomic_long_set(&ck->task_security_cache_fallbacks, 0);
	ck->mm_meta_domain_enabled = ckernel_mm_meta_domain != 0;
	ck->mm_meta_stats = NULL;
	if (ck->mm_meta_domain_enabled) {
		ck->mm_meta_stats = alloc_percpu(struct ck_mm_meta_stats);
		if (!ck->mm_meta_stats)
			ck->mm_meta_domain_enabled = false;
	}

	ck->socket_lsm_fast = ckernel_socket_fast && ck->fast_check &&
		(feature_mask & CKERNEL_FEATURE_SOCKET);
	atomic_long_set(&ck->socket_create_fast, 0);
	atomic_long_set(&ck->socket_bind_fast, 0);
	atomic_long_set(&ck->socket_connect_fast, 0);
	atomic_long_set(&ck->socket_fast_fallback, 0);
	atomic_long_set(&ck->socket_listen_fast, 0);
	atomic_long_set(&ck->socket_accept_fast, 0);
	atomic_long_set(&ck->socket_option_fast, 0);
	atomic_long_set(&ck->socket_shutdown_fast, 0);
	atomic_long_set(&ck->socket_file_perm_fast, 0);
	if (ck_socket_domain_init(ck, ck->socket_lsm_fast,
				  ckernel_file_socket_stock != 0)) {
		ck->socket_lsm_fast = false;
		pr_warn("ckernel: failed to initialize socket token domain; using native LSM hooks\n");
	}

	/*
	 * Initialize file accounting state.
	 *
	 * file_max defaults to D_COUNT_MAX (same as global limit),
	 * can be extended to support per-container quota.
	 * todo suuport dynamic adjustment
	 */
	atomic_long_set(&ck->file_usage, 0);
	ck->file_accounting_started = false;
	atomic_long_set(&ck->file_max, D_COUNT_MAX);
	if (ckernel_acct && (feature_mask & CKERNEL_FEATURE_ACCT)) {
		ck->ck_file_inc = ck_do_file_inc;
		ck->ck_file_dec = ck_do_file_dec;
	} else {
		ck->ck_file_inc = ck_skip_file_inc;
		ck->ck_file_dec = ck_skip_file_dec;
	}

	if (ck_vfs_domain_init(ck,
			       ckernel_vfs_cache != 0 &&
			       (feature_mask & CKERNEL_FEATURE_VFS),
			       ckernel_vfs_ref_cache != 0 &&
			       (feature_mask & CKERNEL_FEATURE_VFS),
			       ckernel_immutable_path_lease != 0 &&
			       (feature_mask & CKERNEL_FEATURE_VFS)))
		pr_warn("ckernel: failed to initialize VFS cache domain; using native VFS\n");

	ck->memcg_stock_batch = ckernel_memcg_stock != 0 &&
		(feature_mask & CKERNEL_FEATURE_MEMCG);
	atomic_long_set(&ck->memcg_restock_pages, 0);
	atomic_long_set(&ck->memcg_restock_fallback_pages, 0);
	ck->shmem_large_folio = ckernel_shmem_large_folio != 0 &&
		(feature_mask & CKERNEL_FEATURE_SHMEM_LARGE);
	ck->shmem_folio_order = ckernel_shmem_folio_order;
	atomic_long_set(&ck->shmem_large_allocs, 0);
	atomic_long_set(&ck->shmem_large_fallbacks, 0);
	if (ck_shmem_cache_init(ck, ckernel_shmem_hot_cache != 0 &&
				(feature_mask & CKERNEL_FEATURE_SHMEM_HOT)))
		pr_warn("ckernel: failed to initialize shmem hot cache; using native lookup\n");
	ck->owner_pid = current->pid;
	ck->online = online_flag ? true : false;
	pr_info("ckernel mode: %d \n", ck->online);
	current->ckernel = ck;
	ck_do_attch_rdtgrp(current);
	if (!ck->online)
		sched_set_task_cfs_quota(current, 100000);
	//ns->ckernel = ck;
	ck->owner_module = THIS_MODULE;
	try_module_get(THIS_MODULE);

	/* Register lifecycle callback invoked from do_exit(). */
	ck->ck_exit = ck_do_exit;
	ck->ck_attch_rdtgrp = ck_do_attch_rdtgrp;

	pr_info("ckernel init owner=%d features=%#llx home_nid=%d home_l3c=%d\n",
		current->pid, feature_mask, home_nid, home_l3c);
	return true;
}

static long ckernel_ioctl(struct file *f,
		unsigned int cmd,
		unsigned long arg)
{
	int r = 0;
	int online_flag = 0;
	u64 available_features = ckernel_available_feature_mask();
	struct ckernel_init_args_v1 init_args;

	/* Simple ioctl interface for initializing ckernel context. */
	switch (cmd) {
		case CKERNEL_INIT:
			if (copy_from_user(&online_flag,
						(int __user *)arg,
						sizeof(int))) {
				pr_err("ckernel: failed to copy arg\n");
				return -EFAULT;
			}
			r = ckernel_alloc(online_flag, available_features,
					  -1, -1) ? 0 : -EEXIST;
			break;
		case CKERNEL_INIT_EX:
			if (copy_from_user(&init_args,
					   (void __user *)arg,
					   sizeof(init_args))) {
				pr_err("ckernel: failed to copy extended init args\n");
				return -EFAULT;
			}
			if (init_args.version != 1)
				return -EINVAL;
			if (init_args.feature_mask & ~CKERNEL_FEATURE_STANDARD_ALL)
				return -EINVAL;
			if (init_args.feature_mask & ~available_features)
				pr_info("ckernel: cap requested features %#llx to available %#llx\n",
					init_args.feature_mask, available_features);
			if (init_args.home_nid < -1 || init_args.home_l3c < -1)
				return -EINVAL;
			r = ckernel_alloc(init_args.online,
					  init_args.feature_mask & available_features,
					  init_args.home_nid,
					  init_args.home_l3c) ? 0 : -EEXIST;
			break;
		default:
			return -ENOTTY;
	}

	return r;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ckernel_ioctl,
};

static struct miscdevice ckernel_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ckernel",
	.fops = &fops,
};

static int __init ckernel_init(void)
{
	if (ckernel_mm_meta_domain)
		ck_maple_meta_domain_enable();

	misc_register(&ckernel_dev);
	ckernel_proc_init();
	ckernel_debugfs_init();

	ckernel_monitor_resctrl_ready = false;
	if (ckernel_monitor) {
		int ret;

		if (!ckernel_resctrl_mounted()) {
			ckernel_monitor_resctrl_fallback(
				"resctrl is not mounted and ready", -ENODEV);
			goto enable_faascale_features;
		}

		ret = ck_rdtgroup_mkdir("ckernel-online", &ck_online_kn);
		if (ret || !ck_online_kn) {
			ckernel_monitor_resctrl_fallback(
				"failed to create ckernel-online", ret ? ret : -ENODEV);
			goto enable_faascale_features;
		}

		ret = ck_rdtgroup_mkdir("ckernel-offline", &ck_offline_kn);
		if (ret || !ck_offline_kn) {
			ckernel_monitor_resctrl_fallback(
				"failed to create ckernel-offline", ret ? ret : -ENODEV);
			goto enable_faascale_features;
		}
		/*
		 * Configure bandwidth / priority / min bandwidth
		 * NOTE: these are MPAM-style control hints mapped to resctrl
		 */

		char online_mb[] = "MB:0=100;1=100;2=100;3=100";
		char *online_str = online_mb;
		ret = ck_rdtgroup_schemata_write(ck_online_kn, online_str);
		if (ret) {
			ckernel_monitor_resctrl_fallback("online MB schema unsupported", ret);
			goto enable_faascale_features;
		}
		char online_pri[] = "MBPRI:0=7;1=7;2=7;3=7";
		online_str = online_pri;
		ret = ck_rdtgroup_schemata_write(ck_online_kn, online_str);
		if (ret) {
			ckernel_monitor_resctrl_fallback("online MBPRI schema unsupported", ret);
			goto enable_faascale_features;
		}
		char online_min[] = "MBMIN:0=100;1=100;2=100;3=100";
		online_str = online_min;
		ret = ck_rdtgroup_schemata_write(ck_online_kn, online_str);
		if (ret) {
			ckernel_monitor_resctrl_fallback("online MBMIN schema unsupported", ret);
			goto enable_faascale_features;
		}

		char offline_mb[] = "MB:0=1;1=1;2=1;3=1";
		char *offline_str = offline_mb;
		ret = ck_rdtgroup_schemata_write(ck_offline_kn, offline_str);
		if (ret) {
			ckernel_monitor_resctrl_fallback("offline MB schema unsupported", ret);
			goto enable_faascale_features;
		}
		char offline_pri[] = "MBPRI:0=1;1=1;2=1;3=1";
		offline_str = offline_pri;
		ret = ck_rdtgroup_schemata_write(ck_offline_kn, offline_str);
		if (ret) {
			ckernel_monitor_resctrl_fallback("offline MBPRI schema unsupported", ret);
			goto enable_faascale_features;
		}

		ret = ckernel_mbm_start(ck_online_kn, ck_offline_kn);
		if (ret) {
			ckernel_monitor_resctrl_fallback("mbm start failed", ret);
			goto enable_faascale_features;
		}
		ckernel_monitor_resctrl_ready = true;
	}

enable_faascale_features:
	faascale_ckernel_set_features_enabled(faascale_memory != 0,
					      faascale_task_domain != 0);
	pr_info("ckernel: init\n");
	return 0;
}

static void __exit ckernel_exit(void)
{
	faascale_ckernel_set_features_enabled(false, false);
	ckernel_debugfs_exit();
	ckernel_proc_exit();
	misc_deregister(&ckernel_dev);

	if (ckernel_monitor_resctrl_ready) {
		ckernel_mbm_stop();
		// todo rmdir online and offline
		//rdtgroup_rmdir(ck_online_kn);
		//rdtgroup_rmdir(ck_offline_kn);
		ck_online_kn = NULL;
		ck_offline_kn = NULL;
	}
	if (ckernel_mm_meta_domain)
		ck_maple_meta_domain_disable();

	pr_info("ckernel: exit\n");
}

module_init(ckernel_init);
module_exit(ckernel_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hang Huang");
MODULE_DESCRIPTION("CKernel driver");
