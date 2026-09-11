#include <linux/ckernel.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>

#include "ckernel_driver.h"

#define PROC_NAME "ckernel"

static int ckernel_show(struct seq_file *m, void *v)
{
	struct ckernel *ck = READ_ONCE(current->ckernel);
	unsigned long task_security_cache_hits = 0;
	struct ck_mm_meta_stats mm_meta = {};
	struct ck_vfs_lease_stats vfs_lease = {};
	struct ck_socket_stock_stats socket_stock = {};
	int cpu;

	seq_printf(m, "ckernel procfs interface\n");
	if (!ck) {
		seq_puts(m, "current_ckernel 0\n");
		return 0;
	}

	seq_puts(m, "current_ckernel 1\n");
	seq_printf(m, "feature_mask 0x%llx\n",
		   READ_ONCE(ck->feature_mask));
	seq_printf(m, "home_nid %d\n", READ_ONCE(ck->home_nid));
	seq_printf(m, "home_l3c %d\n", READ_ONCE(ck->home_l3c));
	seq_printf(m, "fast_check %d\n", READ_ONCE(ck->fast_check) ? 1 : 0);
	seq_printf(m, "task_security_cache_enabled %d\n",
		   READ_ONCE(ck->task_security_cache_enabled) ? 1 : 0);
	if (ck->task_security_cache_hits) {
		for_each_possible_cpu(cpu)
			task_security_cache_hits += READ_ONCE(
				*per_cpu_ptr(ck->task_security_cache_hits, cpu));
	}
	seq_printf(m, "task_security_cache_hits %lu\n",
		   task_security_cache_hits);
	seq_printf(m, "task_security_cache_misses %ld\n",
		   atomic_long_read(&ck->task_security_cache_misses));
	seq_printf(m, "task_security_cache_learns %ld\n",
		   atomic_long_read(&ck->task_security_cache_learns));
	seq_printf(m, "task_security_cache_fallbacks %ld\n",
		   atomic_long_read(&ck->task_security_cache_fallbacks));
	seq_printf(m, "mm_meta_domain_enabled %d\n",
		   READ_ONCE(ck->mm_meta_domain_enabled) ? 1 : 0);
	if (ck->mm_meta_stats) {
		for_each_possible_cpu(cpu) {
			struct ck_mm_meta_stats *stats;

			stats = per_cpu_ptr(ck->mm_meta_stats, cpu);
			mm_meta.hits += READ_ONCE(stats->hits);
			mm_meta.misses += READ_ONCE(stats->misses);
			mm_meta.returns += READ_ONCE(stats->returns);
			mm_meta.evictions += READ_ONCE(stats->evictions);
		}
	}
	seq_printf(m, "mm_meta_hits %lu\n", mm_meta.hits);
	seq_printf(m, "mm_meta_misses %lu\n", mm_meta.misses);
	seq_printf(m, "mm_meta_returns %lu\n", mm_meta.returns);
	seq_printf(m, "mm_meta_evictions %lu\n", mm_meta.evictions);
	seq_printf(m, "socket_lsm_fast %d\n",
		   READ_ONCE(ck->socket_lsm_fast) ? 1 : 0);
	seq_printf(m, "socket_create_fast %ld\n",
		   atomic_long_read(&ck->socket_create_fast));
	seq_printf(m, "socket_bind_fast %ld\n",
		   atomic_long_read(&ck->socket_bind_fast));
	seq_printf(m, "socket_connect_fast %ld\n",
		   atomic_long_read(&ck->socket_connect_fast));
	seq_printf(m, "socket_fast_fallback %ld\n",
		   atomic_long_read(&ck->socket_fast_fallback));
	seq_printf(m, "socket_token_enabled %d\n",
		   READ_ONCE(ck->socket_token_enabled) ? 1 : 0);
	seq_printf(m, "socket_token_learns %ld\n",
		   atomic_long_read(&ck->socket_token_learns));
	seq_printf(m, "socket_token_misses %ld\n",
		   atomic_long_read(&ck->socket_token_misses));
	seq_printf(m, "socket_token_evictions %ld\n",
		   atomic_long_read(&ck->socket_token_evictions));
	seq_printf(m, "socket_listen_fast %ld\n",
		   atomic_long_read(&ck->socket_listen_fast));
	seq_printf(m, "socket_accept_fast %ld\n",
		   atomic_long_read(&ck->socket_accept_fast));
	seq_printf(m, "socket_option_fast %ld\n",
		   atomic_long_read(&ck->socket_option_fast));
	seq_printf(m, "socket_shutdown_fast %ld\n",
		   atomic_long_read(&ck->socket_shutdown_fast));
	seq_printf(m, "socket_file_perm_fast %ld\n",
		   atomic_long_read(&ck->socket_file_perm_fast));
	if (ck->socket_stock_stats) {
		for_each_possible_cpu(cpu) {
			struct ck_socket_stock_stats *stats;

			stats = per_cpu_ptr(ck->socket_stock_stats, cpu);
			socket_stock.learns += READ_ONCE(stats->learns);
			socket_stock.misses += READ_ONCE(stats->misses);
			socket_stock.hook_fast += READ_ONCE(stats->hook_fast);
			socket_stock.file_perm_fast +=
				READ_ONCE(stats->file_perm_fast);
			socket_stock.clone_inherits +=
				READ_ONCE(stats->clone_inherits);
		}
	}
	seq_printf(m, "socket_stock_enabled %d\n",
		   READ_ONCE(ck->socket_stock_enabled) ? 1 : 0);
	seq_printf(m, "socket_stock_learns %lu\n", socket_stock.learns);
	seq_printf(m, "socket_stock_misses %lu\n", socket_stock.misses);
	seq_printf(m, "socket_stock_hook_fast %lu\n", socket_stock.hook_fast);
	seq_printf(m, "socket_stock_file_perm_fast %lu\n",
		   socket_stock.file_perm_fast);
	seq_printf(m, "socket_stock_clone_inherits %lu\n",
		   socket_stock.clone_inherits);
	seq_printf(m, "vfs_cache_enabled %d\n",
		   READ_ONCE(ck->vfs_cache_enabled) ? 1 : 0);
	seq_printf(m, "vfs_cache_hits %ld\n",
		   atomic_long_read(&ck->vfs_cache_hits));
	seq_printf(m, "vfs_cache_misses %ld\n",
		   atomic_long_read(&ck->vfs_cache_misses));
	seq_printf(m, "vfs_cache_fallbacks %ld\n",
		   atomic_long_read(&ck->vfs_cache_fallbacks));
	seq_printf(m, "vfs_cache_rebuilds %ld\n",
		   atomic_long_read(&ck->vfs_cache_rebuilds));
	seq_printf(m, "vfs_cache_bytes %ld\n",
		   atomic_long_read(&ck->vfs_cache_bytes));
	seq_printf(m, "vfs_ref_enabled %d\n",
		   READ_ONCE(ck->vfs_ref_enabled) ? 1 : 0);
	seq_printf(m, "vfs_ref_hits %ld\n",
		   atomic_long_read(&ck->vfs_ref_hits));
	seq_printf(m, "vfs_ref_misses %ld\n",
		   atomic_long_read(&ck->vfs_ref_misses));
	seq_printf(m, "vfs_ref_fallbacks %ld\n",
		   atomic_long_read(&ck->vfs_ref_fallbacks));
	seq_printf(m, "vfs_ref_stale %ld\n",
		   atomic_long_read(&ck->vfs_ref_stale));
	seq_printf(m, "vfs_ref_learns %ld\n",
		   atomic_long_read(&ck->vfs_ref_learns));
	seq_printf(m, "vfs_ref_open_fast %ld\n",
		   atomic_long_read(&ck->vfs_ref_open_fast));
	seq_printf(m, "vfs_ref_stat_fast %ld\n",
		   atomic_long_read(&ck->vfs_ref_stat_fast));
	seq_printf(m, "vfs_ref_dget_avoided %ld\n",
		   atomic_long_read(&ck->vfs_ref_dget_avoided));
	if (ck->vfs_lease_stats) {
		for_each_possible_cpu(cpu) {
			struct ck_vfs_lease_stats *stats;

			stats = per_cpu_ptr(ck->vfs_lease_stats, cpu);
			vfs_lease.hits += READ_ONCE(stats->hits);
			vfs_lease.misses += READ_ONCE(stats->misses);
			vfs_lease.fallbacks += READ_ONCE(stats->fallbacks);
			vfs_lease.stale += READ_ONCE(stats->stale);
			vfs_lease.learns += READ_ONCE(stats->learns);
			vfs_lease.open_fast += READ_ONCE(stats->open_fast);
			vfs_lease.refs += READ_ONCE(stats->refs);
		}
	}
	seq_printf(m, "immutable_path_lease_enabled %d\n",
		   READ_ONCE(ck->immutable_path_lease_enabled) ? 1 : 0);
	seq_printf(m, "immutable_path_lease_hits %lu\n", vfs_lease.hits);
	seq_printf(m, "immutable_path_lease_misses %lu\n", vfs_lease.misses);
	seq_printf(m, "immutable_path_lease_fallbacks %lu\n",
		   vfs_lease.fallbacks);
	seq_printf(m, "immutable_path_lease_stale %lu\n", vfs_lease.stale);
	seq_printf(m, "immutable_path_lease_learns %lu\n", vfs_lease.learns);
	seq_printf(m, "immutable_path_lease_open_fast %lu\n",
		   vfs_lease.open_fast);
	seq_printf(m, "immutable_path_lease_refs %lu\n", vfs_lease.refs);
	seq_printf(m, "memcg_restock_pages %ld\n",
		   atomic_long_read(&ck->memcg_restock_pages));
	seq_printf(m, "memcg_restock_fallback_pages %ld\n",
		   atomic_long_read(&ck->memcg_restock_fallback_pages));
	seq_printf(m, "shmem_large_folio %d\n",
		   READ_ONCE(ck->shmem_large_folio) ? 1 : 0);
	seq_printf(m, "shmem_folio_order %u\n",
		   READ_ONCE(ck->shmem_folio_order));
	seq_printf(m, "shmem_large_allocs %ld\n",
		   atomic_long_read(&ck->shmem_large_allocs));
	seq_printf(m, "shmem_large_fallbacks %ld\n",
		   atomic_long_read(&ck->shmem_large_fallbacks));
	seq_printf(m, "shmem_hot_cache_enabled %d\n",
		   READ_ONCE(ck->shmem_hot_cache_enabled) ? 1 : 0);
	ck_shmem_cache_refresh_stats(ck);
	seq_printf(m, "shmem_hot_cache_hits %ld\n",
		   atomic_long_read(&ck->shmem_hot_cache_hits));
	seq_printf(m, "shmem_hot_cache_misses %ld\n",
		   atomic_long_read(&ck->shmem_hot_cache_misses));
	seq_printf(m, "shmem_hot_cache_stale %ld\n",
		   atomic_long_read(&ck->shmem_hot_cache_stale));
	seq_printf(m, "shmem_hot_cache_fills %ld\n",
		   atomic_long_read(&ck->shmem_hot_cache_fills));
	seq_printf(m, "shmem_hot_cache_evictions %ld\n",
		   atomic_long_read(&ck->shmem_hot_cache_evictions));
	return 0;
}

static int ckernel_open(struct inode *inode, struct file *file)
{
	return single_open(file, ckernel_show, NULL);
}

static const struct proc_ops proc_fops = {
	.proc_open = ckernel_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static struct proc_dir_entry *entry;

int ckernel_proc_init(void)
{
	entry = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
	return 0;
}

void ckernel_proc_exit(void)
{
	proc_remove(entry);
}
