// SPDX-License-Identifier: GPL-2.0
/* Dedicated-VM oracle: actual node locks, not manually emitted observer events. */
#include <linux/capability.h>
#include <linux/cis_slub_test.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "uapi.h"

static struct kmem_cache *cache;
static DEFINE_MUTEX(control);
static atomic_t users = ATOMIC_INIT(0), entered[2];
static u64 token;
static void ctor(void *object) { memset(object, 0, 128); }
static struct kmem_cache *create_cache(void)
{
	return kmem_cache_create("cis_slub_fixture", 128, 0, SLAB_HWCACHE_ALIGN, ctor);
}

static long fixture_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct cis_slub_request r;
	struct cis_slub_test_truth t = {};
	u64 deadline;
	int result = 0;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN)) return -EPERM;
	if (command != CIS_SLUB_RESET && command != CIS_SLUB_OPERATE &&
	    command != CIS_SLUB_RECREATE) return -ENOTTY;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r))) return -EFAULT;
	if (!r.token || r.node > 1 || r.wait_node > 1 || r.wait_holders > 16 ||
	    r.hold_us > 5000 || r.mode > 1) return -EINVAL;
	mutex_lock(&control);
	if (command != CIS_SLUB_OPERATE) {
		if (atomic_read(&users) || r.token <= token) result = -EBUSY;
		else {
			if (command == CIS_SLUB_RECREATE) {
				kmem_cache_destroy(cache);
				cache = create_cache();
			}
			token = r.token;
			atomic_set(&entered[0], 0); atomic_set(&entered[1], 0);
			if (!cache) result = -ENOMEM;
		}
	} else if (!cache || token != r.token) result = -ESTALE;
	else atomic_inc(&users);
	mutex_unlock(&control);
	if (result) return result;
	r.task = ((u64)task_tgid_nr(current) << 32) | task_pid_nr(current);
	if (command != CIS_SLUB_OPERATE) goto output;
	deadline = ktime_get_ns() + 500000000;
	while (atomic_read(&entered[r.wait_node]) < r.wait_holders) {
		if (ktime_get_ns() >= deadline) { result = -ETIMEDOUT; goto leave; }
		usleep_range(50, 100);
	}
	if (!r.mode) {
		result = cis_slub_test_lock(cache, r.node, r.hold_us, &entered[r.node], &t);
		r.cache = t.cache; r.object = t.object; r.begin_ns = t.begin_ns;
		r.acquired_ns = t.acquired_ns; r.release_ns = t.release_ns; r.end_ns = t.end_ns;
	} else {
		/* Ordinary allocator bridge, not a synthetic ownership relation oracle. */
		void *objects[64];
		size_t got;
		r.begin_ns = ktime_get_ns();
		got = kmem_cache_alloc_bulk(cache, GFP_KERNEL, ARRAY_SIZE(objects), objects);
		if (got) kmem_cache_free_bulk(cache, got, objects);
		if (got != ARRAY_SIZE(objects)) result = -ENOMEM;
		if (!result) kmem_cache_shrink(cache);
		r.end_ns = ktime_get_ns(); r.cache = (unsigned long)cache;
	}
leave:
	atomic_dec(&users);
	if (result) return result;
	r.outcome = 1;
output:
	return copy_to_user((void __user *)arg, &r, sizeof(r)) ? -EFAULT : 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE, .unlocked_ioctl = fixture_ioctl, .llseek = no_llseek,
};
static struct miscdevice device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-slub-test", .fops = &fops, .mode = 0600,
};
static int __init fixture_init(void)
{
	int result;
	cache = create_cache();
	if (!cache) return -ENOMEM;
	result = misc_register(&device);
	if (result) kmem_cache_destroy(cache);
	return result;
}
static void __exit fixture_exit(void)
{
	misc_deregister(&device);
	kmem_cache_destroy(cache);
}
module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable-VM native SLUB node lock truth fixture");
