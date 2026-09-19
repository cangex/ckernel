// SPDX-License-Identifier: GPL-2.0
/* Disposable VM truth source, independent of CIS events/maps. */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/maple_tree.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "uapi.h"

struct maple_file {
	struct mutex lock;
	struct maple_tree tree[2];
	u32 next;
	u64 generation;
};

static int maple_open(struct inode *inode, struct file *file)
{
	struct maple_file *s;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN)) return -EPERM;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) return -ENOMEM;
	mutex_init(&s->lock);
	mt_init_flags(&s->tree[0], MT_FLAGS_USE_RCU);
	mt_init_flags(&s->tree[1], MT_FLAGS_USE_RCU);
	s->generation = 1; s->next = 1; file->private_data = s;
	return 0;
}

static int maple_release(struct inode *inode, struct file *file)
{
	struct maple_file *s = file->private_data;
	mtree_destroy(&s->tree[0]); mtree_destroy(&s->tree[1]);
	/* The fixture, not production code, waits for its test callbacks. */
	rcu_barrier(); kfree(s);
	return 0;
}

static long maple_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct maple_file *s = file->private_data;
	struct cis_maple_truth q;
	unsigned int i, tree;
	int result = 0;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN)) return -EPERM;
	if (command != CIS_MAPLE_TRUTH) return -ENOTTY;
	if (copy_from_user(&q, (void __user *)arg, sizeof(q))) return -EFAULT;
	if (q.version != 1 || q.action < 1 || q.action > 4) return -EINVAL;
	mutex_lock(&s->lock);
	if (q.action != s->next) { result = -EINVAL; goto unlock; }
	q.begin_ns = ktime_get_ns(); q.cpu = raw_smp_processor_id(); q.verified = 0;
	q.generation = s->generation;
	q.tree[0] = (unsigned long)&s->tree[0]; q.tree[1] = (unsigned long)&s->tree[1];
	if (q.action == 1) {
		for (i = 0; i < 32; i++) {
			result = mtree_store(&s->tree[0], i * 4, (void *)(unsigned long)((i + 1) * 16), GFP_KERNEL);
			if (result) goto out;
		}
	} else if (q.action == 2) {
		result = mtree_dup(&s->tree[0], &s->tree[1], GFP_KERNEL);
		if (result) goto out;
	} else if (q.action == 3) {
		mtree_destroy(&s->tree[0]); mtree_destroy(&s->tree[1]); rcu_barrier();
	} else {
		/* Deliberate address reuse after complete native destruction. */
		mt_init_flags(&s->tree[0], MT_FLAGS_USE_RCU);
		mt_init_flags(&s->tree[1], MT_FLAGS_USE_RCU); s->generation++;
	}
	if (q.action <= 2) {
		rcu_read_lock();
		for (tree = 0; tree < q.action; tree++)
			for (i = 0; i < 32; i++)
				if (mtree_load(&s->tree[tree], i * 4) == (void *)(unsigned long)((i + 1) * 16))
					q.verified++;
		rcu_read_unlock();
		if (q.verified != 32 * q.action) { result = -EIO; goto out; }
	}
	s->next = q.action == 4 ? 1 : q.action + 1;
out:
	q.end_ns = ktime_get_ns();
	if (copy_to_user((void __user *)arg, &q, sizeof(q))) result = -EFAULT;
unlock:
	mutex_unlock(&s->lock); return result;
}
static const struct file_operations maple_fops = {
	.owner = THIS_MODULE, .open = maple_open, .release = maple_release,
	.unlocked_ioctl = maple_ioctl, .llseek = no_llseek,
};
static struct miscdevice maple_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-maple-test", .mode = 0600, .fops = &maple_fops,
};
static int __init maple_init(void) { return misc_register(&maple_device); }
static void __exit maple_exit(void) { misc_deregister(&maple_device); rcu_barrier(); }
module_init(maple_init);
module_exit(maple_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable VM Maple destination/copy/reuse truth; no allocator algorithm changes");
