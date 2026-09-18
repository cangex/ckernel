// SPDX-License-Identifier: GPL-2.0
/* Dedicated disposable VM only. Real SLUB allocation, no injected lock delay. */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/cis_alloc_test.h>

static struct kmem_cache *caches[2];
struct alloc_file {
	struct mutex lock;
	void *objects[CIS_AT_MAX];
	u32 count, cache;
};

static void release_objects(struct alloc_file *state, bool bulk)
{
	u32 i;
	if (bulk)
		kmem_cache_free_bulk(caches[state->cache], state->count, state->objects);
	else
		for (i = 0; i < state->count; i++)
			kmem_cache_free(caches[state->cache], state->objects[i]);
	state->count = 0;
}

static int alloc_open(struct inode *inode, struct file *file)
{
	struct alloc_file *state;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->lock);
	file->private_data = state;
	return 0;
}

static int alloc_release(struct inode *inode, struct file *file)
{
	struct alloc_file *state = file->private_data;
	release_objects(state, false);
	kfree(state);
	return 0;
}

static long alloc_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct alloc_file *state = file->private_data;
	struct cis_alloc_test_request request;
	long result = 0;
	u32 i;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (command != CIS_ALLOC_TEST_RUN)
		return -ENOTTY;
	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.cache > 1 || request.bulk > 1 || request.reserved[0] || request.reserved[1] ||
	    request.action < CIS_AT_ALLOC || request.action > CIS_AT_SHRINK ||
	    request.count > CIS_AT_MAX || (request.action == CIS_AT_ALLOC && !request.count) ||
	    (request.action != CIS_AT_ALLOC && request.count))
		return -EINVAL;
	mutex_lock(&state->lock);
	request.returned = 0;
	request.cache_address = (unsigned long)caches[request.cache];
	request.cpu = raw_smp_processor_id();
	request.begin_ns = ktime_get_ns();
	if (request.action == CIS_AT_ALLOC) {
		if (state->count) {
			result = -EBUSY;
			goto out;
		}
		state->cache = request.cache;
		if (request.bulk) {
			state->count = kmem_cache_alloc_bulk(caches[state->cache], GFP_KERNEL,
					request.count, state->objects);
		} else {
			for (i = 0; i < request.count; i++) {
				void *object = kmem_cache_alloc(caches[state->cache], GFP_KERNEL);
				if (!object)
					break;
				state->objects[state->count++] = object;
			}
		}
		request.returned = state->count;
	} else if (request.action == CIS_AT_FREE) {
		if (request.cache != state->cache) {
			result = -EINVAL;
			goto out;
		}
		request.returned = state->count;
		release_objects(state, request.bulk);
	} else {
		/* Explicit fixture setup action, not a production fast path. */
		result = kmem_cache_shrink(caches[request.cache]);
	}
out:
	request.end_ns = ktime_get_ns();
	mutex_unlock(&state->lock);
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return result;
}

static const struct file_operations alloc_fops = {
	.owner = THIS_MODULE,
	.open = alloc_open,
	.release = alloc_release,
	.unlocked_ioctl = alloc_ioctl,
	.llseek = no_llseek,
};
static struct miscdevice alloc_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-alloc-test", .mode = 0600,
	.fops = &alloc_fops,
};

static void alloc_ctor(void *object) { }

static int __init alloc_init(void)
{
	int error;
	/* The ctor prevents merging the two otherwise identical test caches. */
	caches[0] = kmem_cache_create("cis_alloc_test", 256, 0, SLAB_ACCOUNT, alloc_ctor);
	if (!caches[0])
		return -ENOMEM;
	caches[1] = kmem_cache_create("cis_alloc_private", 256, 0, SLAB_ACCOUNT, alloc_ctor);
	if (!caches[1]) {
		error = -ENOMEM;
		goto destroy_first;
	}
	error = misc_register(&alloc_device);
	if (!error)
		return 0;
	kmem_cache_destroy(caches[1]);
destroy_first:
	kmem_cache_destroy(caches[0]);
	return error;
}

static void __exit alloc_exit(void)
{
	misc_deregister(&alloc_device);
	kmem_cache_destroy(caches[1]);
	kmem_cache_destroy(caches[0]);
}
module_init(alloc_init);
module_exit(alloc_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable VM native allocator truth fixture; never a host benchmark module");
