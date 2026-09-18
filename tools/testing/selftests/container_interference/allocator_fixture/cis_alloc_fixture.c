// SPDX-License-Identifier: GPL-2.0
/* Dedicated disposable VM only. Real SLUB allocation, no injected lock delay. */
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/cis_alloc_test.h>

static struct kmem_cache *caches[2];
struct alloc_file {
	struct mutex lock;
	void *objects[CIS_AT_MAX];
	u32 count, cache;
	struct rcu_head rcu;
	struct completion done;
	bool deferred;
	u64 callback_begin_ns, callback_end_ns;
	u32 callback_cpu, callback_context, callback_count;
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

static void deferred_release(struct rcu_head *head)
{
	struct alloc_file *state = container_of(head, struct alloc_file, rcu);
	state->callback_begin_ns = ktime_get_ns();
	state->callback_cpu = raw_smp_processor_id();
	state->callback_context = in_hardirq() ? 2 : in_serving_softirq() ? 1 : 0;
	state->callback_count = state->count;
	release_objects(state, false);
	state->callback_end_ns = ktime_get_ns();
	complete(&state->done);
}

static void copy_objects(struct cis_alloc_test_request *request, struct alloc_file *state)
{
	u32 i;
	for (i = 0; i < request->returned; i++)
		request->objects[i] = (unsigned long)state->objects[i];
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
	init_completion(&state->done);
	file->private_data = state;
	return 0;
}

static int alloc_release(struct inode *inode, struct file *file)
{
	struct alloc_file *state = file->private_data;
	if (state->deferred)
		wait_for_completion(&state->done);
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
	    request.action < CIS_AT_ALLOC || request.action > CIS_AT_DRAIN ||
	    request.count > CIS_AT_MAX || (request.action == CIS_AT_ALLOC && !request.count) ||
	    (request.action != CIS_AT_ALLOC && request.count))
		return -EINVAL;
	mutex_lock(&state->lock);
	request.returned = 0;
	request.callback_begin_ns = request.callback_end_ns = 0;
	request.callback_cpu = request.callback_context = 0;
	memset(request.objects, 0, sizeof(request.objects));
	request.cache_address = (unsigned long)caches[request.cache];
	request.cpu = raw_smp_processor_id();
	request.begin_ns = ktime_get_ns();
	if (state->deferred && request.action != CIS_AT_DRAIN) {
		result = -EBUSY;
		goto out;
	}
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
		copy_objects(&request, state);
	} else if (request.action == CIS_AT_FREE) {
		if (request.cache != state->cache) {
			result = -EINVAL;
			goto out;
		}
		request.returned = state->count;
		copy_objects(&request, state);
		release_objects(state, request.bulk);
	} else if (request.action == CIS_AT_SHRINK) {
		/* Explicit fixture setup action, not a production fast path. */
		result = kmem_cache_shrink(caches[request.cache]);
	} else if (request.action == CIS_AT_DEFER) {
		if (!state->count || state->cache != request.cache) {
			result = -EINVAL;
			goto out;
		}
		state->deferred = true;
		reinit_completion(&state->done);
		request.returned = state->count;
		copy_objects(&request, state);
		call_rcu(&state->rcu, deferred_release);
	} else {
		if (!state->deferred || state->cache != request.cache) {
			result = -EINVAL;
			goto out;
		}
		wait_for_completion(&state->done);
		request.returned = state->callback_count;
		copy_objects(&request, state);
		request.callback_begin_ns = state->callback_begin_ns;
		request.callback_end_ns = state->callback_end_ns;
		request.callback_cpu = state->callback_cpu;
		request.callback_context = state->callback_context;
		state->deferred = false;
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
	rcu_barrier();
	kmem_cache_destroy(caches[1]);
	kmem_cache_destroy(caches[0]);
}
module_init(alloc_init);
module_exit(alloc_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable VM native allocator truth fixture; never a host benchmark module");
