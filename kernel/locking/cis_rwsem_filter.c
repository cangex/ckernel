// SPDX-License-Identifier: GPL-2.0
/* Administrative lease; address equality only, never dereference a selection. */
#include <linux/capability.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/cis_rwsem.h>

#define CIS_RWSEM_OBJECTS 8
struct cis_rwsem_filter {
	struct rcu_head rcu;
	unsigned int count;
	unsigned long objects[CIS_RWSEM_OBJECTS];
};
static DEFINE_MUTEX(filter_control);
static struct cis_rwsem_filter *lease;
static struct cis_rwsem_filter __rcu *selection;
static bool attached;

bool cis_rwsem_filter_active(void)
{
	return rcu_access_pointer(selection) != NULL;
}

/* Caller disables preemption; there is no mutex, allocation or global update. */
bool cis_rwsem_filter_allows(void *object)
{
	struct cis_rwsem_filter *filter = rcu_dereference_sched(selection);
	unsigned int i;

	if (!filter)
		return false;
	for (i = 0; i < filter->count; i++)
		if (filter->objects[i] == (unsigned long)object)
			return true;
	return false;
}

int cis_rwsem_observe_register(void)
{
	int ret = 0;
	mutex_lock(&filter_control);
	if (!rcu_access_pointer(selection))
		ret = -ENODATA;
	else
		attached = true;
	mutex_unlock(&filter_control);
	return ret;
}

void cis_rwsem_observe_unregister(void)
{
	mutex_lock(&filter_control);
	attached = false;
	mutex_unlock(&filter_control);
}

static int filter_open(struct inode *inode, struct file *file)
{
	struct cis_rwsem_filter *filter;
	int ret = 0;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return -ENOMEM;
	mutex_lock(&filter_control);
	if (lease || attached)
		ret = -EBUSY;
	else {
		lease = filter;
		file->private_data = filter;
	}
	mutex_unlock(&filter_control);
	if (ret)
		kfree(filter);
	return ret;
}

static ssize_t filter_write(struct file *file, const char __user *data,
			    size_t size, loff_t *offset)
{
	struct cis_rwsem_filter candidate = {}, *filter = file->private_data;
	char *input, *cursor, *word;
	unsigned long address;
	unsigned int i;
	ssize_t ret = -EINVAL;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (!size || size > 256 || *offset)
		return -EINVAL;
	input = memdup_user_nul(data, size);
	if (IS_ERR(input))
		return PTR_ERR(input);
	if (memchr(input, '\0', size))
		goto out;
	cursor = input;
	while ((word = strsep(&cursor, " \t\n"))) {
		if (!*word)
			continue;
		if (candidate.count == CIS_RWSEM_OBJECTS || kstrtoul(word, 0, &address) ||
		    !address || (address & 7))
			goto out;
		for (i = 0; i < candidate.count; i++)
			if (candidate.objects[i] == address)
				goto out;
		candidate.objects[candidate.count++] = address;
	}
	if (!candidate.count)
		goto out;
	mutex_lock(&filter_control);
	if (lease != filter || attached || filter->count)
		ret = -EBUSY;
	else {
		filter->count = candidate.count;
		memcpy(filter->objects, candidate.objects, sizeof(candidate.objects));
		rcu_assign_pointer(selection, filter);
		ret = size;
	}
	mutex_unlock(&filter_control);
out:
	kfree(input);
	return ret;
}

static ssize_t filter_read(struct file *file, char __user *buffer,
			   size_t size, loff_t *offset)
{
	struct cis_rwsem_filter *filter = file->private_data;
	char text[256];
	unsigned int i;
	size_t length = 0;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&filter_control);
	for (i = 0; i < filter->count; i++)
		length += scnprintf(text + length, sizeof(text) - length,
				    "%s0x%lx", i ? " " : "", filter->objects[i]);
	length += scnprintf(text + length, sizeof(text) - length, "\n");
	mutex_unlock(&filter_control);
	return simple_read_from_buffer(buffer, size, offset, text, length);
}

static int filter_release(struct inode *inode, struct file *file)
{
	struct cis_rwsem_filter *filter = file->private_data;
	mutex_lock(&filter_control);
	if (lease == filter) {
		rcu_assign_pointer(selection, NULL);
		lease = NULL;
	}
	mutex_unlock(&filter_control);
	/* A killed worker cannot leave a selected source behind. In-flight hooks
	 * may finish reading their old immutable lease before the RCU callback. */
	kfree_rcu(filter, rcu);
	return 0;
}

static const struct file_operations filter_fops = {
	.open = filter_open, .write = filter_write, .read = filter_read,
	.release = filter_release, .llseek = no_llseek,
};

static int __init cis_rwsem_filter_init(void)
{
	debugfs_create_file("cis_rwsem_filter", 0600, NULL, NULL, &filter_fops);
	return 0;
}
late_initcall(cis_rwsem_filter_init);
