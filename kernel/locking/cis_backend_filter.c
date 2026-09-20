// SPDX-License-Identifier: GPL-2.0
/* One immutable administrative cache/node selection, never a hot-path lock. */
#include <linux/capability.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/numa.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/cis_backend.h>

#define CIS_BACKEND_NODES 8
struct cis_backend_filter {
	struct rcu_head rcu;
	char cache[64];
	unsigned int count, nodes[CIS_BACKEND_NODES];
};
static DEFINE_MUTEX(control);
static struct cis_backend_filter *lease;
static struct cis_backend_filter __rcu *selection;
static unsigned int attached;

bool cis_backend_active(void)
{
	return rcu_access_pointer(selection) != NULL;
}

bool cis_backend_allows(const char *name)
{
	struct cis_backend_filter *f;
	bool result;
	preempt_disable_notrace();
	f = rcu_dereference_sched(selection);
	result = f && name && !strcmp(name, f->cache);
	preempt_enable_notrace();
	return result;
}

/* The native caller owns the live cache and node. Selected indexes are
 * validated at publication; no pointer from userspace is dereferenced. */
bool cis_backend_node_allows(const char *name, void *const *nodes, void *node)
{
	struct cis_backend_filter *f;
	bool result = false;
	unsigned int i;
	preempt_disable_notrace();
	f = rcu_dereference_sched(selection);
	if (f && name && !strcmp(name, f->cache)) {
		result = !f->count;
		for (i = 0; i < f->count; i++)
			if (READ_ONCE(nodes[f->nodes[i]]) == node)
				result = true;
	}
	preempt_enable_notrace();
	return result;
}

int cis_backend_register(void)
{
	int ret = 0;
	mutex_lock(&control);
	if (!rcu_access_pointer(selection))
		ret = -ENODATA;
	else
		attached++;
	mutex_unlock(&control);
	return ret;
}

bool cis_backend_page_allows(int node)
{
	struct cis_backend_filter *f;
	bool result = false;
	unsigned int i;
	preempt_disable_notrace();
	f = rcu_dereference_sched(selection);
	if (f && !strcmp(f->cache, "page_zone")) {
		result = !f->count;
		for (i = 0; i < f->count; i++)
			if (f->nodes[i] == node)
				result = true;
	}
	preempt_enable_notrace();
	return result;
}

void cis_backend_unregister(void)
{
	mutex_lock(&control);
	if (!WARN_ON_ONCE(!attached))
		attached--;
	mutex_unlock(&control);
}

static int filter_open(struct inode *inode, struct file *file)
{
	struct cis_backend_filter *f;
	int ret = 0;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	mutex_lock(&control);
	if (lease || attached)
		ret = -EBUSY;
	else {
		lease = f;
		file->private_data = f;
	}
	mutex_unlock(&control);
	if (ret)
		kfree(f);
	return ret;
}

static ssize_t filter_write(struct file *file, const char __user *data,
			   size_t size, loff_t *offset)
{
	struct cis_backend_filter candidate = {}, *f = file->private_data;
	char *input, *cursor, *cache, *word;
	unsigned int i, node;
	ssize_t ret = -EINVAL;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (!size || size > 160 || *offset)
		return -EINVAL;
	input = memdup_user_nul(data, size);
	if (IS_ERR(input))
		return PTR_ERR(input);
	if (memchr(input, '\0', size))
		goto out;
	cursor = input;
	cache = strsep(&cursor, " ");
	if (!cache || !*cache || strlen(cache) >= sizeof(candidate.cache) || !cursor)
		goto out;
	for (i = 0; cache[i]; i++)
		if (!isalnum(cache[i]) && cache[i] != '_' && cache[i] != '-')
			goto out;
	strscpy(candidate.cache, cache, sizeof(candidate.cache));
	cursor = strim(cursor);
	if (strcmp(cursor, "*")) {
		while ((word = strsep(&cursor, ","))) {
			if (!*word || candidate.count == CIS_BACKEND_NODES ||
			    kstrtouint(word, 10, &node) || node >= MAX_NUMNODES)
				goto out;
			for (i = 0; i < candidate.count; i++)
				if (candidate.nodes[i] == node)
					goto out;
			candidate.nodes[candidate.count++] = node;
		}
		if (!candidate.count)
			goto out;
	}
	mutex_lock(&control);
	if (lease != f || attached || f->cache[0])
		ret = -EBUSY;
	else {
		memcpy(f->cache, candidate.cache, sizeof(f->cache));
		memcpy(f->nodes, candidate.nodes, sizeof(f->nodes));
		f->count = candidate.count;
		rcu_assign_pointer(selection, f);
		ret = size;
	}
	mutex_unlock(&control);
out:
	kfree(input);
	return ret;
}

static ssize_t filter_read(struct file *file, char __user *buffer,
			  size_t size, loff_t *offset)
{
	struct cis_backend_filter *f = file->private_data;
	char text[160];
	size_t n;
	unsigned int i;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&control);
	n = scnprintf(text, sizeof(text), "%s ", f->cache);
	if (!f->count)
		n += scnprintf(text + n, sizeof(text) - n, "*");
	for (i = 0; i < f->count; i++)
		n += scnprintf(text + n, sizeof(text) - n, "%s%u", i ? "," : "", f->nodes[i]);
	n += scnprintf(text + n, sizeof(text) - n, "\n");
	mutex_unlock(&control);
	return simple_read_from_buffer(buffer, size, offset, text, n);
}

static int filter_release(struct inode *inode, struct file *file)
{
	struct cis_backend_filter *f = file->private_data;
	mutex_lock(&control);
	if (lease == f) {
		rcu_assign_pointer(selection, NULL);
		lease = NULL;
	}
	mutex_unlock(&control);
	kfree_rcu(f, rcu);
	return 0;
}

static const struct file_operations filter_fops = {
	.open = filter_open, .write = filter_write, .read = filter_read,
	.release = filter_release, .llseek = no_llseek,
};

static int __init cis_backend_filter_init(void)
{
	debugfs_create_file("cis_backend_filter", 0600, NULL, NULL, &filter_fops);
	return 0;
}
late_initcall(cis_backend_filter_init);
