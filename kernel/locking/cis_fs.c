// SPDX-License-Identifier: GPL-2.0
/* Administrative pinned-filesystem lease; no hot-path ownership lock. */
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/debugfs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#define CREATE_TRACE_POINTS
#include <trace/events/cis_fs.h>

struct cis_fs_filter {
	struct path path;
	u64 generation;
	dev_t dev;
};
static DEFINE_MUTEX(control);
static struct cis_fs_filter *lease;
static struct cis_fs_filter __rcu *selection;
static u64 generation;
static unsigned int attached;
struct cis_fs_audit {
	u64 entries, filtered, sampled, emitted, expired, recursive;
	u64 sequence[6];
	bool busy;
};
static DEFINE_PER_CPU(struct cis_fs_audit, audit);

bool cis_fs_active(void) { return rcu_access_pointer(selection) != NULL; }

int cis_fs_register(void)
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

void cis_fs_unregister(void)
{
	mutex_lock(&control);
	if (!WARN_ON_ONCE(!attached))
		attached--;
	mutex_unlock(&control);
}

void __cis_fs_begin(struct cis_fs_sample *s, dev_t dev, const void *resource,
		   u32 operation, u64 value)
{
	struct cis_fs_filter *f;
	struct cis_fs_audit *a;
	u32 shift = operation <= CIS_FS_TRANSACTION_WAIT ? 0 : 4;
	preempt_disable_notrace();
	a = this_cpu_ptr(&audit);
	a->entries++;
	f = rcu_dereference_sched(selection);
	if (in_interrupt() || !f || f->dev != dev || operation < 1 || operation > 6) {
		a->filtered++;
		goto out;
	}
	if ((a->sequence[operation - 1]++ & ((1U << shift) - 1)))
		goto out;
	a->sampled++;
	*s = (struct cis_fs_sample) {
		.begin_ns = ktime_get_ns(), .lease = f->generation,
		.cgroup_id = cgroup_id(task_dfl_cgroup(current)),
		.resource = (unsigned long)resource, .value = value,
		.dev = dev, .operation = operation, .sample_shift = shift,
	};
out:
	preempt_enable_notrace();
}
EXPORT_SYMBOL_GPL(__cis_fs_begin);

void __cis_fs_end(struct cis_fs_sample *s, u64 count, int error)
{
	struct cis_fs_filter *f;
	struct cis_fs_audit *a;
	s->end_ns = ktime_get_ns();
	s->count = count;
	s->error = error;
	preempt_disable_notrace();
	a = this_cpu_ptr(&audit);
	f = rcu_dereference_sched(selection);
	if (!f || f->generation != s->lease) {
		a->expired++;
		goto out;
	}
	if (a->busy) {
		a->recursive++;
		goto out;
	}
	a->busy = true;
	trace_cis_fs_state(s);
	a->busy = false;
	a->emitted++;
out:
	preempt_enable_notrace();
}
EXPORT_SYMBOL_GPL(__cis_fs_end);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_fs_state);

static int filter_open(struct inode *inode, struct file *file)
{
	struct cis_fs_filter *f;
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
	struct cis_fs_filter *f = file->private_data;
	struct file *target;
	char text[24];
	unsigned int fd;
	ssize_t ret = -EINVAL;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (!size || size >= sizeof(text) || *offset)
		return -EINVAL;
	if (copy_from_user(text, data, size))
		return -EFAULT;
	if (memchr(text, '\0', size))
		return -EINVAL;
	text[size] = '\0';
	if (kstrtouint(text, 10, &fd))
		return -EINVAL;
	target = fget_raw(fd);
	if (!target)
		return -EBADF;
	if (!S_ISDIR(file_inode(target)->i_mode) || target->f_path.dentry->d_sb->s_magic != EXT4_SUPER_MAGIC)
		goto out;
	mutex_lock(&control);
	if (lease != f || attached || f->generation)
		ret = -EBUSY;
	else if (generation == U64_MAX)
		ret = -EOVERFLOW;
	else {
		f->path = target->f_path;
		path_get(&f->path);
		f->dev = f->path.dentry->d_sb->s_dev;
		f->generation = ++generation;
		rcu_assign_pointer(selection, f);
		ret = size;
	}
	mutex_unlock(&control);
out:
	fput(target);
	return ret;
}

static ssize_t filter_read(struct file *file, char __user *buffer,
			   size_t size, loff_t *offset)
{
	struct cis_fs_filter *f = file->private_data;
	char text[128];
	size_t n;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&control);
	n = scnprintf(text, sizeof(text), "version=1 lease=%llu dev=%u major=%u minor=%u\n",
		f->generation, f->dev, MAJOR(f->dev), MINOR(f->dev));
	mutex_unlock(&control);
	return simple_read_from_buffer(buffer, size, offset, text, n);
}

static int filter_release(struct inode *inode, struct file *file)
{
	struct cis_fs_filter *f = file->private_data;
	mutex_lock(&control);
	rcu_assign_pointer(selection, NULL);
	/* Keep the old lease reserved until all readers stopped using its path. */
	synchronize_rcu();
	if (f->generation)
		path_put(&f->path);
	lease = NULL;
	mutex_unlock(&control);
	kfree(f);
	return 0;
}
static const struct file_operations filter_fops = {
	.open = filter_open, .read = filter_read, .write = filter_write,
	.release = filter_release, .llseek = no_llseek,
};

static int audit_show(struct seq_file *m, void *unused)
{
	int cpu;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_printf(m, "version=1 enabled=%u lease_active=%u allocation_shift=4 bytes_per_cpu=%zu\n",
		trace_cis_fs_state_enabled(), cis_fs_active(), sizeof(struct cis_fs_audit));
	for_each_possible_cpu(cpu) {
		struct cis_fs_audit *a = per_cpu_ptr(&audit, cpu);
		seq_printf(m, "cpu=%d entries=%llu filtered=%llu sampled=%llu emitted=%llu expired=%llu recursive=%llu\n",
			cpu, READ_ONCE(a->entries), READ_ONCE(a->filtered), READ_ONCE(a->sampled),
			READ_ONCE(a->emitted), READ_ONCE(a->expired), READ_ONCE(a->recursive));
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(audit);
static int __init cis_fs_init(void)
{
	debugfs_create_file("cis_fs_filter", 0600, NULL, NULL, &filter_fops);
	debugfs_create_file("cis_fs_audit", 0400, NULL, NULL, &audit_fops);
	return 0;
}
late_initcall(cis_fs_init);
