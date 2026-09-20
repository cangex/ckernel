// SPDX-License-Identifier: GPL-2.0
/* One pinned public queue. Administrative locks never enter packet processing. */
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <net/sch_generic.h>
#include <net/sock.h>
#define CREATE_TRACE_POINTS
#include <trace/events/cis_qdisc.h>

struct cis_queue_filter {
	struct net_device *dev;
	struct Qdisc *qdisc;
	struct netdev_queue *txq;
	u64 generation;
	u32 queue, netns;
	bool invalid;
};
static DEFINE_MUTEX(control);
static struct cis_queue_filter *lease;
static struct cis_queue_filter __rcu *selection;
static u64 generation;
static unsigned int attached;
struct cis_queue_audit {
	u64 entries, filtered, sampled, emitted, expired, recursive;
	u64 sequence[2];
	bool busy;
};
static DEFINE_PER_CPU(struct cis_queue_audit, audit);

bool cis_qdisc_active(void) { return rcu_access_pointer(selection) != NULL; }
int cis_qdisc_register(void)
{
	int ret = 0;
	mutex_lock(&control);
	if (!lease || !lease->generation || READ_ONCE(lease->invalid))
		ret = -ENODATA;
	else
		attached++;
	mutex_unlock(&control);
	return ret;
}
void cis_qdisc_unregister(void)
{
	mutex_lock(&control);
	if (!WARN_ON_ONCE(!attached))
		attached--;
	mutex_unlock(&control);
}

void cis_qdisc_invalidate(struct Qdisc *q)
{
	struct cis_queue_filter *f;
	rcu_read_lock();
	f = rcu_dereference(selection);
	if (f && f->qdisc == q)
		WRITE_ONCE(f->invalid, true);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(cis_qdisc_invalidate);

void __cis_qdisc_begin(struct cis_qdisc_sample *s, struct Qdisc *q,
		      struct netdev_queue *txq, struct sk_buff *skb, u32 op)
{
	struct cis_queue_filter *f;
	struct cis_queue_audit *a;
	struct sock *sk;
	struct cgroup *socket_cgroup;
	bool interrupt_context = in_nmi() || in_hardirq() || in_serving_softirq();
	preempt_disable_notrace();
	a = this_cpu_ptr(&audit);
	a->entries++;
	f = rcu_dereference_sched(selection);
	if (!f || f->qdisc != q || f->txq != txq || READ_ONCE(f->invalid) ||
	    op < 1 || op > 2 || !skb) {
		a->filtered++;
		goto out;
	}
	if (a->sequence[op - 1]++ & 15)
		goto out;
	a->sampled++;
	*s = (struct cis_qdisc_sample) {
		.begin_ns = ktime_get_ns(), .lease = f->generation,
		.qdisc = (unsigned long)q, .txq = (unsigned long)txq,
		.dev = (unsigned long)f->dev, .skb = (unsigned long)skb,
		.netns = f->netns, .ifindex = f->dev->ifindex, .queue = f->queue,
		.handle = q->handle, .operation = op, .sample_shift = 4,
		.qlen_begin = READ_ONCE(q->q.qlen), .backlog_begin = READ_ONCE(q->qstats.backlog),
		.length = skb->len, .context = interrupt_context,
		.flags = q->flags, .txq_state = READ_ONCE(txq->state),
	};
	if (!interrupt_context)
		s->actor_cgroup = cgroup_id(task_dfl_cgroup(current));
	/* The skb still owns its socket here. This is accounting, not payload owner. */
	sk = skb->sk;
	if (sk && sk_fullsock(sk)) {
		socket_cgroup = sock_cgroup_ptr(&sk->sk_cgrp_data);
		if (socket_cgroup)
			s->socket_cgroup = cgroup_id(socket_cgroup);
	}
out:
	preempt_enable_notrace();
}
EXPORT_SYMBOL_GPL(__cis_qdisc_begin);

void __cis_qdisc_end(struct cis_qdisc_sample *s, struct Qdisc *q, int rc, u32 packets)
{
	struct cis_queue_filter *f;
	struct cis_queue_audit *a;
	s->end_ns = ktime_get_ns();
	s->result = rc;
	s->packets = packets;
	/* No skb dereference: enqueue/xmit may have consumed or transformed it. */
	s->qlen_end = READ_ONCE(q->q.qlen);
	s->backlog_end = READ_ONCE(q->qstats.backlog);
	preempt_disable_notrace();
	a = this_cpu_ptr(&audit);
	f = rcu_dereference_sched(selection);
	if (!f || f->generation != s->lease || f->qdisc != q || READ_ONCE(f->invalid)) {
		a->expired++;
		goto out;
	}
	if (a->busy) {
		a->recursive++;
		goto out;
	}
	a->busy = true;
	trace_cis_qdisc_state(s);
	a->busy = false;
	a->emitted++;
out:
	preempt_enable_notrace();
}
EXPORT_SYMBOL_GPL(__cis_qdisc_end);
EXPORT_TRACEPOINT_SYMBOL_GPL(cis_qdisc_state);

static int filter_open(struct inode *inode, struct file *file)
{
	struct cis_queue_filter *f;
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

static ssize_t filter_write(struct file *file, const char __user *data, size_t size, loff_t *offset)
{
	struct cis_queue_filter *f = file->private_data;
	struct socket *sock;
	struct net_device *dev;
	struct netdev_queue *txq;
	struct Qdisc *q;
	char text[80], tail;
	unsigned int fd, index, queue;
	int error;
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
	if (sscanf(text, "%u %u %u %c", &fd, &index, &queue, &tail) != 3 ||
	    fd > INT_MAX || !index || index > INT_MAX)
		return -EINVAL;
	sock = sockfd_lookup(fd, &error);
	if (!sock)
		return error;
	if (!sock->sk) {
		sockfd_put(sock);
		return -EINVAL;
	}
	mutex_lock(&control);
	if (lease != f || attached || f->generation) {
		ret = -EBUSY;
		goto unlock;
	}
	if (generation == U64_MAX) {
		ret = -EOVERFLOW;
		goto unlock;
	}
	rtnl_lock();
	dev = dev_get_by_index(sock_net(sock->sk), index);
	if (!dev) {
		ret = -ENODEV;
		goto rtnl_out;
	}
	if (dev->reg_state != NETREG_REGISTERED || queue >= dev->real_num_tx_queues)
		goto dev_out;
	txq = netdev_get_tx_queue(dev, queue);
	q = rtnl_dereference(txq->qdisc_sleeping);
	if (!q || !q->enqueue || (q->flags & TCQ_F_BUILTIN) ||
	    q != rtnl_dereference(txq->qdisc))
		goto dev_out;
	qdisc_refcount_inc(q);
	f->dev = dev; f->txq = txq; f->qdisc = q;
	f->queue = queue; f->netns = sock_net(sock->sk)->ns.inum;
	f->generation = ++generation;
	rcu_assign_pointer(selection, f);
	ret = size;
	goto rtnl_out;
dev_out:
	dev_put(dev);
rtnl_out:
	rtnl_unlock();
unlock:
	mutex_unlock(&control);
	sockfd_put(sock);
	return ret;
}

static ssize_t filter_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
	struct cis_queue_filter *f = file->private_data;
	char text[256];
	size_t n;
	bool valid = false;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&control);
	if (f->generation) {
		rtnl_lock();
		valid = !READ_ONCE(f->invalid) && f->dev->reg_state == NETREG_REGISTERED &&
			f->qdisc == rtnl_dereference(f->txq->qdisc_sleeping) &&
			f->qdisc == rtnl_dereference(f->txq->qdisc);
		if (!valid)
			WRITE_ONCE(f->invalid, true);
		rtnl_unlock();
	}
	n = scnprintf(text, sizeof(text),
		"version=1 lease=%llu valid=%u netns=%u ifindex=%u queue=%u handle=%u qdisc=%llu\n",
		f->generation, valid, f->netns, f->dev ? f->dev->ifindex : 0,
		f->queue, f->qdisc ? f->qdisc->handle : 0, (u64)(unsigned long)f->qdisc);
	mutex_unlock(&control);
	return simple_read_from_buffer(buffer, size, offset, text, n);
}

static int filter_release(struct inode *inode, struct file *file)
{
	struct cis_queue_filter *f = file->private_data;
	mutex_lock(&control);
	rcu_assign_pointer(selection, NULL);
	synchronize_rcu();
	if (f->generation) {
		rtnl_lock();
		qdisc_put(f->qdisc);
		rtnl_unlock();
		dev_put(f->dev);
	}
	lease = NULL;
	mutex_unlock(&control);
	kfree(f);
	return 0;
}
static const struct file_operations filter_fops = {
	.open = filter_open, .write = filter_write, .read = filter_read,
	.release = filter_release, .llseek = no_llseek,
};

static int audit_show(struct seq_file *m, void *unused)
{
	int cpu;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	seq_printf(m, "version=1 enabled=%u lease_active=%u sample_shift=4 bytes_per_cpu=%zu\n",
		trace_cis_qdisc_state_enabled(), cis_qdisc_active(), sizeof(struct cis_queue_audit));
	for_each_possible_cpu(cpu) {
		struct cis_queue_audit *a = per_cpu_ptr(&audit, cpu);
		seq_printf(m, "cpu=%d entries=%llu filtered=%llu sampled=%llu emitted=%llu expired=%llu recursive=%llu\n",
			cpu, READ_ONCE(a->entries), READ_ONCE(a->filtered), READ_ONCE(a->sampled),
			READ_ONCE(a->emitted), READ_ONCE(a->expired), READ_ONCE(a->recursive));
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(audit);
static int __init cis_qdisc_init(void)
{
	debugfs_create_file("cis_queue_filter", 0600, NULL, NULL, &filter_fops);
	debugfs_create_file("cis_queue_audit", 0400, NULL, NULL, &audit_fops);
	return 0;
}
late_initcall(cis_qdisc_init);
