// SPDX-License-Identifier: GPL-2.0
/* Disposable VM only: bounded native lock_sock hold on a caller-supplied TCP FD. */
#include <linux/capability.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "uapi.h"

struct clone_state {
	struct mutex mutex;
	struct sk_buff *child;
};

static int net_open(struct inode *inode, struct file *file)
{
	struct clone_state *state;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->mutex);
	file->private_data = state;
	return 0;
}

static int net_close(struct inode *inode, struct file *file)
{
	struct clone_state *state = file->private_data;

	kfree_skb(state->child);
	kfree(state);
	return 0;
}

static long clone_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct clone_state *state = file->private_data;
	struct cis_net_clone_request r;
	struct socket *socket;
	struct sk_buff *skb;
	struct sock *sk;
	int error = 0;

	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	mutex_lock(&state->mutex);
	if (command == CIS_NET_TEST_DROP_CLONE) {
		if (!state->child) { error = -ENOENT; goto out; }
		r.child = (unsigned long)state->child;
		r.begin_ns = ktime_get_ns();
		kfree_skb(state->child);
		state->child = NULL;
		r.end_ns = ktime_get_ns();
		goto copy;
	}
	if (r.fd < 0 || r.clone > 1 || !r.cookie || state->child) { error = -EINVAL; goto out; }
	socket = sockfd_lookup(r.fd, &error);
	if (!socket)
		goto out;
	sk = socket->sk;
	if (!sk || sk->sk_type != SOCK_STREAM || sk->sk_protocol != IPPROTO_TCP ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    atomic64_read(&sk->sk_cookie) != r.cookie) { error = -EINVAL; goto put; }
	lock_sock(sk);
	r.begin_ns = ktime_get_ns();
	/* Native repair-mode push moves the unsent buffer to the RTX tree. */
	skb = tcp_rtx_queue_head(sk);
	if (!tcp_sk(sk)->repair || !skb_queue_empty(&sk->sk_write_queue) || !skb ||
	    tcp_rtx_queue_tail(sk) != skb ||
	    skb->fclone != SKB_FCLONE_ORIG) { error = -EINVAL; goto unlock; }
	r.original = (unsigned long)skb;
	if (r.clone) {
		state->child = skb_clone(skb, GFP_KERNEL);
		if (!state->child) { error = -ENOMEM; goto unlock; }
	}
	r.child = (unsigned long)state->child;
	r.data_refs = atomic_read(&skb_shinfo(skb)->dataref);
	r.header_refs = refcount_read(&container_of(skb, struct sk_buff_fclones, skb1)->fclone_ref);
	r.end_ns = ktime_get_ns();
unlock:
	release_sock(sk);
put:
	sockfd_put(socket);
copy:
	if (!error && copy_to_user((void __user *)arg, &r, sizeof(r)))
		error = -EFAULT;
out:
	mutex_unlock(&state->mutex);
	return error;
}

static long net_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct cis_net_test_request r;
	struct socket *socket;
	struct sock *sk;
	int error;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (command == CIS_NET_TEST_CLONE || command == CIS_NET_TEST_DROP_CLONE)
		return clone_ioctl(file, command, arg);
	if (command != CIS_NET_TEST_HOLD)
		return -ENOTTY;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	if (r.fd < 0 || r.hold_ms > 50 || r.reserved || !r.cookie)
		return -EINVAL;
	socket = sockfd_lookup(r.fd, &error);
	if (!socket)
		return error;
	sk = socket->sk;
	if (!sk || (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_protocol != IPPROTO_TCP || atomic64_read(&sk->sk_cookie) != r.cookie) {
		error = -EINVAL;
		goto out;
	}
	r.enter_ns = ktime_get_ns();
	lock_sock(sk);
	r.acquired_ns = ktime_get_ns();
	r.socket_address = (unsigned long)sk;
	r.cpu = raw_smp_processor_id();
	if (r.hold_ms)
		msleep(r.hold_ms);
	r.release_begin_ns = ktime_get_ns();
	release_sock(sk);
	r.released_ns = ktime_get_ns();
	error = copy_to_user((void __user *)arg, &r, sizeof(r)) ? -EFAULT : 0;
out:
	sockfd_put(socket);
	return error;
}

static const struct file_operations net_fops = {
	.owner = THIS_MODULE, .open = net_open, .release = net_close,
	.unlocked_ioctl = net_ioctl, .llseek = no_llseek,
};
static struct miscdevice net_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-net-test", .fops = &net_fops, .mode = 0600,
};
static int __init net_init(void) { return misc_register(&net_device); }
static void __exit net_exit(void) { misc_deregister(&net_device); }
module_init(net_init);
module_exit(net_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable-VM native TCP socket lock truth fixture");
