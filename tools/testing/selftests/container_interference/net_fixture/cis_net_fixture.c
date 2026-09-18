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
#include "uapi.h"

static long net_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct cis_net_test_request r;
	struct socket *socket;
	struct sock *sk;
	int error;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
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
	.owner = THIS_MODULE, .unlocked_ioctl = net_ioctl, .llseek = no_llseek,
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
