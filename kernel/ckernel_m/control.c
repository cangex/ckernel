// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "internal.h"

static long ckm_instance_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ckm_instance *i = file->private_data;
	struct ckm_query q;
	struct ckm_diagnostics d;
#ifdef CONFIG_CKERNEL_M_VFS
	struct ckm_vfs_root root;
	struct ckm_vfs_query vfs;
#endif

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	switch (cmd) {
#ifdef CONFIG_CKERNEL_M_VFS
	case CKM_IOC_VFS_ROOT:
		if (copy_from_user(&root, (void __user *)arg, sizeof(root)))
			return -EFAULT;
		if (root.version != CKM_ABI_VERSION || root.size != sizeof(root) ||
		    root.reserved[0] || root.reserved[1] || root.reserved[2] || root.reserved[3])
			return -EINVAL;
		return ckm_vfs_register(i, root.fd, root.capacity);
	case CKM_IOC_VFS_QUERY:
		if (copy_from_user(&vfs, (void __user *)arg, sizeof(vfs)))
			return -EFAULT;
		if (vfs.version != CKM_ABI_VERSION || vfs.size != sizeof(vfs) ||
		    vfs.reserved[0] || vfs.reserved[1] || vfs.reserved[2] || vfs.reserved[3])
			return -EINVAL;
		memset(&vfs, 0, sizeof(vfs));
		ckm_vfs_query(i, &vfs);
		return copy_to_user((void __user *)arg, &vfs, sizeof(vfs)) ? -EFAULT : 0;
#endif
	case CKM_IOC_DIAGNOSTICS:
		if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
			return -EFAULT;
		if (d.version != CKM_ABI_VERSION || d.size != sizeof(d) ||
		    d.reserved[0] || d.reserved[1] || d.reserved[2] || d.reserved[3])
			return -EINVAL;
		memset(&d, 0, sizeof(d));
		ckm_query_diagnostics(i, &d);
		return copy_to_user((void __user *)arg, &d, sizeof(d)) ? -EFAULT : 0;
	case CKM_IOC_BIND:
#ifdef CONFIG_CKERNEL_M_VFS
		return arg ? -EINVAL : ckm_vfs_bind(i);
#else
		return arg ? -EINVAL : ckm_bind_current(i);
#endif
	case CKM_IOC_REVOKE:
		if (arg)
			return -EINVAL;
		ckm_revoke(i);
		return 0;
	case CKM_IOC_QUERY:
		if (copy_from_user(&q, (void __user *)arg, sizeof(q)))
			return -EFAULT;
		if (q.version != CKM_ABI_VERSION || q.size != sizeof(q) ||
		    q.reserved[0] || q.reserved[1] || q.reserved[2])
			return -EINVAL;
		memset(&q, 0, sizeof(q));
		ckm_query_instance(i, &q);
		return copy_to_user((void __user *)arg, &q, sizeof(q)) ? -EFAULT : 0;
	default:
		return -ENOTTY;
	}
}

static int ckm_instance_release(struct inode *inode, struct file *file)
{
	struct ckm_instance *i = file->private_data;

	ckm_revoke(i);
	ckm_put(i);
	return 0;
}

static const struct file_operations ckm_instance_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ckm_instance_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.release = ckm_instance_release,
	.llseek = no_llseek,
};

static long ckm_control_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ckm_create r;
	struct ckm_instance *i;
	struct file *handle;
	int fd;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != CKM_IOC_CREATE)
		return -ENOTTY;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	if (r.version != CKM_ABI_VERSION || r.size != sizeof(r) ||
	    r.features & ~(CKM_FEATURE_MAPLE | CKM_FEATURE_VFS) || r.max_nodes > 4096 ||
	    r.reserved[0] || r.reserved[1] || r.reserved[2] || r.reserved[3])
		return -EINVAL;
	if ((r.features & CKM_FEATURE_MAPLE) &&
	    (!IS_ENABLED(CONFIG_CKERNEL_M_MAPLE) || !r.max_nodes))
		return -EOPNOTSUPP;
	if ((r.features & CKM_FEATURE_VFS) && !IS_ENABLED(CONFIG_CKERNEL_M_VFS))
		return -EOPNOTSUPP;
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	i = ckm_create_instance(&r);
	if (IS_ERR(i)) {
		put_unused_fd(fd);
		return PTR_ERR(i);
	}
	handle = anon_inode_getfile("ckernel-m-instance", &ckm_instance_fops, i, O_RDWR);
	if (IS_ERR(handle)) {
		put_unused_fd(fd);
		ckm_revoke(i);
		ckm_put(i);
		return PTR_ERR(handle);
	}
	fd_install(fd, handle);
	return fd;
}

static const struct file_operations ckm_control_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ckm_control_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice ckm_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ckernel-m",
	.fops = &ckm_control_fops,
	.mode = 0600,
};

static int __init ckm_control_init(void)
{
	return misc_register(&ckm_device);
}
device_initcall(ckm_control_init);
