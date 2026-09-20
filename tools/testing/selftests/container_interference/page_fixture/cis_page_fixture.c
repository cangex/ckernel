// SPDX-License-Identifier: GPL-2.0
/* Disposable VM only: native page allocation/free, no synthetic trace events. */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "uapi.h"

static long page_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cis_page_test q;
	struct page **pages;
	u32 i, order;
	gfp_t flags = GFP_KERNEL | __GFP_ACCOUNT | __GFP_THISNODE | __GFP_NORETRY | __GFP_NOWARN;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN)) return -EPERM;
	if (cmd != CIS_PAGE_TEST) return -EINVAL;
	if (copy_from_user(&q, (void __user *)arg, sizeof(q))) return -EFAULT;
	if (q.version != 1 || q.reserved[0] || q.reserved[1] ||
	    q.node >= MAX_NUMNODES || !node_online(q.node) ||
	    !node_isset(q.node, current->mems_allowed)) return -EINVAL;
	pages = kcalloc(CIS_PAGE_SMALL + CIS_PAGE_LARGE, sizeof(*pages), GFP_KERNEL_ACCOUNT);
	if (!pages) return -ENOMEM;
	q.pages_allocated = q.pages_freed = q.wrong_node = q.failed = 0;
	q.begin_ns = ktime_get_ns();
	for (i = 0; i < CIS_PAGE_SMALL + CIS_PAGE_LARGE; i++) {
		order = i < CIS_PAGE_SMALL ? 0 : CIS_PAGE_ORDER;
		pages[i] = alloc_pages_node(q.node, flags, order);
		if (!pages[i]) { q.failed++; break; }
		q.wrong_node += page_to_nid(pages[i]) != q.node;
		q.pages_allocated += 1U << order;
	}
	for (i = 0; i < CIS_PAGE_SMALL + CIS_PAGE_LARGE; i++) {
		if (!pages[i]) continue;
		order = i < CIS_PAGE_SMALL ? 0 : CIS_PAGE_ORDER;
		__free_pages(pages[i], order);
		q.pages_freed += 1U << order;
	}
	q.end_ns = ktime_get_ns();
	kfree(pages);
	return copy_to_user((void __user *)arg, &q, sizeof(q)) ? -EFAULT : 0;
}

static const struct file_operations page_fops = {
	.owner = THIS_MODULE, .unlocked_ioctl = page_ioctl, .llseek = no_llseek,
};
static struct miscdevice page_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-page-test", .fops = &page_fops, .mode = 0600,
};
static int __init page_test_init(void) { return misc_register(&page_device); }
static void __exit page_test_exit(void) { misc_deregister(&page_device); }
module_init(page_test_init);
module_exit(page_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable-VM native page supply and return coverage fixture");
