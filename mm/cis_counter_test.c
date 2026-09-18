// SPDX-License-Identifier: GPL-2.0
/* Fixed-lifetime external truth, never used by the production observer. */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/page_counter.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <uapi/linux/cis_counter_test.h>

static struct page_counter counters[4][3];

static long counter_test_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cis_counter_test_request r;
	struct page_counter *leaf, *parent, *failed = NULL;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != CIS_COUNTER_TEST_RUN)
		return -ENOTTY;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	if (r.slot >= 4 || r.leaf >= 2 || r.operation > 2 ||
	    r.reserved || r.reserved2 || !r.pages || r.pages > 64)
		return -EINVAL;
	parent = &counters[r.slot][0];
	leaf = &counters[r.slot][r.leaf + 1];
	r.leaf_address = (unsigned long)leaf;
	r.parent_address = (unsigned long)parent;
	r.failed_address = 0;
	r.begin_ns = ktime_get_ns();
	if (r.operation == 0) {
		page_counter_charge(leaf, r.pages);
		r.success = 1;
		page_counter_uncharge(leaf, r.pages);
	} else {
		r.success = page_counter_try_charge(leaf, r.pages, &failed);
		if (r.success)
			page_counter_uncharge(leaf, r.pages);
		else
			r.failed_address = (unsigned long)failed;
	}
	r.end_ns = ktime_get_ns();
	r.final_leaf = page_counter_read(leaf);
	r.final_parent = page_counter_read(parent);
	/* Concurrent reads are snapshots; conservation is checked after quiescence. */
	if (copy_to_user((void __user *)arg, &r, sizeof(r)))
		return -EFAULT;
	return 0;
}

static const struct file_operations counter_test_fops = {
	.owner = THIS_MODULE, .unlocked_ioctl = counter_test_ioctl,
};
static struct miscdevice counter_test_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-counter-test",
	.fops = &counter_test_fops, .mode = 0600,
};
static int __init counter_test_init(void)
{
	int i, j;

	for (i = 0; i < 4; i++) {
		page_counter_init(&counters[i][0], NULL);
		counters[i][0].max = 32;
		for (j = 1; j < 3; j++) {
			page_counter_init(&counters[i][j], &counters[i][0]);
			counters[i][j].max = 128;
			counters[i][j].min = 4;
			counters[i][j].low = 8;
		}
	}
	return misc_register(&counter_test_device);
}
device_initcall(counter_test_init);
