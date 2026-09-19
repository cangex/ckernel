// SPDX-License-Identifier: GPL-2.0
/* Exclusive disposable VM only. Native API truth, no injected observer events. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "uapi.h"

struct test_slot {
	struct rw_semaphore sem;
	atomic_t users, acquired;
	u64 token;
};
static struct test_slot slots[4];
static DEFINE_MUTEX(control);

static long fixture_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	struct cis_rwsem_test r;
	struct test_slot *s;
	u64 deadline;
	int result = 0;
	bool held = false;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN)) return -EPERM;
	if (command != CIS_RWSEM_RESET && command != CIS_RWSEM_OPERATE && command != CIS_RWSEM_QUERY) return -ENOTTY;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r))) return -EFAULT;
	if (!r.token || r.slot >= ARRAY_SIZE(slots) || r.wait_slot >= ARRAY_SIZE(slots) ||
	    r.mode > 6 || r.hold_ms > 500 || r.wait_holders > 10) return -EINVAL;
	s = &slots[r.slot];
	if (command == CIS_RWSEM_QUERY) {
		r.address = (unsigned long)&s->sem;
		goto output;
	}
	mutex_lock(&control);
	if (command == CIS_RWSEM_RESET) {
		if (atomic_read(&s->users) || r.token <= s->token) result = -EBUSY;
		else {
			r.enter_ns = ktime_get_ns();
			init_rwsem(&s->sem);
			r.end_ns = ktime_get_ns();
			atomic_set(&s->acquired, 0);
			s->token = r.token;
		}
	} else if (s->token != r.token) result = -ESTALE;
	else atomic_inc(&s->users);
	mutex_unlock(&control);
	if (result) return result;
	r.address = (unsigned long)&s->sem;
	r.task = ((u64)task_tgid_nr(current) << 32) | task_pid_nr(current);
	if (command == CIS_RWSEM_RESET) goto output;
	deadline = ktime_get_ns() + 500000000;
	while (atomic_read(&slots[r.wait_slot].acquired) < r.wait_holders) {
		if (ktime_get_ns() >= deadline) { result = -ETIMEDOUT; goto leave; }
		usleep_range(100, 200);
	}
	r.enter_ns = ktime_get_ns();
	switch (r.mode) {
	case 0: down_read(&s->sem); held = true; break;
	case 1: down_write(&s->sem); held = true; break;
	case 2: held = down_read_trylock(&s->sem); break;
	case 3: held = down_write_trylock(&s->sem); break;
	case 4: down_read_non_owner(&s->sem); held = true; break;
	case 5: down_write(&s->sem); held = true; break;
	case 6:
		result = down_read_interruptible(&s->sem);
		held = !result;
		break;
	}
	if (held) {
		r.acquired_ns = ktime_get_ns();
		atomic_inc(&s->acquired);
		if (r.mode == 5) downgrade_write(&s->sem);
		if (r.hold_ms) msleep(r.hold_ms);
		r.release_ns = ktime_get_ns();
		if (r.mode == 1 || r.mode == 3) up_write(&s->sem);
		else if (r.mode == 4) up_read_non_owner(&s->sem);
		else up_read(&s->sem);
	}
	r.end_ns = ktime_get_ns();
	r.outcome = result ? result : held ? 1 : 0;
	result = 0;
leave:
	atomic_dec(&s->users);
	if (result) return result;
output:
	return copy_to_user((void __user *)arg, &r, sizeof(r)) ? -EFAULT : 0;
}

static const struct file_operations fixture_fops = {
	.owner = THIS_MODULE, .unlocked_ioctl = fixture_ioctl, .llseek = no_llseek,
};
static struct miscdevice fixture_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-rwsem-test", .mode = 0600, .fops = &fixture_fops,
};
static int __init fixture_init(void) { return misc_register(&fixture_device); }
static void __exit fixture_exit(void) { misc_deregister(&fixture_device); }
module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable-VM native rwsem operation truth fixture");
