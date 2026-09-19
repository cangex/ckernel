// SPDX-License-Identifier: GPL-2.0
/* Independent truth fixture, never installed on the host. No real device I/O. */
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "abi.h"

#define DEPTH 4
static bool disposable_vm;
module_param(disposable_vm, bool, 0444);
static struct blk_mq_tag_set tags[2];
static struct gendisk *disks[2];
static atomic_t held[2];
struct context { struct mutex lock; struct request *rq[DEPTH]; };

static blk_status_t reject_io(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	/* Only allocation/free is supported. Accidentally issuing I/O must fail. */
	blk_mq_start_request(bd->rq);
	blk_mq_end_request(bd->rq, BLK_STS_IOERR);
	return BLK_STS_OK;
}
static const struct blk_mq_ops mq_ops = { .queue_rq = reject_io };

static int fixture_open(struct inode *inode, struct file *file)
{
	struct context *ctx;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	mutex_init(&ctx->lock);
	file->private_data = ctx;
	return 0;
}
static void release_slot(struct context *ctx, unsigned int slot)
{
	struct request *rq = ctx->rq[slot];
	unsigned int disk;
	if (!rq)
		return;
	disk = rq->q == disks[1]->queue;
	ctx->rq[slot] = NULL;
	atomic_dec(&held[disk]);
	blk_mq_free_request(rq);
}
static int fixture_release(struct inode *inode, struct file *file)
{
	struct context *ctx = file->private_data;
	unsigned int i;
	for (i = 0; i < DEPTH; i++)
		release_slot(ctx, i);
	kfree(ctx);
	return 0;
}
static long fixture_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cis_tag_op op;
	struct context *ctx = file->private_data;
	struct request *rq;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != CIS_TAG_OP)
		return -ENOTTY;
	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;
	if (op.op > 2 || op.disk > 1 || op.slot >= DEPTH || op.nowait > 1)
		return -EINVAL;
	mutex_lock(&ctx->lock);
	op.before_ns = ktime_get_ns();
	op.task_start = current->start_boottime;
	op.tid = task_pid_nr(current);
	op.queue = (unsigned long)disks[op.disk]->queue;
	op.depth = tags[op.disk].queue_depth;
	op.result = 0;
	op.tag = -1;
	if (op.op == 0) {
		if (ctx->rq[op.slot]) {
			op.result = -EBUSY;
		} else {
			rq = blk_mq_alloc_request(disks[op.disk]->queue, REQ_OP_READ,
				op.nowait ? BLK_MQ_REQ_NOWAIT : 0);
			if (IS_ERR(rq))
				op.result = PTR_ERR(rq);
			else {
				ctx->rq[op.slot] = rq;
				op.tag = rq->tag;
				atomic_inc(&held[op.disk]);
			}
		}
	} else if (op.op == 1) {
		release_slot(ctx, op.slot);
	}
	op.held[0] = atomic_read(&held[0]);
	op.held[1] = atomic_read(&held[1]);
	op.after_ns = ktime_get_ns();
	mutex_unlock(&ctx->lock);
	return copy_to_user((void __user *)arg, &op, sizeof(op)) ? -EFAULT : 0;
}
static const struct file_operations fops = {
	.owner = THIS_MODULE, .open = fixture_open, .release = fixture_release,
	.unlocked_ioctl = fixture_ioctl, .llseek = no_llseek,
};
static struct miscdevice device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "cis-tag-fixture", .fops = &fops, .mode = 0600,
};
static void destroy(unsigned int n)
{
	while (n--) {
		put_disk(disks[n]);
		blk_mq_free_tag_set(&tags[n]);
	}
}
static int __init fixture_init(void)
{
	unsigned int i;
	int err;
	if (!disposable_vm)
		return -EPERM;
	for (i = 0; i < 2; i++) {
		tags[i].ops = &mq_ops;
		tags[i].nr_hw_queues = 1;
		tags[i].queue_depth = DEPTH;
		tags[i].numa_node = NUMA_NO_NODE;
		err = blk_mq_alloc_tag_set(&tags[i]);
		if (err)
			goto fail;
		disks[i] = blk_mq_alloc_disk(&tags[i], NULL);
		if (IS_ERR(disks[i])) {
			err = PTR_ERR(disks[i]);
			blk_mq_free_tag_set(&tags[i]);
			goto fail;
		}
	}
	err = misc_register(&device);
	if (!err)
		return 0;
fail:
	destroy(i);
	return err;
}
static void __exit fixture_exit(void)
{
	misc_deregister(&device);
	WARN_ON(atomic_read(&held[0]) || atomic_read(&held[1]));
	destroy(2);
}
module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable native blk-mq tag allocation truth fixture");
