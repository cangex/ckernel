// SPDX-License-Identifier: GPL-2.0
/* Disposable VM only: real request requeue and partial-completion boundaries. */
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#define CIS_BYTES (16U << 20)

static unsigned int test_mode;
module_param(test_mode, uint, 0444);
MODULE_PARM_DESC(test_mode, "1=requeue once, 2=two 2048-byte completions");
static bool disposable_vm;
module_param(disposable_vm, bool, 0444);

static atomic64_t requests, requeues, partials, completions, errors;
static int counter_get(char *buffer, const struct kernel_param *param)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n", atomic64_read(param->arg));
}
static const struct kernel_param_ops counter_ops = { .get = counter_get };
module_param_cb(requests, &counter_ops, &requests, 0444);
module_param_cb(requeues, &counter_ops, &requeues, 0444);
module_param_cb(partials, &counter_ops, &partials, 0444);
module_param_cb(completions, &counter_ops, &completions, 0444);
module_param_cb(errors, &counter_ops, &errors, 0444);

struct cis_disk {
	struct blk_mq_tag_set tags;
	struct gendisk *disk;
	void *data;
};
struct cis_cmd { bool requeued; };
static struct cis_disk disks[2];
static int major;

static blk_status_t cis_queue_rq(struct blk_mq_hw_ctx *hctx,
			       const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct cis_disk *disk = hctx->queue->queuedata;
	struct cis_cmd *cmd = blk_mq_rq_to_pdu(rq);
	struct req_iterator iter;
	struct bio_vec bvec;
	u64 offset = (u64)blk_rq_pos(rq) << SECTOR_SHIFT;
	blk_status_t result = BLK_STS_OK;

	blk_mq_start_request(rq);
	if (!cmd->requeued)
		atomic64_inc(&requests);
	if (blk_rq_bytes(rq) != 4096 || offset > CIS_BYTES - 4096 ||
	    (req_op(rq) != REQ_OP_READ && req_op(rq) != REQ_OP_WRITE)) {
		atomic64_inc(&errors);
		result = BLK_STS_IOERR;
		goto complete;
	}
	if (test_mode == 1 && !cmd->requeued) {
		cmd->requeued = true;
		atomic64_inc(&requeues);
		blk_mq_requeue_request(rq, true);
		return BLK_STS_OK;
	}
	/* Actors use disjoint sectors. This fixture asserts no device blocker. */
	rq_for_each_segment(bvec, rq, iter) {
		void *address = kmap_local_page(bvec.bv_page);

		if (req_op(rq) == REQ_OP_WRITE)
			memcpy(disk->data + offset, address + bvec.bv_offset, bvec.bv_len);
		else
			memcpy(address + bvec.bv_offset, disk->data + offset, bvec.bv_len);
		kunmap_local(address);
		offset += bvec.bv_len;
	}
	if (test_mode == 2) {
		atomic64_inc(&partials);
		if (WARN_ON_ONCE(!blk_update_request(rq, BLK_STS_OK, 2048))) {
			atomic64_inc(&errors);
			result = BLK_STS_IOERR;
		}
	}
complete:
	cmd->requeued = false;
	atomic64_inc(&completions);
	blk_mq_end_request(rq, result);
	return BLK_STS_OK;
}

static int cis_init_request(struct blk_mq_tag_set *set, struct request *rq,
			    unsigned int hctx_idx, unsigned int numa_node)
{
	struct cis_cmd *cmd = blk_mq_rq_to_pdu(rq);

	cmd->requeued = false;
	return 0;
}

static const struct blk_mq_ops cis_mq_ops = {
	.queue_rq = cis_queue_rq, .init_request = cis_init_request,
};
static const struct block_device_operations cis_fops = { .owner = THIS_MODULE };

static int cis_add_disk(struct cis_disk *d, unsigned int index)
{
	int error;

	d->data = vzalloc(CIS_BYTES);
	if (!d->data)
		return -ENOMEM;
	d->tags.ops = &cis_mq_ops;
	d->tags.nr_hw_queues = 1;
	d->tags.queue_depth = 16;
	d->tags.numa_node = NUMA_NO_NODE;
	d->tags.cmd_size = sizeof(struct cis_cmd);
	d->tags.flags = BLK_MQ_F_BLOCKING;
	d->tags.driver_data = d;
	error = blk_mq_alloc_tag_set(&d->tags);
	if (error)
		goto free_data;
	d->disk = blk_mq_alloc_disk(&d->tags, d);
	if (IS_ERR(d->disk)) {
		error = PTR_ERR(d->disk);
		d->disk = NULL;
		goto free_tags;
	}
	d->disk->major = major;
	d->disk->first_minor = index;
	d->disk->minors = 1;
	d->disk->flags |= GENHD_FL_NO_PART;
	d->disk->fops = &cis_fops;
	d->disk->private_data = d;
	snprintf(d->disk->disk_name, DISK_NAME_LEN, "cisblock%u", index);
	blk_queue_logical_block_size(d->disk->queue, 512);
	blk_queue_max_hw_sectors(d->disk->queue, 8);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, d->disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, d->disk->queue);
	set_capacity(d->disk, CIS_BYTES >> SECTOR_SHIFT);
	error = add_disk(d->disk);
	if (!error)
		return 0;
	put_disk(d->disk);
	d->disk = NULL;
free_tags:
	blk_mq_free_tag_set(&d->tags);
free_data:
	vfree(d->data);
	d->data = NULL;
	return error;
}

static void cis_remove_disk(struct cis_disk *d)
{
	del_gendisk(d->disk);
	put_disk(d->disk);
	blk_mq_free_tag_set(&d->tags);
	vfree(d->data);
}

static int __init cis_init(void)
{
	int error;

	if (!disposable_vm || (test_mode != 1 && test_mode != 2))
		return -EINVAL;
	major = register_blkdev(0, "cisblock");
	if (major < 0)
		return major;
	error = cis_add_disk(&disks[0], 0);
	if (error)
		goto unregister;
	error = cis_add_disk(&disks[1], 1);
	if (!error)
		return 0;
	cis_remove_disk(&disks[0]);
unregister:
	unregister_blkdev(major, "cisblock");
	return error;
}

static void __exit cis_exit(void)
{
	cis_remove_disk(&disks[1]);
	cis_remove_disk(&disks[0]);
	unregister_blkdev(major, "cisblock");
}
module_init(cis_init);
module_exit(cis_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable memory devices for native request lifecycle truth");
