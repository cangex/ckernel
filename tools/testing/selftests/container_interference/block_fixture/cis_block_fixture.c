// SPDX-License-Identifier: GPL-2.0
/* Disposable VM only: real request requeue and partial-completion boundaries. */
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include "merge_uapi.h"
#include "lifecycle_uapi.h"

#define CIS_BYTES (16U << 20)

static unsigned int test_mode;
module_param(test_mode, uint, 0444);
MODULE_PARM_DESC(test_mode, "1=requeue, 2=partial, 3=plug bio merges, 4=scheduler request merges, 5=split/error/presubmit cancel");
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

struct cis_lifecycle_job {
	struct cis_lifecycle_test output;
	struct completion done;
};
struct cis_disk {
	struct blk_mq_tag_set tags;
	struct gendisk *disk;
	void *data;
	struct mutex job_lock;
	struct cis_lifecycle_job *active_job;
};
struct cis_cmd { bool requeued; };
static struct cis_disk disks[2];
static int major;

struct cis_merge_job {
	struct cis_merge_test output;
	struct completion done;
	atomic_t issued, completed, errors;
};

static void cis_bio_done(struct bio *bio)
{
	struct cis_merge_job *job = bio->bi_private;

	if (bio->bi_status) atomic_inc(&job->errors);
	if (atomic_inc_return(&job->completed) == job->output.count)
		complete(&job->done);
}

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
	struct cis_merge_truth *truth = NULL;
	struct bio *bio;
	struct cis_lifecycle_job *job = READ_ONCE(disk->active_job);
	struct cis_lifecycle_truth *life = NULL;

	if (test_mode == 5 && job) {
		unsigned int index = job->output.requests++;

		if (index < CIS_LIFECYCLE_MAX) {
			life = &job->output.truth[index];
			life->request = (unsigned long)rq;
			life->bio = (unsigned long)rq->bio;
			life->begin_ns = ktime_get_ns();
			life->sector = blk_rq_pos(rq);
			life->bytes = blk_rq_bytes(rq);
		} else atomic64_inc(&errors);
	}
	if ((test_mode == 3 || test_mode == 4) && rq->bio && rq->bio->bi_end_io == cis_bio_done) {
		struct cis_merge_job *job = rq->bio->bi_private;
		int index = atomic_inc_return(&job->issued) - 1;

		if (index < CIS_MERGE_MAX) {
			truth = &job->output.truth[index];
			truth->request = (unsigned long)rq;
			truth->begin_ns = ktime_get_ns();
			truth->bytes = blk_rq_bytes(rq);
			__rq_for_each_bio(bio, rq) {
				truth->bios++;
				if (bio->bi_private != job || bio->bi_end_io != cis_bio_done)
					atomic_inc(&job->errors);
			}
		} else atomic_inc(&job->errors);
	}

	blk_mq_start_request(rq);
	if (!cmd->requeued)
		atomic64_inc(&requests);
	if ((test_mode >= 3 ? (!blk_rq_bytes(rq) || blk_rq_bytes(rq) > CIS_MERGE_MAX * 4096) : blk_rq_bytes(rq) != 4096) ||
	    offset > CIS_BYTES - blk_rq_bytes(rq) ||
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
	if (test_mode == 5 && job && job->output.scenario == 3) {
		atomic64_inc(&errors);
		result = BLK_STS_IOERR;
		goto complete;
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
	if (truth) truth->end_ns = ktime_get_ns();
	if (life) { life->end_ns = ktime_get_ns(); life->status = result; }
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
static unsigned int cis_block_index(struct cis_merge_test *test, unsigned int i)
{
	static const unsigned int bridge[] = { 0, 2, 1 };

	if (test->pattern == 3) return bridge[i];
	return test->pattern == 1 ? i * 2 : test->pattern == 2 ? test->count - 1 - i : i;
}

static void cis_lifecycle_done(struct bio *bio)
{
	struct cis_lifecycle_job *job = bio->bi_private;

	job->output.completed++;
	job->output.io_errors += !!bio->bi_status;
	complete(&job->done);
}

static int cis_lifecycle_ioctl(struct block_device *bdev, blk_mode_t mode,
			      unsigned long arg)
{
	struct cis_disk *disk = bdev->bd_disk->private_data;
	struct cis_lifecycle_job *job;
	struct bio *bio = NULL;
	struct page *pages[2] = {};
	unsigned int i, n, scenario, role;
	int error = -ENOMEM;

	if (!(mode & BLK_OPEN_WRITE)) return -EPERM;
	job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job) return -ENOMEM;
	if (copy_from_user(&job->output, (void __user *)arg, sizeof(job->output))) {
		error = -EFAULT; goto out;
	}
	scenario = job->output.scenario; role = job->output.role;
	if (role > 1 || scenario > 3 || job->output.reserved[0] || job->output.reserved[1]) {
		error = -EINVAL; goto out;
	}
	memset(&job->output, 0, sizeof(job->output));
	job->output.role = role; job->output.scenario = scenario;
	n = scenario ? 2 : 1;
	job->output.bytes = n * 4096;
	init_completion(&job->done);
	bio = bio_alloc(bdev, n, REQ_OP_WRITE, GFP_KERNEL);
	if (!bio) goto out;
	for (i = 0; i < n; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i]) goto out;
		memset(page_address(pages[i]), 0x53 + role, 4096);
		if (bio_add_page(bio, pages[i], 4096, 0) != 4096) goto out;
	}
	bio->bi_iter.bi_sector = (1 + role * 32) * 8;
	bio->bi_private = job; bio->bi_end_io = cis_lifecycle_done;
	job->output.original_bio = (unsigned long)bio;
	/* Independent API truth; never calls observation hooks. Cancellation is
	 * deliberately BEFORE submission and must create no request episode. */
	mutex_lock(&disk->job_lock);
	memset(disk->data + (1 + role * 32) * 4096, 0, n * 4096);
	if (scenario == 2) {
		job->output.canceled = 1;
	} else {
		WRITE_ONCE(disk->active_job, job);
		submit_bio(bio);
		wait_for_completion(&job->done);
		WRITE_ONCE(disk->active_job, NULL);
	}
	job->output.verified = 1;
	for (i = 0; i < n * 4096; i++) {
		unsigned char expected = scenario >= 2 ? 0 : 0x53 + role;

		if (((unsigned char *)disk->data)[(1 + role * 32) * 4096 + i] != expected)
			job->output.verified = 0;
	}
	mutex_unlock(&disk->job_lock);
	error = copy_to_user((void __user *)arg, &job->output, sizeof(job->output)) ? -EFAULT : 0;
out:
	if (bio) bio_put(bio);
	for (i = 0; i < 2; i++) if (pages[i]) __free_page(pages[i]);
	kfree(job);
	return error;
}

static int cis_merge_ioctl(struct block_device *bdev, blk_mode_t mode,
			   unsigned int command, unsigned long arg)
{
	struct cis_disk *disk = bdev->bd_disk->private_data;
	struct cis_merge_job *job;
	struct bio *bios[CIS_MERGE_MAX] = {};
	struct page *pages[CIS_MERGE_MAX] = {};
	struct blk_plug plug;
	unsigned int i, n, block;
	int error = -ENOMEM;

	if (test_mode == 5 && command == CIS_LIFECYCLE_RUN)
		return cis_lifecycle_ioctl(bdev, mode, arg);
	if ((test_mode != 3 && test_mode != 4) || command != CIS_MERGE_RUN) return -ENOTTY;
	if (!(mode & BLK_OPEN_WRITE)) return -EPERM;
	job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job) return -ENOMEM;
	if (copy_from_user(&job->output, (void __user *)arg, sizeof(job->output))) {
		error = -EFAULT; goto out;
	}
	n = job->output.count;
	if (job->output.role > 1 || job->output.reserved ||
	    (test_mode == 3 && ((n != 2 && n != 9) || job->output.pattern > 2)) ||
	    (test_mode == 4 && !((n == 3 && job->output.pattern == 3) || (n == 2 && job->output.pattern == 1)))) {
		error = -EINVAL; goto out;
	}
	memset(&job->output.requests, 0, sizeof(job->output) - offsetof(struct cis_merge_test, requests));
	init_completion(&job->done);
	for (i = 0; i < n; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i]) goto out;
		memset(page_address(pages[i]), 0x33 + job->output.role, 4096);
		bios[i] = bio_alloc(bdev, 1, REQ_OP_WRITE, GFP_KERNEL);
		if (!bios[i]) goto out;
		if (bio_add_page(bios[i], pages[i], 4096, 0) != 4096) goto out;
		block = cis_block_index(&job->output, i);
		bios[i]->bi_iter.bi_sector = (1 + job->output.role * 32 + block) * 8;
		bios[i]->bi_private = job; bios[i]->bi_end_io = cis_bio_done;
	}
	/* No synthetic trace calls. Actual submit/plug/merge/dispatch/endio APIs. */
	blk_start_plug(&plug);
	for (i = 0; i < n; i++) submit_bio(bios[i]);
	blk_finish_plug(&plug);
	wait_for_completion(&job->done);
	job->output.requests = atomic_read(&job->issued);
	job->output.completed = atomic_read(&job->completed);
	job->output.errors = atomic_read(&job->errors);
	job->output.verified = 1;
	for (i = 0; i < n; i++) {
		block = cis_block_index(&job->output, i);
		if (memcmp(disk->data + (1 + job->output.role * 32 + block) * 4096,
			   page_address(pages[i]), 4096)) job->output.verified = 0;
	}
	error = copy_to_user((void __user *)arg, &job->output, sizeof(job->output)) ? -EFAULT : 0;
out:
	for (i = 0; i < CIS_MERGE_MAX; i++) {
		if (bios[i]) bio_put(bios[i]);
		if (pages[i]) __free_page(pages[i]);
	}
	kfree(job);
	return error;
}

static const struct block_device_operations cis_fops = { .owner = THIS_MODULE, .ioctl = cis_merge_ioctl };

static int cis_add_disk(struct cis_disk *d, unsigned int index)
{
	int error;

	d->data = vzalloc(CIS_BYTES);
	if (!d->data)
		return -ENOMEM;
	mutex_init(&d->job_lock);
	d->tags.ops = &cis_mq_ops;
	d->tags.nr_hw_queues = 1;
	d->tags.queue_depth = 16;
	d->tags.numa_node = NUMA_NO_NODE;
	d->tags.cmd_size = sizeof(struct cis_cmd);
	d->tags.flags = BLK_MQ_F_BLOCKING | (test_mode >= 3 ? BLK_MQ_F_SHOULD_MERGE : 0);
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
	blk_queue_max_hw_sectors(d->disk->queue, (test_mode == 3 || test_mode == 4) ? 128 : 8);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, d->disk->queue);
	if (test_mode < 3 || test_mode == 5) blk_queue_flag_set(QUEUE_FLAG_NOMERGES, d->disk->queue);
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

	if (!disposable_vm || (test_mode < 1 || test_mode > 5))
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
