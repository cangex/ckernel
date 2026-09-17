// SPDX-License-Identifier: GPL-2.0
/* Isolated-test-only ground truth. Never load on a production host. */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/cgroup.h>
#include <linux/capability.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/percpu.h>
#include <linux/cis_observe.h>
#ifdef CONFIG_CIS_OBSERVE
#include <trace/events/cis.h>
#endif
#include "uapi.h"
static bool isolated_vm;
module_param(isolated_vm,bool,0400);
static DEFINE_MUTEX(lock_a);
static DEFINE_MUTEX(lock_b);
static DECLARE_RWSEM(fixture_lifetime);
static u64 object_generation=1;
static DEFINE_SPINLOCK(storm_lock);
static u64 storm_counter;
struct dentry_test_context { struct task_struct *task; struct dentry *dentry; u64 slowpaths; };
static DEFINE_PER_CPU(struct dentry_test_context, dentry_test);
#ifdef CONFIG_CIS_OBSERVE
static void dentry_delay(void *unused,void *object,unsigned int kind,unsigned int phase,
		struct task_struct *owner,unsigned long flags,unsigned long skipped)
{
	struct dentry_test_context *test=this_cpu_ptr(&dentry_test);
	(void)unused; (void)owner; (void)flags; (void)skipped;
	if(kind==CIS_LOCKREF && phase==CIS_ACQUIRE && test->task==current &&
	   test->dentry && object==&test->dentry->d_lockref) {
		test->slowpaths++;
		/* Test-only bounded delay inside a real fallback; never sleep under d_lock. */
		udelay(40);
	}
}
#endif
static long dentry_ioctl(unsigned long arg)
{
	struct cis_fixture_dentry q;
	struct fd f;
	struct dentry *d;
	unsigned int i;
	if(copy_from_user(&q,(void __user*)arg,sizeof(q))) return -EFAULT;
	if(q.seed>1) return -EINVAL;
	f=fdget(q.fd); if(!f.file) return -EBADF;
	d=f.file->f_path.dentry;
	q.object=(unsigned long)&d->d_lockref; q.tid=task_pid_nr(current); q.slowpaths=0;
	rcu_read_lock(); q.cgroup_id=cgroup_id(task_dfl_cgroup(current)); rcu_read_unlock();
	q.begin_ns=ktime_get_ns();
	for(i=0;i<2048;i++) {
		struct dentry_test_context *test;
		preempt_disable();
		test=this_cpu_ptr(&dentry_test); test->task=current; test->dentry=d; test->slowpaths=0;
		if(q.seed && !(i&7)) {
			/* Direct d_lock is deliberately outside the lockref-owner coverage. */
			spin_lock(&d->d_lock); udelay(80); spin_unlock(&d->d_lock);
		}
		dget(d); dput(d);
		q.slowpaths+=test->slowpaths;
		test->task=NULL; test->dentry=NULL;
		preempt_enable(); cond_resched();
	}
	q.end_ns=ktime_get_ns(); fdput(f);
	return copy_to_user((void __user*)arg,&q,sizeof(q))?-EFAULT:0;
}
struct async_context {
	struct work_struct work;
	struct completion done;
	struct cgroup *owner;
	struct mutex control;
	struct cis_fixture_async result;
	bool queued;
};
static void fixture_work(struct work_struct *work)
{
	struct async_context *ctx=container_of(work,struct async_context,work);
	ctx->result.start_ns=ktime_get_ns();
	rcu_read_lock(); ctx->result.executor_cgroup=cgroup_id(task_dfl_cgroup(current)); rcu_read_unlock();
	usleep_range(500,600);
	ctx->result.end_ns=ktime_get_ns();
	if(ctx->result.requeue) {
		ctx->result.requeue=0;
		queue_work(system_unbound_wq,&ctx->work);
		return;
	}
	complete(&ctx->done);
}
static int fixture_open(struct inode *inode,struct file *file)
{
	struct async_context *ctx;
	(void)inode;
	if(!capable(CAP_SYS_ADMIN)) return -EPERM;
	ctx=kzalloc(sizeof(*ctx),GFP_KERNEL);
	if(!ctx) return -ENOMEM;
	rcu_read_lock(); ctx->owner=task_dfl_cgroup(current); cgroup_get(ctx->owner); rcu_read_unlock();
	INIT_WORK(&ctx->work,fixture_work); init_completion(&ctx->done); mutex_init(&ctx->control);
	file->private_data=ctx; return 0;
}
static int fixture_release(struct inode *inode,struct file *file)
{
	struct async_context *ctx=file->private_data;
	(void)inode;
	cancel_work_sync(&ctx->work); cgroup_put(ctx->owner); kfree(ctx); return 0;
}
static long async_ioctl(struct file *file,unsigned int cmd,unsigned long arg)
{
	struct async_context *ctx=file->private_data;
	struct cis_fixture_async input;
	long ret=0;
	bool same;
	rcu_read_lock(); same=task_dfl_cgroup(current)==ctx->owner; rcu_read_unlock();
	if(!same) return -EXDEV;
	if(copy_from_user(&input,(void __user*)arg,sizeof(input))) return -EFAULT;
	mutex_lock(&ctx->control);
	if(cmd==CIS_FIXTURE_QUEUE) {
		if(ctx->queued || input.requeue>1) { ret=-EBUSY; goto out; }
		memset(&ctx->result,0,sizeof(ctx->result));
		ctx->result.requeue=input.requeue; ctx->result.owner_cgroup=cgroup_id(ctx->owner);
		ctx->result.object=(unsigned long)&ctx->work; ctx->result.queued_ns=ktime_get_ns();
		reinit_completion(&ctx->done); ctx->queued=true;
		if(!queue_work(system_unbound_wq,&ctx->work)) { ctx->queued=false; ret=-EIO; goto out; }
		/* Return only submission facts: worker result fields are not yet synchronized. */
		input.object=ctx->result.object; input.owner_cgroup=ctx->result.owner_cgroup; input.queued_ns=ctx->result.queued_ns;
	} else if(cmd==CIS_FIXTURE_WAIT) {
		if(!ctx->queued) { ret=-EINVAL; goto out; }
		if(!wait_for_completion_timeout(&ctx->done,msecs_to_jiffies(1000))) { ret=-ETIMEDOUT; goto out; }
		flush_work(&ctx->work); ctx->queued=false; input=ctx->result;
	} else if(cmd==CIS_FIXTURE_CANCEL) {
		input.cancelled=cancel_work_sync(&ctx->work);
		ctx->queued=false; input.object=(unsigned long)&ctx->work; input.owner_cgroup=cgroup_id(ctx->owner);
	}
	if(copy_to_user((void __user*)arg,&input,sizeof(input))) ret=-EFAULT;
out: mutex_unlock(&ctx->control); return ret;
}
static long fixture_ioctl(struct file *file,unsigned int cmd,unsigned long arg)
{
	struct cis_fixture_request q;
	struct mutex *lock;
	(void)file;
	if(!capable(CAP_SYS_ADMIN)) return -EPERM;
	if(cmd==CIS_FIXTURE_DENTRY) return dentry_ioctl(arg);
	if(cmd==CIS_FIXTURE_STORM) {
		struct cis_fixture_storm storm;
		u32 i;
		if(copy_from_user(&storm,(void __user*)arg,sizeof(storm))) return -EFAULT;
		if(!storm.iterations || storm.iterations>4096 || storm.reserved) return -EINVAL;
		for(i=0;i<storm.iterations;i++) {
			spin_lock(&storm_lock); storm_counter++; spin_unlock(&storm_lock);
			if(!(i&63)) cond_resched();
		}
		return 0;
	}
	if(cmd==CIS_FIXTURE_QUEUE || cmd==CIS_FIXTURE_WAIT || cmd==CIS_FIXTURE_CANCEL) return async_ioctl(file,cmd,arg);
	if(cmd!=CIS_FIXTURE_LOCK && cmd!=CIS_FIXTURE_RESET && cmd!=CIS_FIXTURE_BUSY) return -ENOTTY;
	if(copy_from_user(&q,(void __user *)arg,sizeof(q))) return -EFAULT;
	if(cmd==CIS_FIXTURE_RESET) {
		/* Drain all old users, then deliberately reuse the same mutex addresses. */
		down_write(&fixture_lifetime);
		mutex_destroy(&lock_a); mutex_destroy(&lock_b);
		mutex_init(&lock_a); mutex_init(&lock_b);
		q.object_generation=++object_generation; q.object=(unsigned long)&lock_a;
		q.begin_ns=ktime_get_ns();
		up_write(&fixture_lifetime);
		return copy_to_user((void __user*)arg,&q,sizeof(q))?-EFAULT:0;
	}
	if(q.slot>1 || !q.hold_us || q.hold_us>(cmd==CIS_FIXTURE_BUSY?20000:2000)) return -EINVAL;
	down_read(&fixture_lifetime);
	q.object_generation=object_generation;
	lock=q.slot?&lock_b:&lock_a;
	q.object=(unsigned long)lock;
	q.tid=task_pid_nr(current);
	rcu_read_lock(); q.cgroup_id=cgroup_id(task_dfl_cgroup(current)); rcu_read_unlock();
	q.begin_ns=ktime_get_ns();
	if(mutex_lock_interruptible(lock)) { up_read(&fixture_lifetime); return -EINTR; }
	q.acquired_ns=ktime_get_ns();
	if(cmd==CIS_FIXTURE_BUSY) {
		u64 until=ktime_get_ns()+q.hold_us*1000ULL;
		while(ktime_get_ns()<until) cpu_relax();
	} else usleep_range(q.hold_us,q.hold_us+50);
	q.released_ns=ktime_get_ns();
	mutex_unlock(lock);
	up_read(&fixture_lifetime);
	return copy_to_user((void __user *)arg,&q,sizeof(q))?-EFAULT:0;
}
static const struct file_operations ops={.owner=THIS_MODULE,.open=fixture_open,.release=fixture_release,.unlocked_ioctl=fixture_ioctl,.compat_ioctl=fixture_ioctl};
static struct miscdevice device={.minor=MISC_DYNAMIC_MINOR,.name="cis-fixture",.fops=&ops,.mode=0600};
static int __init fixture_init(void)
{
	int ret;
	if(!isolated_vm) return -EPERM;
#ifdef CONFIG_CIS_OBSERVE
	ret=register_trace_cis_lock_state(dentry_delay,NULL);
	if(ret) return ret;
#endif
	ret=misc_register(&device);
#ifdef CONFIG_CIS_OBSERVE
	if(ret) { unregister_trace_cis_lock_state(dentry_delay,NULL); tracepoint_synchronize_unregister(); }
#endif
	return ret;
}
static void __exit fixture_exit(void)
{
	misc_deregister(&device);
#ifdef CONFIG_CIS_OBSERVE
	unregister_trace_cis_lock_state(dentry_delay,NULL); tracepoint_synchronize_unregister();
#endif
}
module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CIS isolated-VM contention ground truth; bounded mutex holds");
