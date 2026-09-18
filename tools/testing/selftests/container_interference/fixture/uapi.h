/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_FIXTURE_UAPI_H
#define CIS_FIXTURE_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cis_fixture_request {
	__u32 slot, hold_us;
	__u64 object, begin_ns, acquired_ns, released_ns, cgroup_id, object_generation;
	__u64 tid;
};
#define CIS_FIXTURE_LOCK _IOWR('C', 1, struct cis_fixture_request)
struct cis_fixture_async {
	__u64 object, owner_cgroup, executor_cgroup, queued_ns, start_ns, end_ns;
	__u32 requeue, cancelled;
};
#define CIS_FIXTURE_QUEUE _IOWR('C',2,struct cis_fixture_async)
#define CIS_FIXTURE_WAIT _IOWR('C',3,struct cis_fixture_async)
#define CIS_FIXTURE_CANCEL _IOWR('C',4,struct cis_fixture_async)
#define CIS_FIXTURE_RESET _IOWR('C',5,struct cis_fixture_request)
struct cis_fixture_storm { __u32 iterations, reserved; };
#define CIS_FIXTURE_STORM _IOW('C',6,struct cis_fixture_storm)
#define CIS_FIXTURE_BUSY _IOWR('C',7,struct cis_fixture_request)
struct cis_fixture_dentry {
	__s32 fd;
	__u32 seed;
	__u64 object, cgroup_id, tid, begin_ns, end_ns, slowpaths;
};
#define CIS_FIXTURE_DENTRY _IOWR('C',8,struct cis_fixture_dentry)
struct cis_fixture_attempt {
	__u32 mode, hold_us;
	__s32 result;
	__u32 reserved;
	__u64 object, tid, cgroup_id, begin_ns, end_ns, acquired_ns;
};
#define CIS_FIXTURE_ATTEMPT _IOWR('C',9,struct cis_fixture_attempt)
#define CIS_FIXTURE_DENTRY_DELAY _IOW('C',10,__u32)
#endif
