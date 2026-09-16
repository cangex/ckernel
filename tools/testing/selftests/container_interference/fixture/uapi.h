/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_FIXTURE_UAPI_H
#define CIS_FIXTURE_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cis_fixture_request {
	__u32 slot, hold_us;
	__u64 object, begin_ns, acquired_ns, released_ns, cgroup_id;
};
#define CIS_FIXTURE_LOCK _IOWR('C', 1, struct cis_fixture_request)
struct cis_fixture_async {
	__u64 object, owner_cgroup, executor_cgroup, queued_ns, start_ns, end_ns;
	__u32 requeue, cancelled;
};
#define CIS_FIXTURE_QUEUE _IOWR('C',2,struct cis_fixture_async)
#define CIS_FIXTURE_WAIT _IOWR('C',3,struct cis_fixture_async)
#define CIS_FIXTURE_CANCEL _IOWR('C',4,struct cis_fixture_async)
#endif
