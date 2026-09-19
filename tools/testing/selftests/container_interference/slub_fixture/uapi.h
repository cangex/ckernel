/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef CIS_SLUB_FIXTURE_UAPI_H
#define CIS_SLUB_FIXTURE_UAPI_H
#include <linux/ioctl.h>
#include <linux/types.h>
struct cis_slub_request {
	__u64 token, cache, object, begin_ns, acquired_ns, release_ns, end_ns, task;
	__u32 node, wait_node, wait_holders, hold_us, mode, outcome;
};
#define CIS_SLUB_RESET _IOWR('u', 1, struct cis_slub_request)
#define CIS_SLUB_OPERATE _IOWR('u', 2, struct cis_slub_request)
#define CIS_SLUB_RECREATE _IOWR('u', 3, struct cis_slub_request)
#endif
