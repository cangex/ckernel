/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef CIS_ALLOC_PLACEMENT_UAPI_H
#define CIS_ALLOC_PLACEMENT_UAPI_H
#include <linux/ioctl.h>
#include <linux/types.h>
struct cis_alloc_placement {
	__u32 version;
	__s32 requested_node;
	__u64 reserved[2];
	__u64 begin_ns, allocated_ns, release_begin_ns, end_ns;
	__u64 object, cache_address;
	__s32 actual_node, result;
	__u32 cpu, allowed_node;
};
#define CIS_ALLOC_PLACEMENT _IOWR('C', 83, struct cis_alloc_placement)
#endif
