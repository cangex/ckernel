/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef CIS_ALLOC_ROLLBACK_UAPI_H
#define CIS_ALLOC_ROLLBACK_UAPI_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define CIS_AR_COUNT 4
struct cis_alloc_rollback {
	__u32 version, action, cache, returned;
	__u32 populated, cpu, reserved[2];
	__u64 begin_ns, end_ns, cache_address;
	__u64 objects[CIS_AR_COUNT];
};
#define CIS_ALLOC_ROLLBACK _IOWR('C', 84, struct cis_alloc_rollback)
#endif
