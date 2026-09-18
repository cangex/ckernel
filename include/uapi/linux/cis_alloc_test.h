/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_CIS_ALLOC_TEST_H
#define _UAPI_CIS_ALLOC_TEST_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define CIS_AT_ALLOC 1
#define CIS_AT_FREE 2
#define CIS_AT_SHRINK 3
#define CIS_AT_MAX 128
struct cis_alloc_test_request {
	__u32 action, cache, count, bulk;
	__u64 reserved[2];
	__u64 begin_ns, end_ns, cache_address;
	__u32 returned, cpu;
};
#define CIS_ALLOC_TEST_RUN _IOWR('C', 82, struct cis_alloc_test_request)
#endif
