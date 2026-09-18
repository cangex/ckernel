/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_CIS_COUNTER_TEST_H
#define _UAPI_CIS_COUNTER_TEST_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cis_counter_test_request {
	__u32 slot, leaf, operation, reserved;
	__u64 pages, begin_ns, end_ns, leaf_address, parent_address, failed_address;
	__s64 final_leaf, final_parent;
	__u32 success, reserved2;
	__u64 leaf_generation, parent_generation;
};
#define CIS_COUNTER_TEST_RUN _IOWR('C', 80, struct cis_counter_test_request)
struct cis_counter_test_reset {
	__u32 slot, reserved;
	__u64 before[3], after[3];
};
#define CIS_COUNTER_TEST_RESET _IOWR('C', 81, struct cis_counter_test_reset)
#endif
