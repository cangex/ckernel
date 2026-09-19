/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_MAPLE_TEST_UAPI_H
#define CIS_MAPLE_TEST_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cis_maple_truth {
	__u32 version, action, cpu, verified;
	__u64 begin_ns, end_ns, tree[2], generation;
};
#define CIS_MAPLE_TRUTH _IOWR('T', 81, struct cis_maple_truth)
#endif
