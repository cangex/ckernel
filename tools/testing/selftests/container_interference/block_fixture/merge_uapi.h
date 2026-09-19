/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_BLOCK_MERGE_TEST_H
#define CIS_BLOCK_MERGE_TEST_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define CIS_MERGE_MAX 9
struct cis_merge_truth {
	__u64 request, begin_ns, end_ns;
	__u32 bytes, bios;
};
struct cis_merge_test {
	__u32 role, count, pattern, reserved;
	__u32 requests, completed, errors, verified;
	struct cis_merge_truth truth[CIS_MERGE_MAX];
};
#define CIS_MERGE_RUN _IOWR(0xda, 1, struct cis_merge_test)
#endif
