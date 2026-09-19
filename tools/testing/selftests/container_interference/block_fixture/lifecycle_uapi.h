/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_BLOCK_LIFECYCLE_TEST_H
#define CIS_BLOCK_LIFECYCLE_TEST_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define CIS_LIFECYCLE_MAX 4
struct cis_lifecycle_truth {
	__u64 request, bio, begin_ns, end_ns, sector;
	__u32 bytes, status;
};
struct cis_lifecycle_test {
	__u32 role, scenario, reserved[2];
	__u64 original_bio;
	__u32 bytes, requests, completed, io_errors, canceled, verified;
	struct cis_lifecycle_truth truth[CIS_LIFECYCLE_MAX];
};
#define CIS_LIFECYCLE_RUN _IOWR(0xda, 2, struct cis_lifecycle_test)
#endif
