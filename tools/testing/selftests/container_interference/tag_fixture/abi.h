/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_TAG_FIXTURE_ABI_H
#define CIS_TAG_FIXTURE_ABI_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cis_tag_op {
	__u32 op, disk, slot, nowait;
	__u64 before_ns, after_ns, queue, task_start;
	__u32 tid, depth;
	__s32 result, tag;
	__u32 held[2];
};
#define CIS_TAG_OP _IOWR('T', 0x61, struct cis_tag_op)
#endif
