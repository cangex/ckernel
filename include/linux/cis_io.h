/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_IO_H
#define _LINUX_CIS_IO_H
#include <linux/types.h>

/* One closed native pause; no persistent inode or writer ownership. */
struct cis_wb_pause {
	u64 begin_ns, end_ns, cgroup_id;
	u64 dirty, threshold, wb_dirty, wb_threshold;
	s64 requested_jiffies, remaining_jiffies;
};
#endif
