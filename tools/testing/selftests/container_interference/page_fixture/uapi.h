/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_PAGE_FIXTURE_UAPI
#define CIS_PAGE_FIXTURE_UAPI
#include <linux/types.h>
#include <linux/ioctl.h>
#define CIS_PAGE_SMALL 1024
#define CIS_PAGE_LARGE 129
#define CIS_PAGE_ORDER 4
struct cis_page_test {
	__u32 version, node, reserved[2];
	__u64 begin_ns, end_ns, pages_allocated, pages_freed;
	__u32 wrong_node, failed;
};
#define CIS_PAGE_TEST _IOWR('P', 11, struct cis_page_test)
#endif
