/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_PROG_INFO_H
#define CIS_PROG_INFO_H
#include <linux/types.h>
#include <stddef.h>

/* Stable BPF_OBJ_GET_INFO_BY_FD prefix through recursion_misses (OLK 6.6).
 * Older build-host UAPI headers lack the final member. All optional pointer
 * and count fields in the retained prefix MUST be zero for this query. */
struct cis_prog_recursion_info {
	__u32 type;
	__u32 id;
	__u8 zero_prefix[200];
	__u64 recursion_misses;
};
_Static_assert(offsetof(struct cis_prog_recursion_info, recursion_misses) == 208,
	"BPF program-info recursion counter ABI offset");
_Static_assert(sizeof(struct cis_prog_recursion_info) == 216,
	"BPF program-info recursion counter ABI size");
#endif
