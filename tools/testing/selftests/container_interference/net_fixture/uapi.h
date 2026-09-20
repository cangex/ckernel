/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef CIS_NET_FIXTURE_UAPI_H
#define CIS_NET_FIXTURE_UAPI_H
#include <linux/ioctl.h>
#include <linux/types.h>
struct cis_net_test_request {
	__s32 fd;
	__u32 hold_ms;
	__u64 cookie;
	__u64 enter_ns, acquired_ns, release_begin_ns, released_ns, socket_address;
	__u32 cpu, reserved;
};
#define CIS_NET_TEST_HOLD _IOWR(0xca, 83, struct cis_net_test_request)
struct cis_net_clone_request {
	__s32 fd;
	__u32 clone;
	__u64 cookie, original, child, begin_ns, end_ns;
	__u32 data_refs, header_refs;
};
#define CIS_NET_TEST_CLONE _IOWR(0xca, 84, struct cis_net_clone_request)
#define CIS_NET_TEST_DROP_CLONE _IOWR(0xca, 85, struct cis_net_clone_request)
#endif
