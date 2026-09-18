/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_RWSEM_TEST_H
#define CIS_RWSEM_TEST_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct cis_rwsem_test {
	__u64 token, address, enter_ns, acquired_ns, release_ns, end_ns, task;
	__u32 slot, mode, hold_ms, wait_slot, wait_holders;
	__s32 outcome;
};
#define CIS_RWSEM_RESET _IOWR('Z', 81, struct cis_rwsem_test)
#define CIS_RWSEM_OPERATE _IOWR('Z', 82, struct cis_rwsem_test)
#endif
