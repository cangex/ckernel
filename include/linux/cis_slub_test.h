/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CIS_SLUB_TEST_H
#define _LINUX_CIS_SLUB_TEST_H
#include <linux/atomic.h>
#include <linux/types.h>
struct kmem_cache;
struct cis_slub_test_truth {
	u64 cache, object, begin_ns, acquired_ns, release_ns, end_ns;
};
#ifdef CONFIG_CIS_SLUB_TEST
int cis_slub_test_lock(struct kmem_cache *, int, unsigned int,
		atomic_t *, struct cis_slub_test_truth *);
#endif
#endif
