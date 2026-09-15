// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include "internal.h"

static void ckm_abi_layout(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, sizeof(struct ckm_create), (size_t)32);
	KUNIT_EXPECT_EQ(test, offsetof(struct ckm_query, cookie), (size_t)8);
	KUNIT_EXPECT_EQ(test, sizeof(struct ckm_query) % 8, (size_t)0);
}

static struct kunit_case ckm_cases[] = {
	KUNIT_CASE(ckm_abi_layout),
	{}
};
static struct kunit_suite ckm_suite = {
	.name = "ckernel-m-core",
	.test_cases = ckm_cases,
};
kunit_test_suite(ckm_suite);
MODULE_LICENSE("GPL");
