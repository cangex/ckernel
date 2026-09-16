// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "include/ckernel_m.h"

static void subject_equivalence(struct kunit *test)
{
	struct cred *temporary;
	const struct cred *saved;
	bool overridden;

	KUNIT_EXPECT_TRUE(test, aa_ckm_self_subject(current, NULL));
	KUNIT_EXPECT_FALSE(test, aa_ckm_self_subject(NULL, NULL));
	KUNIT_EXPECT_FALSE(test, aa_ckm_self_subject(current, current_cred()));
	temporary = prepare_creds();
	KUNIT_ASSERT_NOT_NULL(test, temporary);
	saved = override_creds(temporary);
	overridden = aa_ckm_self_subject(current, NULL);
	revert_creds(saved);
	abort_creds(temporary);
	KUNIT_EXPECT_FALSE(test, overridden);
	KUNIT_EXPECT_TRUE(test, aa_ckm_self_subject(current, NULL));
}

static struct kunit_case ckm_security_cases[] = {
	KUNIT_CASE(subject_equivalence),
	{}
};

static struct kunit_suite ckm_security_suite = {
	.name = "ckernel-m-apparmor-subject",
	.test_cases = ckm_security_cases,
};
kunit_test_suite(ckm_security_suite);
