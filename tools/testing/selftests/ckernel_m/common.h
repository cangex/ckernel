/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CKM_SELFTEST_COMMON_H
#define CKM_SELFTEST_COMMON_H
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define SKIP 4
#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d: %s failed (errno=%d)\n", \
		__FILE__, __LINE__, #x, errno); return 1; } } while (0)
int child_result(pid_t pid);
int test_main(int argc, char **argv);
#endif
