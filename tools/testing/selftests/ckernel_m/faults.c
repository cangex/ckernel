// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

static int put(const char *name, const char *value)
{
	char path[256];
	int fd, rc;

	if (name[0] == '/')
		snprintf(path, sizeof(path), "%s", name);
	else
		snprintf(path, sizeof(path), "/sys/kernel/debug/failslab/%s", name);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	rc = write(fd, value, strlen(value)) == (ssize_t)strlen(value) ? 0 : -1;
	close(fd);
	return rc;
}

static int disarm(void)
{
	int rc = put("times", "0");

	rc |= put("probability", "0");
	rc |= put("/proc/self/make-it-fail", "0");
	return rc;
}

static int arm(void)
{
	return put("/proc/self/make-it-fail", "1") ||
		put("probability", "100") || put("times", "1");
}

int test_main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	char *p;
	int n, rc = 1, injected = 0, outcome, saved;
	pid_t child;

	(void)argc; (void)argv;
	if (!getenv("CKM_ISOLATED_GUEST") || !getenv("CKM_FAULTS") ||
	    access("/sys/kernel/debug/failslab/probability", W_OK) ||
	    access("/proc/self/make-it-fail", W_OK))
		return SKIP;
	p = mmap(NULL, 512 * page, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED);
	if (disarm() || put("task-filter", "1") || put("ignore-gfp-wait", "0") ||
	    put("interval", "1") || put("space", "0") || put("verbose", "0"))
		goto out;
	for (n = 0; n < 16; n++) {
		if (arm())
			goto out;
		child = fork();
		saved = errno;
		if (!child)
			_exit(0);
		if (disarm())
			goto out;
		if (child < 0) {
			if (saved != ENOMEM && saved != EAGAIN)
				goto out;
			injected++;
		} else if (child_result(child)) {
			goto out;
		}
		if (arm())
			goto out;
		outcome = mprotect(p + page, page, PROT_READ);
		saved = errno;
		if (disarm())
			goto out;
		if (outcome && saved != ENOMEM)
			goto out;
		if (mprotect(p, 512 * page, PROT_READ | PROT_WRITE))
			goto out;
		p[page] = 42;
	}
	printf("# targeted failslab fork_failures=%d rounds=16\n", injected);
	if (!injected)
		goto out;
	rc = 0;
out:
	if (disarm())
		rc = 1;
	if (munmap(p, 512 * page))
		rc = 1;
	return rc;
}
