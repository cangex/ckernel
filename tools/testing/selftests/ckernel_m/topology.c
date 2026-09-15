// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#include <linux/mempolicy.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static int cpu3_online(const char *value)
{
	int fd = open("/sys/devices/system/cpu/cpu3/online", O_WRONLY), rc;

	if (fd < 0)
		return -1;
	rc = write(fd, value, 1) == 1 ? 0 : -1;
	close(fd);
	return rc;
}

static int churn(void)
{
	long page = sysconf(_SC_PAGESIZE);
	char *p;
	int j, rc = 0;

	p = mmap(NULL, page * 512, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 1;
	for (j = 0; j < 512; j += 2)
		if (mprotect(p + j * page, page, PROT_READ)) {
			rc = 1;
			break;
		}
	return munmap(p, page * 512) ? 1 : rc;
}

int test_main(int argc, char **argv)
{
	cpu_set_t before, now;
	unsigned long nodes = 2;
	int j, rc = 1, fd;
	char online;
	bool off = false, policy = false;
	const char *phase = "cross-node churn";

	(void)argc; (void)argv;
	if (!getenv("CKM_ISOLATED_GUEST") ||
	    access("/sys/devices/system/node/node1/cpu3", F_OK))
		return SKIP;
	CHECK(!sched_getaffinity(0, sizeof(before), &before));
	CHECK(CPU_ISSET(0, &before) && CPU_ISSET(3, &before));
	fd = open("/sys/devices/system/cpu/cpu3/online", O_RDONLY);
	CHECK(fd >= 0);
	j = read(fd, &online, 1);
	close(fd);
	CHECK(j == 1 && online == '1');
	for (j = 0; j < 8; j++) {
		CPU_ZERO(&now);
		CPU_SET(j % 2 ? 3 : 0, &now);
		if (sched_setaffinity(0, sizeof(now), &now) || churn())
			goto out;
	}
	CPU_ZERO(&now);
	CPU_SET(0, &now);
	phase = "pin CPU0";
	if (sched_setaffinity(0, sizeof(now), &now))
		goto out;
	phase = "bind node1 policy";
	/* OLK get_nodes() decrements maxnode before copying this bitmap. */
	if (syscall(SYS_set_mempolicy, MPOL_BIND, &nodes,
		    sizeof(nodes) * CHAR_BIT + 1UL))
		goto out;
	policy = true;
	phase = "policy churn";
	if (churn())
		goto out;
	phase = "reset policy";
	if (syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0UL))
		goto out;
	policy = false;
	phase = "CPU3 offline";
	if (cpu3_online("0"))
		goto out;
	off = true;
	phase = "offline churn";
	if (churn())
		goto out;
	phase = "CPU3 online";
	if (cpu3_online("1"))
		goto out;
	off = false;
	CPU_ZERO(&now);
	CPU_SET(3, &now);
	phase = "online churn";
	if (sched_setaffinity(0, sizeof(now), &now) || churn())
		goto out;
	rc = 0;
out:
	if (rc)
		fprintf(stderr, "topology phase=%s errno=%d\n", phase, errno);
	if (policy && syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0UL))
		rc = 1;
	if (off && cpu3_online("1"))
		rc = 1;
	if (sched_setaffinity(0, sizeof(before), &before))
		rc = 1;
	return rc;
}
