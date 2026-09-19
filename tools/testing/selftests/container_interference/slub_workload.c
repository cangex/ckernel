// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "slub_fixture/uapi.h"

int main(int argc, char **argv)
{
	struct cis_slub_request r = {};
	unsigned int op;
	int fd;
	if (argc != 8) return 2;
	op = !strcmp(argv[1], "reset") ? CIS_SLUB_RESET :
	     !strcmp(argv[1], "recreate") ? CIS_SLUB_RECREATE :
	     !strcmp(argv[1], "operate") ? CIS_SLUB_OPERATE : 0;
	if (!op) return 2;
	r.token = strtoull(argv[2], NULL, 10); r.node = strtoul(argv[3], NULL, 10);
	r.hold_us = strtoul(argv[4], NULL, 10); r.wait_node = strtoul(argv[5], NULL, 10);
	r.wait_holders = strtoul(argv[6], NULL, 10); r.mode = strtoul(argv[7], NULL, 10);
	fd = open("/dev/cis-slub-test", O_RDWR | O_CLOEXEC);
	if (fd < 0 || ioctl(fd, op, &r)) { perror("slub fixture"); return 3; }
	printf("CIS_SLUB_TRUTH command=%u hold_us=%u wait_node=%u wait_holders=%u mode=%u token=%llu node=%u task=%llu cache=%llu object=%llu begin_ns=%llu acquired_ns=%llu release_ns=%llu end_ns=%llu outcome=%u\n",
	       op == CIS_SLUB_RESET ? 1 : op == CIS_SLUB_OPERATE ? 2 : 3,
	       r.hold_us, r.wait_node, r.wait_holders, r.mode,
	       (unsigned long long)r.token, r.node, (unsigned long long)r.task,
	       (unsigned long long)r.cache, (unsigned long long)r.object,
	       (unsigned long long)r.begin_ns, (unsigned long long)r.acquired_ns,
	       (unsigned long long)r.release_ns, (unsigned long long)r.end_ns, r.outcome);
	close(fd);
	return 0;
}
