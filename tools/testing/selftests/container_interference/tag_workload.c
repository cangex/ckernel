// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "tag_fixture/abi.h"

int main(int argc, char **argv)
{
	struct cis_tag_op op;
	unsigned int command, disk, slot, nowait;
	int fd;
	if (argc != 2)
		return 2;
	fd = atoi(argv[1]);
	setvbuf(stdout, NULL, _IOLBF, 0);
	puts("{\"event\":\"ready\"}");
	while (scanf("%u %u %u %u", &command, &disk, &slot, &nowait) == 4) {
		memset(&op, 0, sizeof(op));
		op.op = command; op.disk = disk; op.slot = slot; op.nowait = nowait;
		puts("{\"event\":\"attempt\"}");
		if (ioctl(fd, CIS_TAG_OP, &op)) {
			perror("CIS_TAG_OP");
			return 3;
		}
		printf("{\"event\":\"result\",\"op\":%u,\"disk\":%u,\"slot\":%u,\"nowait\":%u,"
		       "\"before_ns\":%llu,\"after_ns\":%llu,\"queue\":%llu,\"task_start\":%llu,"
		       "\"tid\":%u,\"depth\":%u,\"result\":%d,\"tag\":%d,\"held\":[%u,%u]}\n",
		       op.op, op.disk, op.slot, op.nowait, (unsigned long long)op.before_ns,
		       (unsigned long long)op.after_ns, (unsigned long long)op.queue,
		       (unsigned long long)op.task_start, op.tid, op.depth, op.result, op.tag,
		       op.held[0], op.held[1]);
	}
	close(fd);
	return 0;
}
