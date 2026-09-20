// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "common.h"
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

int main(void)
{
	uint64_t end = cis_now_ns() + 60000000000ULL;
	int fd = open("/tmp/topology-ready", O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0 || close(fd))
		return 2;
	while (cis_now_ns() < end) {
		char command[32] = {0};
		fd = open("/tmp/topology-command", O_RDONLY | O_NOFOLLOW);
		if (fd >= 0) {
			ssize_t count = read(fd, command, sizeof(command) - 1);
			if (close(fd) || count < 0 || unlink("/tmp/topology-command"))
				return 3;
			if (!strcmp(command, "exit"))
				return 0;
			if (strcmp(command, "namespace") || unshare(CLONE_NEWNS) ||
			    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
				return 4;
			fd = open("/tmp/topology-ack", O_WRONLY | O_CREAT | O_EXCL, 0600);
			if (fd < 0 || close(fd))
				return 5;
		}
		usleep(10000);
	}
	return 6;
}
