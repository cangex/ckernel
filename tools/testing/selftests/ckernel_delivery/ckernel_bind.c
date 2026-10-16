// SPDX-License-Identifier: GPL-2.0
/* Explicit opt-in launcher. Requires a separately approved kernel/module. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct ck_init_args {
	uint32_t version;
	int32_t online;
	uint64_t features;
	int32_t home_nid, home_l3c;
};
#define CK_INIT_EX _IOW(0xaf, 2, struct ck_init_args)

int main(int argc, char **argv)
{
	struct ck_init_args args = { .version = 1, .online = 1,
		.home_nid = -1, .home_l3c = -1 };
	char *end;
	int fd;

	if (argc < 3) {
		fprintf(stderr, "usage: %s FEATURE_MASK PROGRAM [ARG...]\n", argv[0]);
		return 2;
	}
	errno = 0;
	args.features = strtoull(argv[1], &end, 0);
	if (errno || end == argv[1] || *end || argv[1][0] == '-' ||
	    args.features & ~UINT64_C(0x3ff)) {
		fprintf(stderr, "invalid feature mask\n");
		return 2;
	}
	fd = open("/dev/ckernel", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/ckernel");
		return 1;
	}
	if (ioctl(fd, CK_INIT_EX, &args)) {
		perror("CK_INIT_EX (requested features must be available)");
		close(fd);
		return 1;
	}
	close(fd);
	execvp(argv[2], &argv[2]);
	perror("execvp");
	return 1;
}
