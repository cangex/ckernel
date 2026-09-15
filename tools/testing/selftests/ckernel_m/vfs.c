// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

int test_main(int argc, char **argv)
{
	char path[] = "/tmp/ckm-vfs-XXXXXX", buf[4] = {};
	int fd, old;
	struct stat s;

	(void)argc; (void)argv;
	fd = mkstemp(path);
	CHECK(fd >= 0 && write(fd, "old", 3) == 3);
	old = open(path, O_RDONLY);
	CHECK(old >= 0 && !unlink(path));
	close(fd);
	fd = open(path, O_CREAT | O_RDWR | O_EXCL, 0600);
	CHECK(fd >= 0 && write(fd, "new!", 4) == 4);
	CHECK(!fstat(fd, &s) && s.st_size == 4);
	CHECK(read(old, buf, 3) == 3 && !memcmp(buf, "old", 3));
	close(old); close(fd);
	CHECK(!unlink(path));
	return 0;
}
