// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/mman.h>

static int shared_fd(void *arg)
{
	return close(*(int *)arg) ? 1 : 0;
}

int test_main(int argc, char **argv)
{
	struct rlimit r = { 64, 64 };
	int fd, copy, fds[128], n = 0;
	void *stack;
	pid_t child;

	(void)argc; (void)argv;
	fd = open("/dev/null", O_RDWR);
	CHECK(fd >= 0);
	copy = dup(fd);
	CHECK(copy >= 0);
	child = fork();
	if (!child)
		_exit(fcntl(copy, F_GETFD) >= 0 && !close(copy) ? 0 : 1);
	CHECK(!child_result(child));
	CHECK(fcntl(copy, F_GETFD) >= 0);
	stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(stack != MAP_FAILED);
	child = clone(shared_fd, (char *)stack + 65536, CLONE_FILES | SIGCHLD, &copy);
	CHECK(!child_result(child));
	CHECK(fcntl(copy, F_GETFD) < 0 && errno == EBADF);
	munmap(stack, 65536);
	close(fd);
	CHECK(!setrlimit(RLIMIT_NOFILE, &r));
	while (n < 128 && (fds[n] = open("/dev/null", O_RDONLY)) >= 0)
		n++;
	CHECK(n < 64 && errno == EMFILE);
	while (n)
		close(fds[--n]);
	return 0;
}
