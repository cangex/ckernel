// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#if __has_include("../../../../include/uapi/linux/ckernel_m.h")
#include "../../../../include/uapi/linux/ckernel_m.h"
#define HAVE_CKM_ABI
#endif
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>

#ifndef HAVE_CKM_ABI
int test_main(int argc, char **argv)
{
	(void)argc; (void)argv;
	return SKIP;
}
#else
static int query(int fd, struct ckm_query *q)
{
	memset(q, 0, sizeof(*q));
	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	return ioctl(fd, CKM_IOC_QUERY, q);
}

static int reject_shared(void *arg)
{
	int fd = *(int *)arg;

	return !(ioctl(fd, CKM_IOC_BIND, 0UL) < 0 && errno == EBUSY);
}

static int control_edges(int control, struct ckm_create *r)
{
	pid_t children[8], child;
	void *stack = malloc(65536);
	int fd, n, j;

	CHECK(stack);
	fd = ioctl(control, CKM_IOC_CREATE, r);
	CHECK(fd >= 0);
	child = clone(reject_shared, (char *)stack + 65536, CLONE_VM | SIGCHLD, &fd);
	CHECK(!child_result(child));
	child = clone(reject_shared, (char *)stack + 65536, CLONE_FILES | SIGCHLD, &fd);
	CHECK(!child_result(child));
	free(stack);
	CHECK(ioctl(fd, CKM_IOC_BIND, 1UL) < 0 && errno == EINVAL);
	child = fork();
	if (!child) {
		struct ckm_query q;

		if (unshare(CLONE_NEWUSER))
			_exit(errno == EPERM || errno == EINVAL ? SKIP : 1);
		if (ioctl(control, CKM_IOC_CREATE, r) >= 0 || errno != EPERM)
			_exit(1);
		if (query(fd, &q) >= 0 || errno != EPERM)
			_exit(1);
		_exit(ioctl(fd, CKM_IOC_REVOKE, 0UL) < 0 && errno == EPERM ? 0 : 1);
	}
	n = child_result(child);
	if (n == SKIP)
		puts("# SKIP new-userns control authorization: namespace unavailable");
	else
		CHECK(!n);
	close(fd);
	for (n = 0; n < 8; n++) {
		children[n] = fork();
		CHECK(children[n] >= 0);
		if (!children[n]) {
			for (j = 0; j < 8; j++) {
				fd = ioctl(control, CKM_IOC_CREATE, r);
				if (fd < 0 || ioctl(fd, CKM_IOC_REVOKE, 0UL))
					_exit(1);
				close(fd);
			}
			_exit(0);
		}
	}
	for (n = 0; n < 8; n++)
		CHECK(!child_result(children[n]));
	return 0;
}

int test_main(int argc, char **argv)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r) };
	struct ckm_query q;
	int control, fd, round, status;
	pid_t child;

	if (argc > 2 && !strcmp(argv[1], "--exec-child")) {
		fd = atoi(argv[2]);
		CHECK(!query(fd, &q) && q.tasks >= 1);
		CHECK(ioctl(fd, CKM_IOC_BIND, 0UL) < 0 && errno == EBUSY);
		return 0;
	}
	control = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	if (control < 0 && (errno == ENOENT || errno == ENODEV))
		return SKIP;
	CHECK(control >= 0);
	r.reserved[0] = 1;
	CHECK(ioctl(control, CKM_IOC_CREATE, &r) < 0 && errno == EINVAL);
	r.reserved[0] = 0;
	r.version++;
	CHECK(ioctl(control, CKM_IOC_CREATE, &r) < 0 && errno == EINVAL);
	r.version = CKM_ABI_VERSION;
	CHECK(ioctl(control, CKM_IOC_BIND, 0UL) < 0 && errno == ENOTTY);
	CHECK(ioctl(control, CKM_IOC_CREATE, (void *)1) < 0 && errno == EFAULT);
	child = fork();
	if (!child) {
		if (setgid(65534) || setuid(65534))
			_exit(1);
		_exit(ioctl(control, CKM_IOC_CREATE, &r) < 0 && errno == EPERM ? 0 : 1);
	}
	CHECK(!child_result(child));
	CHECK(!control_edges(control, &r));
	for (round = 0; round < 32; round++) {
		fd = ioctl(control, CKM_IOC_CREATE, &r);
		CHECK(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
		CHECK(!query(fd, &q) && q.state == CKM_ACTIVE && !q.tasks);
		child = fork();
		if (!child) {
			char number[24];
			if (ioctl(fd, CKM_IOC_BIND, 0UL) || fcntl(fd, F_SETFD, 0))
				_exit(1);
			snprintf(number, sizeof(number), "%d", fd);
			execl(argv[0], argv[0], "--exec-child", number, NULL);
			_exit(1);
		}
		CHECK(!child_result(child));
		CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0UL));
		CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0UL));
		CHECK(!query(fd, &q) && q.state != CKM_ACTIVE);
		child = fork();
		if (!child)
			_exit(ioctl(fd, CKM_IOC_BIND, 0UL) < 0 && errno == ESHUTDOWN ? 0 : 1);
		status = child_result(child);
		close(fd);
		CHECK(!status);
	}
	close(control);
	return 0;
}
#endif
