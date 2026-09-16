// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/ckernel_m.h"

#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d %s errno=%d\n", __func__, __LINE__, #x, errno); \
	return 1; } } while (0)

static int create(void)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_VFS | CKM_FEATURE_VFS_OPEN };
	int ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC), inst;

	if (getenv("CKM_OPEN_SECURITY"))
		r.features |= CKM_FEATURE_SECURITY;
	if (ctl < 0)
		return -1;
	inst = ioctl(ctl, CKM_IOC_CREATE, &r);
	close(ctl);
	return inst;
}

static int reg_bind(int inst, const char *root)
{
	struct ckm_vfs_root r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.capacity = 2 };
	int ret;

	r.fd = open(root, O_PATH | O_CLOEXEC);
	if (r.fd < 0)
		return -1;
	ret = ioctl(inst, CKM_IOC_VFS_ROOT, &r);
	close(r.fd);
	return ret ? ret : ioctl(inst, CKM_IOC_BIND, 0);
}

static int query(int inst, struct ckm_vfs_open_query *q)
{
	memset(q, 0, sizeof(*q));
	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	return ioctl(inst, CKM_IOC_VFS_OPEN_QUERY, q);
}

static int fd_message(int sock, int *fd, int send)
{
	char control[CMSG_SPACE(sizeof(int))] = {}, byte = 0;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);

	if (send) {
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(c), fd, sizeof(int));
		return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
	}
	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) != 1 ||
	    msg.msg_flags & MSG_CTRUNC || c->cmsg_level != SOL_SOCKET ||
	    c->cmsg_type != SCM_RIGHTS || c->cmsg_len != CMSG_LEN(sizeof(int)))
		return -1;
	memcpy(fd, CMSG_DATA(c), sizeof(int));
	return 0;
}

struct loop { const char *path; atomic_int stop, errors; };

static void *open_loop(void *arg)
{
	struct loop *l = arg;
	char buf[3];

	while (!atomic_load(&l->stop)) {
		int fd = open(l->path, O_RDONLY);

		if (fd < 0 || read(fd, buf, 3) != 3 || memcmp(buf, "abc", 3))
			atomic_fetch_add(&l->errors, 1);
		if (fd >= 0 && close(fd))
			atomic_fetch_add(&l->errors, 1);
	}
	return NULL;
}

static int one(const char *kind)
{
	char root[] = "/tmp/ckm-open-XXXXXX", path[256], hidden[256], buf[8] = {};
	struct ckm_vfs_open_query q, before;
	int inst, fd, other, k, status;
	pid_t child;

	if (!strcmp(kind, "invalid_feature")) {
		struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
			.features = CKM_FEATURE_VFS_OPEN };

		fd = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
		CHECK(fd >= 0 && ioctl(fd, CKM_IOC_CREATE, &r) == -1 && errno == EOPNOTSUPP);
		CHECK(!close(fd));
		return 0;
	}
	CHECK(!unshare(CLONE_NEWNS));
	CHECK(!mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL));
	CHECK(mkdtemp(root));
	CHECK(!mount("open-loan", root, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m,mode=0755"));
	snprintf(path, sizeof(path), "%s/file", root);
	snprintf(hidden, sizeof(hidden), "%s/hidden", root);
	fd = open(path, O_CREAT | O_RDWR, 0644);
	CHECK(fd >= 0 && write(fd, "abcdef", 6) == 6 && !close(fd));
	fd = open(hidden, O_CREAT | O_RDWR, 0600);
	CHECK(fd >= 0 && !close(fd));
	CHECK(!mount(NULL, root, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
	if (!strcmp(kind, "direct_open")) {
		/* This OLK's shmem_file_open sets FMODE_CAN_ODIRECT. */
		other = open(path, O_RDONLY | O_DIRECT);
		CHECK(other >= 0 && !close(other));
	}
	if (!strcmp(kind, "scm_owner_exit")) {
		int sockets[2];

		CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets));
		child = fork();
		CHECK(child >= 0);
		if (!child) {
			close(sockets[0]);
			inst = create();
			CHECK(inst >= 0 && !reg_bind(inst, root));
			fd = open(path, O_RDONLY);
			CHECK(fd >= 0 && !close(fd));
			fd = open(path, O_RDONLY);
			CHECK(fd >= 0 && !query(inst, &q) && q.hits > 0);
			CHECK(!fd_message(sockets[1], &fd, 1));
			CHECK(!close(fd) && !close(inst));
			_exit(0);
		}
		CHECK(!close(sockets[1]) && !fd_message(sockets[0], &fd, 0));
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
		inst = create();
		CHECK(inst >= 0 && !reg_bind(inst, root));
		CHECK(read(fd, buf, 6) == 6 && !memcmp(buf, "abcdef", 6));
		CHECK(!close(fd) && !close(sockets[0]));
		CHECK(!close(inst) && !umount(root) && !rmdir(root));
		return 0;
	}
	inst = create();
	CHECK(inst >= 0 && !reg_bind(inst, root));
	for (k = 0; k < 3; k++) {
		fd = open(path, O_RDONLY);
		CHECK(fd >= 0 && !close(fd));
	}
	CHECK(!query(inst, &before) && before.hits >= 2 && before.hits == before.released);
	fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	if (!strcmp(kind, "offsets_dup")) {
		other = open(path, O_RDONLY);
		CHECK(other >= 0 && read(fd, buf, 1) == 1 && buf[0] == 'a');
		CHECK(read(other, buf, 1) == 1 && buf[0] == 'a');
		CHECK(!close(other));
		other = dup(fd);
		CHECK(other >= 0 && read(other, buf, 1) == 1 && buf[0] == 'b' && !close(other));
	} else if (!strcmp(kind, "fallback")) {
		CHECK(!query(inst, &before));
		other = open(path, O_PATH);
		CHECK(other >= 0 && !close(other));
		CHECK(open(path, O_WRONLY) == -1 && errno == EROFS);
		CHECK(!query(inst, &q) && q.hits == before.hits);
	} else if (!strcmp(kind, "denied")) {
		other = open(hidden, O_RDONLY);
		CHECK(other >= 0 && !close(other));
		child = fork();
		CHECK(child >= 0);
		if (!child) {
			CHECK(!setuid(65534));
			_exit(!(open(hidden, O_RDONLY) == -1 && errno == EACCES));
		}
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
	} else if (!strcmp(kind, "direct_open")) {
		other = open(path, O_RDONLY | O_DIRECT);
		CHECK(other >= 0 && !close(other));
	} else if (!strcmp(kind, "allocation_fail")) {
		int nth = open("/proc/self/fail-nth", O_RDWR | O_CLOEXEC);
		int rejected = 0, completed = 0;
		char value[32];

		CHECK(nth >= 0);
		for (k = 1; k <= 32; k++) {
			int saved;

			snprintf(value, sizeof(value), "%d", k);
			CHECK(pwrite(nth, value, strlen(value), 0) == (ssize_t)strlen(value));
			other = open(path, O_RDONLY);
			saved = errno;
			CHECK(pwrite(nth, "0", 1, 0) == 1);
			if (other >= 0) {
				completed++;
				CHECK(!close(other));
			} else {
				CHECK(saved == ENOMEM);
				rejected++;
			}
		}
		CHECK(rejected && completed && !close(nth));
		printf("CKM_OPEN_FAULT rejected=%d completed=%d\n", rejected, completed);
	} else if (!strcmp(kind, "lsm_denied")) {
		child = fork();
		CHECK(child >= 0);
		if (!child) {
			const char *change = "changeprofile ckm_open_deny";
			int attr = open("/proc/self/attr/current", O_WRONLY);

			CHECK(attr >= 0 && write(attr, change, strlen(change)) == (ssize_t)strlen(change));
			CHECK(!close(attr));
			_exit(!(open(path, O_RDONLY) == -1 && errno == EACCES));
		}
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
	} else if (!strcmp(kind, "fork_exec")) {
		char number[32];

		snprintf(number, sizeof(number), "%d", fd);
		child = fork();
		CHECK(child >= 0);
		if (!child) {
			execl("/tests/vfs_open_lease", "vfs_open_lease", "inherited", number, NULL);
			_exit(127);
		}
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
	} else if (!strcmp(kind, "revoke_race")) {
		struct loop l = { .path = path };
		pthread_t t[2];

		CHECK(!pthread_create(&t[0], NULL, open_loop, &l));
		CHECK(!pthread_create(&t[1], NULL, open_loop, &l));
		usleep(20000);
		CHECK(!ioctl(inst, CKM_IOC_REVOKE, 0));
		usleep(20000);
		atomic_store(&l.stop, 1);
		CHECK(!pthread_join(t[0], NULL) && !pthread_join(t[1], NULL) && !atomic_load(&l.errors));
	} else if (!strcmp(kind, "remount_unlink")) {
		CHECK(!mount(NULL, root, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL));
		CHECK(!unlink(path));
		other = open(path, O_CREAT | O_WRONLY, 0644);
		CHECK(other >= 0 && write(other, "NEW", 3) == 3 && !close(other));
		CHECK(pread(fd, buf, 6, 0) == 6 && !memcmp(buf, "abcdef", 6));
		other = open(path, O_RDONLY);
		CHECK(other >= 0 && read(other, buf, 3) == 3 && !memcmp(buf, "NEW", 3) && !close(other));
	} else if (!strcmp(kind, "migration")) {
		for (k = 0; k < 128; k++) {
			cpu_set_t cpus;

			CPU_ZERO(&cpus);
			CPU_SET(k % 4, &cpus);
			CHECK(!sched_setaffinity(0, sizeof(cpus), &cpus));
			other = open(path, O_RDONLY);
			CHECK(other >= 0 && !close(other));
		}
	}
	CHECK(umount(root) == -1 && errno == EBUSY);
	CHECK(!close(fd));
	CHECK(!query(inst, &q) && q.hits == q.released);
	if (getenv("CKM_OPEN_SECURITY")) {
		struct ckm_security_query security = { .version = CKM_ABI_VERSION,
			.size = sizeof(security) };

		CHECK(!ioctl(inst, CKM_IOC_SECURITY_QUERY, &security));
		CHECK(security.label_hits > 0 && security.label_hits == security.label_released);
		printf("CKM_OPEN_SECURITY case=%s hits=%llu released=%llu\n",
		       kind, security.label_hits, security.label_released);
	}
	printf("CKM_OPEN_COUNTS case=%s hits=%llu released=%llu native=%llu\n", kind, q.hits, q.released, q.native);
	CHECK(!close(inst) && !umount(root) && !rmdir(root));
	return 0;
}

int main(int argc, char **argv)
{
	const char *cases[] = { "offsets_dup", "fallback", "denied", "direct_open",
		"fork_exec", "revoke_race", "remount_unlink", "migration", "scm_owner_exit", "lsm_denied",
		"invalid_feature", "allocation_fail" };
	unsigned int k;
	int failures = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 3 && !strcmp(argv[1], "inherited")) {
		char b[6];
		int fd = atoi(argv[2]);

		return !(read(fd, b, 6) == 6 && !memcmp(b, "abcdef", 6) && !close(fd));
	}
	if (!getenv("CKM_ISOLATED_GUEST"))
		return 4;
	for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
		int status, rc;
		pid_t p = fork();

		if (!p)
			_exit(one(cases[k]));
		CHECK(p > 0 && waitpid(p, &status, 0) == p);
		rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
		printf("CKM_OPEN_TEST case=%s result=%s\n", cases[k], rc ? "FAIL" : "PASS");
		failures += !!rc;
	}
	return !!failures;
}
