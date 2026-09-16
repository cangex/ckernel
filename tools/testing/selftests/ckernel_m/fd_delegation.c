// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/ckernel_m.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d %s errno=%d\n", \
	__func__, __LINE__, #x, errno); return 1; } } while (0)
static int enabled = 1;
struct fixture { int root, a, b, au, bu, pu, al, pl, inst; char path[160]; };

static int putfd(int fd, const char *value)
{
	return lseek(fd, 0, SEEK_SET) < 0 || write(fd, value, strlen(value)) != (ssize_t)strlen(value);
}

static long number(int fd)
{
	char buf[80] = {};

	if (lseek(fd, 0, SEEK_SET) < 0 || read(fd, buf, sizeof(buf) - 1) <= 0)
		return -1;
	return strtol(buf, NULL, 10);
}

static int limit(int fd, long value)
{
	char buf[80];

	snprintf(buf, sizeof(buf), "%ld", value);
	return putfd(fd, buf);
}

static int openat_file(const char *path, const char *name)
{
	char buf[512];
	int len;

	len = snprintf(buf, sizeof(buf), "%s/%s", path, name);
	if (len < 0 || (size_t)len >= sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
	return open(buf, (!strcmp(name, "files.usage") ? O_RDONLY : O_RDWR) | O_CLOEXEC);
}

static int setup(struct fixture *f)
{
	char path[180];

	memset(f, 0, sizeof(*f));
	f->inst = -1;
	snprintf(f->path, sizeof(f->path), "/files/ckm-fd-%d", getpid());
	CHECK(!mkdir(f->path, 0755));
	f->root = open("/files/cgroup.procs", O_WRONLY | O_CLOEXEC);
	f->pu = openat_file(f->path, "files.usage");
	f->pl = openat_file(f->path, "files.limit");
	snprintf(path, sizeof(path), "%s/a", f->path);
	CHECK(!mkdir(path, 0755));
	f->a = openat_file(path, "cgroup.procs");
	f->au = openat_file(path, "files.usage");
	f->al = openat_file(path, "files.limit");
	snprintf(path, sizeof(path), "%s/b", f->path);
	CHECK(!mkdir(path, 0755));
	f->b = openat_file(path, "cgroup.procs");
	f->bu = openat_file(path, "files.usage");
	CHECK(f->root >= 0 && f->a >= 0 && f->b >= 0 && f->au >= 0 &&
	      f->bu >= 0 && f->pu >= 0 && f->al >= 0 && f->pl >= 0);
	CHECK(!putfd(f->a, "0"));
	return 0;
}

static int enroll(struct fixture *f)
{
	struct ckm_create req = { .version = CKM_ABI_VERSION, .size = sizeof(req),
		.features = CKM_FEATURE_FD };
	int ctl;

	if (!enabled)
		return 0;
	ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	CHECK(ctl >= 0);
	f->inst = ioctl(ctl, CKM_IOC_CREATE, &req);
	CHECK(f->inst >= 0 && !close(ctl));
	CHECK(!ioctl(f->inst, CKM_IOC_BIND, 0));
	return 0;
}

static int query(struct fixture *f, struct ckm_fd_query *q)
{
	memset(q, 0, sizeof(*q));
	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	return enabled ? ioctl(f->inst, CKM_IOC_FD_QUERY, q) : 0;
}

static int create_only(struct ckm_create *req)
{
	int ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC), result, saved;

	if (ctl < 0) return -1;
	result = ioctl(ctl, CKM_IOC_CREATE, req);
	saved = errno;
	close(ctl);
	errno = saved;
	return result;
}

static int retire(int fd)
{
	int k;
	struct fixture f = { .inst = fd };
	struct ckm_fd_query q;

	CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0));
	for (k = 0; k < 2000; k++) {
		CHECK(!query(&f, &q));
		if (q.stopped) break;
		usleep(1000);
	}
	CHECK(q.stopped && !q.idle && !close(fd));
	return 0;
}

static int wait_ok(pid_t p)
{
	int status;

	return p < 0 || waitpid(p, &status, 0) != p || !WIFEXITED(status) || WEXITSTATUS(status);
}

static int warm(void)
{
	int fd = open("/dev/null", O_RDONLY);

	CHECK(fd >= 0 && !close(fd));
	return 0;
}

static int usage(void)
{
	struct fixture f;
	struct ckm_fd_query q;
	int fd[128], k;
	long base;

	CHECK(!setup(&f) && !enroll(&f));
	base = number(f.au);
	CHECK(base > 0 && !warm() && !query(&f, &q));
	if (enabled) CHECK(q.idle > 0 && q.idle <= CKM_FD_MAX_IDLE && q.local_free > 0);
	CHECK(number(f.au) == base && !query(&f, &q) && q.idle == 0);
	for (k = 0; k < 128; k++) CHECK((fd[k] = open("/dev/null", O_RDONLY)) >= 0);
	CHECK(number(f.au) == base + 128);
	for (k = 0; k < 128; k++) CHECK(!close(fd[k]));
	CHECK(number(f.au) == base);
	return 0;
}

static int limits(void)
{
	struct fixture f;
	int fd[4], k, bad;
	long base;

	CHECK(!setup(&f) && !enroll(&f));
	base = number(f.au);
	CHECK(base > 0 && !limit(f.al, base + 4));
	for (k = 0; k < 4; k++) CHECK((fd[k] = open("/dev/null", O_RDONLY)) >= 0);
	bad = open("/dev/null", O_RDONLY);
	CHECK(bad == -1 && errno == EMFILE);
	CHECK(number(f.au) == base + 4);
	/* Preserve legacy set_max's ignored EBUSY, rather than inventing semantics. */
	CHECK(!limit(f.al, base + 3) && number(f.al) == base + 4);
	for (k = 0; k < 4; k++) CHECK(!close(fd[k]));
	CHECK(number(f.au) == base && !limit(f.al, base));
	CHECK(open("/dev/null", O_RDONLY) == -1 && errno == EMFILE);
	CHECK(!putfd(f.al, "max"));
	return 0;
}

static int rollback(void)
{
	struct fixture f;
	long base;
	int k;

	CHECK(!setup(&f) && !enroll(&f));
	base = number(f.au);
	for (k = 0; k < 200; k++) {
		CHECK(open("/tmp/ckm-does-not-exist", O_RDONLY) == -1 && errno == ENOENT);
		CHECK(dup(-1) == -1 && errno == EBADF);
	}
	CHECK(number(f.au) == base);
	return 0;
}

static int dup_replace(void)
{
	struct fixture f;
	struct rlimit old, tight;
	long base;
	int a, b, k;

	CHECK(!setup(&f) && !enroll(&f));
	a = open("/dev/null", O_RDONLY);
	b = open("/dev/zero", O_RDONLY);
	CHECK(a >= 0 && b >= 0);
	base = number(f.au);
	for (k = 0; k < 200; k++) {
		CHECK(dup2(a, b) == b && dup2(a, a) == a);
		CHECK(dup3(a, a, O_CLOEXEC) == -1 && errno == EINVAL);
	}
	CHECK(number(f.au) == base && !getrlimit(RLIMIT_NOFILE, &old));
	tight = old;
	tight.rlim_cur = 0;
	CHECK(!setrlimit(RLIMIT_NOFILE, &tight));
	CHECK(dup(a) == -1 && errno == EMFILE);
	CHECK(open("/dev/null", O_RDONLY) == -1 && errno == EMFILE);
	CHECK(!setrlimit(RLIMIT_NOFILE, &old) && number(f.au) == base);
	CHECK(!close(a) && !close(b) && number(f.au) == base - 2);
	return 0;
}

static int inheritance(void)
{
	struct fixture f;
	int ready[2], go[2];
	long base;
	char byte;
	pid_t p;

	CHECK(!pipe(ready) && !pipe(go) && !setup(&f) && !enroll(&f));
	base = number(f.au);
	CHECK(base > 0 && !limit(f.al, base * 2 - 1));
	p = fork();
	CHECK(p == -1 && errno == EMFILE);
	CHECK(number(f.au) == base && !limit(f.al, base * 2));
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(write(ready[1], "R", 1) == 1 && read(go[0], &byte, 1) == 1);
		_exit(0);
	}
	CHECK(read(ready[0], &byte, 1) == 1 && number(f.au) == base * 2);
	CHECK(write(go[1], "G", 1) == 1 && !wait_ok(p));
	CHECK(number(f.au) == base && !putfd(f.al, "max"));
	return 0;
}

static atomic_int thread_errors;

static void *fd_thread(void *arg)
{
	int base = *(int *)arg, k, fd;

	for (k = 0; k < 2000; k++) {
		fd = dup(base);
		if (fd < 0 || close(fd)) atomic_fetch_add(&thread_errors, 1);
	}
	return NULL;
}

static int shared_files(void)
{
	struct fixture f;
	pthread_t t[4];
	long base;
	int fd, k;

	CHECK(!setup(&f) && !enroll(&f));
	fd = open("/dev/null", O_RDONLY);
	CHECK(fd >= 0);
	base = number(f.au);
	for (k = 0; k < 4; k++) CHECK(!pthread_create(&t[k], NULL, fd_thread, &fd));
	for (k = 0; k < 4; k++) CHECK(!pthread_join(t[k], NULL));
	CHECK(!atomic_load(&thread_errors) && number(f.au) == base);
	CHECK(!close(fd));
	return 0;
}

static int migration(void)
{
	struct fixture f;
	struct ckm_fd_query before, after;
	long base;

	CHECK(!setup(&f) && !enroll(&f));
	base = number(f.au);
	CHECK(!warm() && !putfd(f.b, "0"));
	CHECK(number(f.au) == 0 && number(f.bu) == base);
	CHECK(!query(&f, &before) && before.idle == 0 && !warm() && !query(&f, &after));
	CHECK(after.local_alloc == before.local_alloc && number(f.bu) == base);
	CHECK(!putfd(f.a, "0") && number(f.au) == base && number(f.bu) == 0);
	CHECK(!warm() && !query(&f, &after));
	if (enabled) CHECK(after.local_alloc > before.local_alloc);
	return 0;
}

static int limit_race(void)
{
	struct fixture f;
	pthread_t threads[4];
	long base;
	int fd, k;

	CHECK(!setup(&f) && !enroll(&f));
	fd = open("/dev/null", O_RDONLY);
	CHECK(fd >= 0);
	base = number(f.au);
	for (k = 0; k < 4; k++) CHECK(!pthread_create(&threads[k], NULL, fd_thread, &fd));
	for (k = 0; k < 1000; k++) CHECK(!limit(f.al, base + (k & 1 ? 32 : 256)));
	for (k = 0; k < 4; k++) CHECK(!pthread_join(threads[k], NULL));
	CHECK(!atomic_load(&thread_errors) && number(f.au) == base && !putfd(f.al, "max"));
	CHECK(!close(fd));
	return 0;
}

static int sibling_rescue(void)
{
	struct fixture f;
	struct ckm_fd_query q;
	int ready[2], go[2], fd[64], k;
	long a, b;
	char byte;
	pid_t p;

	CHECK(!pipe(ready) && !pipe(go) && !setup(&f));
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(!putfd(f.b, "0"));
		CHECK(write(ready[1], "R", 1) == 1 && read(go[0], &byte, 1) == 1);
		for (k = 0; k < 64; k++) CHECK((fd[k] = open("/dev/null", O_RDONLY)) >= 0);
		CHECK(open("/dev/null", O_RDONLY) == -1 && errno == EMFILE);
		CHECK(write(ready[1], "F", 1) == 1 && read(go[0], &byte, 1) == 1);
		for (k = 0; k < 64; k++) CHECK(!close(fd[k]));
		_exit(0);
	}
	CHECK(read(ready[0], &byte, 1) == 1 && !enroll(&f));
	a = number(f.au); b = number(f.bu);
	CHECK(a > 0 && b > 0 && !limit(f.pl, a + b + 64));
	CHECK(!warm() && !query(&f, &q));
	if (enabled) CHECK(q.idle == 64);
	CHECK(write(go[1], "G", 1) == 1 && read(ready[0], &byte, 1) == 1 && byte == 'F');
	CHECK(!query(&f, &q) && q.idle == 0);
	CHECK(number(f.pu) == a + b + 64);
	CHECK(write(go[1], "D", 1) == 1 && !wait_ok(p));
	CHECK(number(f.au) == a && number(f.bu) == 0 && !putfd(f.pl, "max"));
	return 0;
}

static int revoke_pool(void)
{
	struct fixture f;
	struct ckm_fd_query a, b;
	long base;
	int fd, k;

	CHECK(!setup(&f) && !enroll(&f));
	base = number(f.au);
	fd = open("/dev/null", O_RDONLY);
	CHECK(fd >= 0 && !warm());
	if (enabled) {
		CHECK(!ioctl(f.inst, CKM_IOC_REVOKE, 0));
		for (k = 0; k < 2000; k++) {
			CHECK(!query(&f, &a));
			if (a.stopped) break;
			usleep(1000);
		}
		CHECK(a.stopped && !a.idle && !warm() && !query(&f, &b));
		CHECK(b.local_alloc == a.local_alloc);
	}
	CHECK(number(f.au) == base + 1 && !close(fd) && number(f.au) == base);
	return 0;
}

static int pass_fd(int socket, int fd)
{
	char data = 'F', control[CMSG_SPACE(sizeof(fd))] = {};
	struct iovec io = { &data, 1 };
	struct msghdr msg = { .msg_iov = &io, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);

	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(c), &fd, sizeof(fd));
	return sendmsg(socket, &msg, 0) != 1;
}

static int take_fd(int socket)
{
	char data, control[CMSG_SPACE(sizeof(int))] = {};
	struct iovec io = { &data, 1 };
	struct msghdr msg = { .msg_iov = &io, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *c;
	int fd;

	if (recvmsg(socket, &msg, MSG_CMSG_CLOEXEC) != 1 || msg.msg_flags & MSG_CTRUNC)
		return -1;
	c = CMSG_FIRSTHDR(&msg);
	if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
	    c->cmsg_len != CMSG_LEN(sizeof(fd))) return -1;
	memcpy(&fd, CMSG_DATA(c), sizeof(fd));
	return fd;
}

static int scm_rights(void)
{
	struct fixture f;
	int sockets[2], fd;
	long base;
	char byte;
	pid_t p;

	CHECK(!socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) && !setup(&f));
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(!putfd(f.b, "0") && !enroll(&f));
		base = number(f.bu);
		CHECK(base > 0 && write(sockets[1], "R", 1) == 1);
		fd = take_fd(sockets[1]);
		CHECK(fd >= 0 && number(f.bu) == base + 1);
		CHECK(write(sockets[1], "H", 1) == 1 && read(sockets[1], &byte, 1) == 1);
		CHECK(byte == 'D' && write(fd, "x", 1) == 1 && !close(fd));
		CHECK(number(f.bu) == base && write(sockets[1], "C", 1) == 1);
		_exit(0);
	}
	CHECK(read(sockets[0], &byte, 1) == 1 && byte == 'R' && !enroll(&f));
	base = number(f.au);
	fd = open("/dev/null", O_RDWR);
	CHECK(fd >= 0 && !pass_fd(sockets[0], fd));
	CHECK(read(sockets[0], &byte, 1) == 1 && byte == 'H');
	CHECK(number(f.au) == base + 1 && !close(fd));
	if (enabled) CHECK(!retire(f.inst));
	CHECK(number(f.au) == base - !!enabled);
	CHECK(write(sockets[0], "D", 1) == 1 && read(sockets[0], &byte, 1) == 1 && byte == 'C');
	CHECK(!wait_ok(p) && number(f.bu) == 0);
	return 0;
}

static int revoke_race(void)
{
	struct fixture f;
	pthread_t threads[4];
	int fd, k;
	long base;

	CHECK(!setup(&f) && !enroll(&f));
	fd = open("/dev/null", O_RDONLY);
	CHECK(fd >= 0);
	base = number(f.au);
	for (k = 0; k < 4; k++) CHECK(!pthread_create(&threads[k], NULL, fd_thread, &fd));
	if (enabled) CHECK(!ioctl(f.inst, CKM_IOC_REVOKE, 0));
	for (k = 0; k < 4; k++) CHECK(!pthread_join(threads[k], NULL));
	CHECK(!atomic_load(&thread_errors) && number(f.au) == base && !close(fd));
	return 0;
}

static int batch_exit(void)
{
	struct fixture f;
	pid_t children[16];
	int ready[2], go[2], k, batch;
	long base;
	char byte;

	CHECK(!pipe(ready) && !pipe(go) && !setup(&f));
	base = number(f.pu);
	for (batch = 0; batch < 4; batch++) {
		for (k = 0; k < 16; k++) {
			children[k] = fork();
			CHECK(children[k] >= 0);
			if (!children[k]) {
				char path[256];
				int procs, fds[96], j;

				snprintf(path, sizeof(path), "%s/child-%d", f.path, getpid());
				CHECK(!mkdir(path, 0755));
				procs = openat_file(path, "cgroup.procs");
				CHECK(procs >= 0 && !putfd(procs, "0") && !enroll(&f));
				for (j = 0; j < 96; j++) CHECK((fds[j] = open("/dev/null", O_RDONLY)) >= 0);
				for (j = 0; j < 48; j++) CHECK(!close(fds[j]));
				CHECK(write(ready[1], "R", 1) == 1 && read(go[0], &byte, 1) == 1);
				/* Exit with live FDs and idle reservations; cleanup must differ. */
				_exit(0);
			}
		}
		for (k = 0; k < 16; k++) CHECK(read(ready[0], &byte, 1) == 1);
		CHECK(number(f.pu) > base);
		for (k = 0; k < 16; k++) CHECK(write(go[1], "G", 1) == 1);
		for (k = 0; k < 16; k++) CHECK(!wait_ok(children[k]));
		CHECK(number(f.pu) == base);
	}
	return 0;
}

static int abi(void)
{
	struct fixture f;
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_FD };
	struct ckm_fd_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q), .pad = 1 };
	int fd;
	pid_t p;

	CHECK(create_only(&r) == -1 && errno == EOPNOTSUPP);
	CHECK(!setup(&f));
	r.reserved[0] = 1;
	CHECK(create_only(&r) == -1 && errno == EINVAL);
	r.reserved[0] = 0;
	fd = create_only(&r);
	CHECK(fd >= 0 && create_only(&r) == -1 && errno == EBUSY);
	CHECK(ioctl(fd, CKM_IOC_FD_QUERY, &q) == -1 && errno == EINVAL);
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(!setuid(65534));
		CHECK(ioctl(fd, CKM_IOC_REVOKE, 0) == -1 && errno == EPERM);
		_exit(0);
	}
	CHECK(!wait_ok(p) && !retire(fd));
	fd = create_only(&r);
	CHECK(fd >= 0 && !retire(fd));
	return 0;
}

static int faults(void)
{
	struct fixture f;
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_FD };
	int nth, fd, k, failed = 0, completed = 0;
	char value[32];
	const char *knobs[] = { "/sys/kernel/debug/failslab/ignore-gfp-wait",
		"/sys/kernel/debug/failslab/verbose" };

	CHECK(!setup(&f));
	nth = open("/proc/self/fail-nth", O_RDWR | O_CLOEXEC);
	CHECK(nth >= 0);
	for (k = 0; k < 2; k++) {
		fd = open(knobs[k], O_WRONLY);
		CHECK(fd >= 0 && write(fd, "0", 1) == 1 && !close(fd));
	}
	for (k = 1; k <= 64; k++) {
		int len = snprintf(value, sizeof(value), "%d", k);
		CHECK(pwrite(nth, value, len, 0) == len);
		fd = create_only(&r);
		CHECK(pwrite(nth, "0", 1, 0) == 1);
		if (fd < 0) failed++;
		else { completed++; CHECK(!retire(fd)); }
		fd = create_only(&r);
		CHECK(fd >= 0 && !retire(fd));
	}
	printf("CKM_FD_FAULT probes=64 rejected=%d completed=%d recovery=64\n", failed, completed);
	CHECK(failed > 0 && completed > 0 && !close(nth));
	return 0;
}

static int admin_disable(void)
{
	struct fixture f;
	struct ckm_fd_query q;
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_FD };
	int control;

	CHECK(!setup(&f) && !enroll(&f) && !warm());
	control = open("/files/files.no_acct", O_WRONLY);
	CHECK(control >= 0 && !query(&f, &q) && q.idle > 0);
	CHECK(write(control, "1", 1) == 1 && !query(&f, &q));
	CHECK(q.stopped && !q.idle);
	CHECK(create_only(&r) == -1 && errno == EOPNOTSUPP);
	CHECK(!close(control) && !retire(f.inst));
	return 0;
}

int main(int argc, char **argv)
{
	struct { const char *name; int (*fn)(void); } cases[] = {
		{ "usage", usage }, { "limits", limits }, { "rollback", rollback },
		{ "dup_replace", dup_replace },
		{ "inheritance", inheritance }, { "shared_files", shared_files },
		{ "migration", migration }, { "sibling_rescue", sibling_rescue },
		{ "limit_race", limit_race },
		{ "revoke", revoke_pool },
		{ "scm_rights", scm_rights }, { "revoke_race", revoke_race },
		{ "batch_exit", batch_exit },
	};
	struct { const char *name; int (*fn)(void); } managed[] = {
		{ "abi", abi }, { "faults", faults }, { "admin_disable", admin_disable },
	};
	unsigned int k;
	int failures = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 2 && !strcmp(argv[1], "--native")) enabled = 0;
	if (!getenv("CKM_ISOLATED_GUEST") || access("/files/files.usage", R_OK)) return 4;
	for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
		pid_t p = fork();
		int fail;

		if (!p) {
			alarm(10);
			_exit(cases[k].fn());
		}
		fail = wait_ok(p);
		printf("CKM_FD_TEST mode=%s case=%s result=%s\n", enabled ? "delegated" : "native",
		       cases[k].name, fail ? "FAIL" : "PASS");
		failures += fail;
	}
	if (enabled) for (k = 0; k < sizeof(managed) / sizeof(managed[0]); k++) {
		pid_t p = fork();
		int fail;

		if (!p) { alarm(15); _exit(managed[k].fn()); }
		fail = wait_ok(p);
		printf("CKM_FD_TEST mode=delegated case=%s result=%s\n", managed[k].name, fail ? "FAIL" : "PASS");
		failures += fail;
	}
	printf("CKM_FD_TEST_END failures=%d\n", failures);
	return !!failures;
}
