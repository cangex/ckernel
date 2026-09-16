// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/ckernel_m.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d %s errno=%d\n", \
	__func__, __LINE__, #x, errno); return 1; } } while (0)
static int enabled = 1;

static int create(void)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_NET };
	int fd, saved, ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);

	if (ctl < 0) return -1;
	fd = ioctl(ctl, CKM_IOC_CREATE, &r);
	saved = errno;
	close(ctl);
	errno = saved;
	return fd;
}

static int enroll(void)
{
	int fd = create();

	if (fd < 0 || ioctl(fd, CKM_IOC_BIND, 0)) return -1;
	return fd;
}

static int query(int fd, struct ckm_net_query *q)
{
	memset(q, 0, sizeof(*q));
	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	return ioctl(fd, CKM_IOC_NET_QUERY, q);
}

static int drained(int fd)
{
	struct ckm_net_query q;
	int n;

	for (n = 0; n < 1000; n++) {
		CHECK(!query(fd, &q));
		CHECK(q.live + q.retiring <= q.capacity);
		if (!q.live && !q.retiring) break;
		usleep(10000);
	}
	CHECK(n < 1000 && q.created + q.cloned == q.released);
	return 0;
}

static int wait_ok(pid_t p)
{
	int status;

	return p < 0 || waitpid(p, &status, 0) != p || !WIFEXITED(status) || WEXITSTATUS(status);
}

static int profile(const char *name)
{
	char command[120];
	int fd, n, error;

	if (!name) return 0;
	fd = open("/proc/self/attr/current", O_WRONLY);
	CHECK(fd >= 0);
	n = snprintf(command, sizeof(command), "changeprofile %s", name);
	error = write(fd, command, n) != n;
	return close(fd) || error;
}

static int endpoint(int type, struct sockaddr_in *addr)
{
	socklen_t size = sizeof(*addr);
	int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd < 0 || bind(fd, (struct sockaddr *)addr, size) ||
	    getsockname(fd, (struct sockaddr *)addr, &size)) return -1;
	return fd;
}

static int pair(int type, int *a, int *b)
{
	struct sockaddr_in left, right;
	int listener;

	if (type == SOCK_DGRAM) {
		*a = endpoint(type, &left);
		*b = endpoint(type, &right);
		CHECK(*a >= 0 && *b >= 0);
		CHECK(!connect(*a, (struct sockaddr *)&right, sizeof(right)));
		CHECK(!connect(*b, (struct sockaddr *)&left, sizeof(left)));
	} else {
		listener = endpoint(type, &left);
		CHECK(listener >= 0 && !listen(listener, 4));
		*a = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		CHECK(*a >= 0 && !connect(*a, (struct sockaddr *)&left, sizeof(left)));
		*b = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
		CHECK(*b >= 0 && !close(listener));
	}
	return 0;
}

static int permissions(int type, const char *name, int deny, int characterize)
{
	int a, b, sr, se, rr, re;
	int inst = enabled ? enroll() : -1;
	struct ckm_net_query before, after;
	char data = 0;
	struct pollfd ready;

	CHECK(!enabled || inst >= 0);
	CHECK(!pair(type, &a, &b));
	CHECK(send(a, "Q", 1, MSG_NOSIGNAL) == 1);
	ready = (struct pollfd){ .fd = b, .events = POLLIN };
	CHECK(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN));
	CHECK(!profile(name));
	if (enabled) CHECK(!query(inst, &before));
	errno = 0;
	sr = send(a, "S", 1, MSG_NOSIGNAL);
	se = errno;
	errno = 0;
	rr = recv(b, &data, 1, MSG_DONTWAIT);
	re = errno;
	if (characterize) {
		CHECK(sr == 1 || (sr == -1 && (se == EACCES || se == EPERM)));
		CHECK(rr == 1 || (rr == -1 && (re == EACCES || re == EPERM)));
		printf("CKM_NET_CHARACTERIZE transport=%s profile=%s send=%d send_errno=%d recv=%d recv_errno=%d\n",
		       type == SOCK_DGRAM ? "udp" : "tcp", name, sr, se, rr, re);
	} else if (deny) {
		CHECK(sr == -1 && (se == EACCES || se == EPERM));
		CHECK(rr == -1 && (re == EACCES || re == EPERM));
	} else {
		CHECK(sr == 1 && rr == 1 && data == 'Q');
	}
	CHECK(!close(a) && !close(b));
	if (enabled) {
		CHECK(!query(inst, &after));
		if (!name) CHECK(after.send_hits > before.send_hits && after.recv_hits > before.recv_hits);
		else CHECK(after.send_hits == before.send_hits && after.recv_hits == before.recv_hits);
		CHECK(!drained(inst) && !close(inst));
	}
	return 0;
}

static int exchange(int a, int b)
{
	char c;

	CHECK(send(a, "Z", 1, MSG_NOSIGNAL) == 1);
	CHECK(recv(b, &c, 1, 0) == 1 && c == 'Z');
	return 0;
}

static int created_confined(void)
{
	struct ckm_net_query q;
	int fd = enroll(), a, b, k;

	CHECK(fd >= 0 && !profile("ckm_net_allow") && !pair(SOCK_DGRAM, &a, &b));
	for (k = 0; k < 32; k++) CHECK(!exchange(a, b));
	CHECK(!query(fd, &q) && q.created == 2 && q.mediated >= 64);
	CHECK(!q.send_hits && !q.recv_hits);
	CHECK(!close(a) && !close(b) && !drained(fd) && !close(fd));
	return 0;
}

static int legacy_qualification(void)
{
	struct ckm_net_query q;
	int fd = enroll(), a, b, k;

	CHECK(fd >= 0 && !profile("ckm_net_legacy") && !pair(SOCK_DGRAM, &a, &b));
	for (k = 0; k < 32; k++) CHECK(!exchange(a, b));
	CHECK(!query(fd, &q) && q.send_hits >= 32 && q.recv_hits >= 32);
	CHECK(!close(a) && !close(b) && !drained(fd) && !close(fd));
	return 0;
}

static int overflow(void)
{
	struct ckm_net_query q;
	int fd = enroll(), sockets[96], k;

	CHECK(fd >= 0);
	for (k = 0; k < 96; k++) CHECK((sockets[k] = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);
	CHECK(!query(fd, &q) && q.live == 64 && q.full == 32 && q.created == 64);
	for (k = 0; k < 96; k++) CHECK(!close(sockets[k]));
	CHECK(!drained(fd));
	for (k = 0; k < 200; k++) {
		int a, b;
		CHECK(!pair(SOCK_DGRAM, &a, &b) && !exchange(a, b) && !close(a) && !close(b));
		if (!(k % 16)) CHECK(!drained(fd));
	}
	CHECK(!drained(fd) && !close(fd));
	return 0;
}

static int credential_change(void)
{
	struct ckm_net_query a, b;
	int fd = enroll(), x, y;

	CHECK(fd >= 0 && !pair(SOCK_DGRAM, &x, &y) && !exchange(x, y) && !query(fd, &a));
	CHECK(setfsuid(65534) == 0 && setfsuid((uid_t)-1) == 65534);
	CHECK(!exchange(x, y));
	CHECK(setfsuid(0) == 65534 && !query(fd, &b));
	CHECK(a.send_hits == b.send_hits && a.recv_hits == b.recv_hits && b.subject >= a.subject + 2);
	CHECK(!close(x) && !close(y) && !drained(fd) && !close(fd));
	return 0;
}

static int exec_child(int fd, int x, int y)
{
	struct ckm_net_query a, b;

	CHECK(!query(fd, &a) && !exchange(x, y) && !query(fd, &b));
	CHECK(b.send_hits == a.send_hits && b.recv_hits == a.recv_hits && b.subject >= a.subject + 2);
	return 0;
}

static int fork_exec(void)
{
	struct ckm_net_query a, b;
	int fd = enroll(), x, y;
	pid_t p;

	CHECK(fd >= 0 && !pair(SOCK_DGRAM, &x, &y) && !query(fd, &a));
	p = fork();
	if (!p) {
		char sf[20], sx[20], sy[20];
		struct ckm_net_query before, after;

		/* copy_creds() duplicates credentials for non-CLONE_THREAD forks. */
		CHECK(!query(fd, &before) && !exchange(x, y) && !query(fd, &after));
		CHECK(after.send_hits == before.send_hits && after.recv_hits == before.recv_hits);
		CHECK(after.subject >= before.subject + 2);
		CHECK(!fcntl(fd, F_SETFD, 0) && !fcntl(x, F_SETFD, 0) && !fcntl(y, F_SETFD, 0));
		snprintf(sf, sizeof(sf), "%d", fd); snprintf(sx, sizeof(sx), "%d", x);
		snprintf(sy, sizeof(sy), "%d", y);
		execl("/socket_identity", "socket_identity", "--exec", sf, sx, sy, NULL);
		_exit(127);
	}
	CHECK(!wait_ok(p) && !query(fd, &b));
	CHECK(b.send_hits == a.send_hits && b.recv_hits == a.recv_hits && b.subject >= a.subject + 4);
	CHECK(!close(x) && !close(y) && !drained(fd) && !close(fd));
	return 0;
}

static int fd_message(int socket, int *fd, int sending)
{
	char control[CMSG_SPACE(sizeof(int))] = {}, data = 0;
	struct iovec iov = { .iov_base = &data, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);

	if (sending) {
		c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(c), fd, sizeof(*fd));
		return sendmsg(socket, &msg, MSG_NOSIGNAL) != 1;
	}
	CHECK(recvmsg(socket, &msg, MSG_CMSG_CLOEXEC) == 1 && !(msg.msg_flags & MSG_CTRUNC));
	CHECK(c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int)));
	memcpy(fd, CMSG_DATA(c), sizeof(*fd));
	return 0;
}

static int transfer(void)
{
	int sv[2], fd, owner, a, b, k;
	pid_t p;
	struct ckm_net_query q;

	CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	p = fork();
	if (!p) {
		CHECK(!close(sv[0]));
		owner = enroll();
		CHECK(owner >= 0 && !pair(SOCK_DGRAM, &a, &b) && !exchange(a, b));
		CHECK(!fd_message(sv[1], &owner, 1) && !fd_message(sv[1], &a, 1) && !fd_message(sv[1], &b, 1));
		CHECK(!ioctl(owner, CKM_IOC_REVOKE, 0) && !close(owner) && !close(a) && !close(b));
		_exit(0);
	}
	CHECK(!close(sv[1]) && !fd_message(sv[0], &owner, 0) &&
	      !fd_message(sv[0], &a, 0) && !fd_message(sv[0], &b, 0) && !wait_ok(p));
	fd = enroll();
	CHECK(fd >= 0);
	for (k = 0; k < 32; k++) CHECK(!exchange(a, b));
	CHECK(!query(fd, &q) && !q.send_hits && !q.recv_hits && q.missing >= 64);
	CHECK(!query(owner, &q) && q.live == 2);
	CHECK(!close(a) && !close(b) && !drained(owner) && !close(owner));
	CHECK(!close(fd) && !close(sv[0]));
	return 0;
}

static int reload_policy(const char *file, int legacy)
{
	pid_t p = fork();

	if (!p) {
		if (legacy) execl("/sbin/apparmor_parser", "apparmor_parser", "-K", "-r",
			"--compile-features", "/features.nopolicydb", file, NULL);
		else execl("/sbin/apparmor_parser", "apparmor_parser", "-K", "-r", file, NULL);
		_exit(127);
	}
	return wait_ok(p);
}

struct traffic { int a, b; atomic_int stop, bad, completed; };
static void *during_reload(void *arg)
{
	struct traffic *t = arg;
	char c;

	while (!atomic_load(&t->stop)) {
		int n = send(t->a, "r", 1, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n != 1 && errno != EACCES && errno != EPERM && errno != EAGAIN)
			atomic_fetch_add(&t->bad, 1);
		n = recv(t->b, &c, 1, MSG_DONTWAIT);
		if (n != 1 && errno != EACCES && errno != EPERM && errno != EAGAIN)
			atomic_fetch_add(&t->bad, 1);
		atomic_fetch_add(&t->completed, 1);
		usleep(1000);
	}
	return NULL;
}

static int reload(void)
{
	int fd = create(), ready[2], go[2], a, b;
	pid_t p;
	char c;

	CHECK(fd >= 0 && !reload_policy("/network-reload-initial.profile", 1));
	CHECK(!pipe(ready) && !pipe(go));
	p = fork();
	if (!p) {
		struct ckm_net_query before, after;
		struct traffic t = {};
		pthread_t thread;

		CHECK(!ioctl(fd, CKM_IOC_BIND, 0) && !profile("ckm_net_reload"));
		CHECK(!pair(SOCK_DGRAM, &a, &b) && !exchange(a, b));
		CHECK(!query(fd, &before) && before.send_hits > 0 && before.recv_hits > 0);
		t.a = a; t.b = b;
		CHECK(!pthread_create(&thread, NULL, during_reload, &t));
		CHECK(write(ready[1], "x", 1) == 1 && read(go[0], &c, 1) == 1);
		atomic_store(&t.stop, 1);
		CHECK(!pthread_join(thread, NULL) && !atomic_load(&t.bad) && atomic_load(&t.completed) > 0);
		CHECK(!query(fd, &before));
		CHECK(send(a, "x", 1, MSG_NOSIGNAL) == -1 && (errno == EACCES || errno == EPERM));
		CHECK(recv(b, &c, 1, MSG_DONTWAIT) == -1 && (errno == EACCES || errno == EPERM));
		CHECK(!query(fd, &after) && after.send_hits == before.send_hits && after.recv_hits == before.recv_hits);
		CHECK(!close(a) && !close(b) && !drained(fd));
		_exit(0);
	}
	CHECK(read(ready[0], &c, 1) == 1);
	CHECK(!reload_policy("/network-replace.profile", 0));
	CHECK(write(go[1], "x", 1) == 1 && !wait_ok(p) && !close(fd));
	return 0;
}

static int revoked(void)
{
	struct ckm_net_query before, after;
	int fd = enroll(), a, b;

	CHECK(fd >= 0 && !pair(SOCK_STREAM, &a, &b) && !exchange(a, b) && !query(fd, &before));
	CHECK(before.cloned > 0 && before.send_hits > 0 && before.recv_hits > 0);
	CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0) && !exchange(a, b) && !query(fd, &after));
	CHECK(before.send_hits == after.send_hits && before.recv_hits == after.recv_hits);
	CHECK(!close(a) && !close(b) && !drained(fd) && !close(fd));
	return 0;
}

static void *churn(void *arg)
{
	atomic_int *bad = arg;
	int k;

	for (k = 0; k < 100; k++) {
		int a, b;
		if (pair(SOCK_DGRAM, &a, &b) || exchange(a, b) || close(a) || close(b)) {
			atomic_fetch_add(bad, 1); break;
		}
	}
	return NULL;
}

static int revoke_race(void)
{
	int fd = enroll(), k;
	pthread_t threads[4];
	atomic_int bad = 0;

	CHECK(fd >= 0);
	for (k = 0; k < 4; k++) CHECK(!pthread_create(&threads[k], NULL, churn, &bad));
	usleep(1000);
	CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0));
	for (k = 0; k < 4; k++) CHECK(!pthread_join(threads[k], NULL));
	CHECK(!atomic_load(&bad) && !drained(fd) && !close(fd));
	return 0;
}

static int batch_exit(void)
{
	int round, k;
	pid_t children[12];

	for (round = 0; round < 4; round++) {
		for (k = 0; k < 12; k++) {
			children[k] = fork();
			if (!children[k]) {
				int fd = enroll(), n, a, b;
				CHECK(fd >= 0);
				for (n = 0; n < 16; n++) CHECK(!pair(SOCK_DGRAM, &a, &b) && !exchange(a, b));
				_exit(0); /* Live sockets and their holder exit together. */
			}
		}
		for (k = 0; k < 12; k++) CHECK(!wait_ok(children[k]));
		usleep(100000);
	}
	return 0;
}

static int abi(void)
{
	struct ckm_net_query q;
	struct ckm_create req = { .version = CKM_ABI_VERSION, .size = sizeof(req),
		.features = CKM_FEATURE_NET, .reserved = { 1 } };
	int fd = create(), ctl;
	pid_t p;

	CHECK(fd >= 0 && !query(fd, &q) && q.capacity == 64 && q.management_bytes > 0);
	q.reserved[0] = 1;
	CHECK(ioctl(fd, CKM_IOC_NET_QUERY, &q) == -1 && errno == EINVAL);
	ctl = open("/dev/ckernel-m", O_RDWR);
	CHECK(ctl >= 0 && ioctl(ctl, CKM_IOC_CREATE, &req) == -1 && errno == EINVAL && !close(ctl));
	p = fork();
	if (!p) { CHECK(!setuid(65534)); CHECK(ioctl(fd, CKM_IOC_REVOKE, 0) == -1 && errno == EPERM); _exit(0); }
	CHECK(!wait_ok(p) && !close(fd));
	return 0;
}

static int faults(void)
{
	int nth, fd, k, rejected = 0, completed = 0;
	char value[32];
	const char *knobs[] = { "/sys/kernel/debug/failslab/ignore-gfp-wait",
		"/sys/kernel/debug/failslab/verbose" };

	nth = open("/proc/self/fail-nth", O_RDWR | O_CLOEXEC);
	CHECK(nth >= 0);
	for (k = 0; k < 2; k++) {
		fd = open(knobs[k], O_WRONLY);
		CHECK(fd >= 0 && write(fd, "0", 1) == 1 && !close(fd));
	}
	for (k = 1; k <= 64; k++) {
		int len = snprintf(value, sizeof(value), "%d", k);
		CHECK(pwrite(nth, value, len, 0) == len);
		fd = create();
		CHECK(pwrite(nth, "0", 1, 0) == 1);
		if (fd < 0) rejected++;
		else { completed++; CHECK(!close(fd)); }
		fd = create();
		CHECK(fd >= 0 && !close(fd));
		usleep(1000);
	}
	printf("CKM_NET_FAULT probes=64 rejected=%d completed=%d recovery=64\n", rejected, completed);
	CHECK(rejected > 0 && completed > 0 && !close(nth));
	return 0;
}

static int migrate(void)
{
	struct ckm_net_query before, after;
	cpu_set_t cpus;
	int fd = enroll(), a, b, k, control;
	char path[160];

	CHECK(fd >= 0 && !pair(SOCK_DGRAM, &a, &b));
	for (k = 0; k < 32; k++) {
		CPU_ZERO(&cpus); CPU_SET(k % 4, &cpus);
		CHECK(!sched_setaffinity(0, sizeof(cpus), &cpus) && !exchange(a, b));
	}
	CHECK(!query(fd, &before) && before.send_hits == 32 && before.recv_hits == 32);
	snprintf(path, sizeof(path), "/sys/fs/cgroup/ckm-net/migrate-%d", getpid());
	CHECK(!mkdir(path, 0755));
	snprintf(path, sizeof(path), "/sys/fs/cgroup/ckm-net/migrate-%d/cgroup.procs", getpid());
	control = open(path, O_WRONLY);
	CHECK(control >= 0 && write(control, "0", 1) == 1 && !close(control));
	CHECK(!exchange(a, b) && !query(fd, &after));
	CHECK(after.send_hits == before.send_hits && after.recv_hits == before.recv_hits);
	control = open("/sys/fs/cgroup/ckm-net/cgroup.procs", O_WRONLY);
	CHECK(control >= 0 && write(control, "0", 1) == 1 && !close(control));
	CHECK(!exchange(a, b) && !query(fd, &after));
	CHECK(after.send_hits == before.send_hits + 1 && after.recv_hits == before.recv_hits + 1);
	CHECK(!close(a) && !close(b) && !drained(fd) && !close(fd));
	return 0;
}

static int stack_deny(void)
{
	struct ckm_net_query before, after;
	int fd = enroll(), a, b, attr;
	const char command[] = "stack ckm_net_deny";
	char c;

	CHECK(fd >= 0 && !profile("ckm_net_legacy") && !pair(SOCK_DGRAM, &a, &b));
	CHECK(!exchange(a, b) && !query(fd, &before));
	attr = open("/proc/self/attr/current", O_WRONLY);
	CHECK(attr >= 0 && write(attr, command, sizeof(command) - 1) == sizeof(command) - 1 && !close(attr));
	CHECK(send(a, "x", 1, MSG_NOSIGNAL) == -1 && (errno == EACCES || errno == EPERM));
	CHECK(recv(b, &c, 1, MSG_DONTWAIT) == -1 && (errno == EACCES || errno == EPERM));
	CHECK(!query(fd, &after) && after.send_hits == before.send_hits && after.recv_hits == before.recv_hits);
	CHECK(!close(a) && !close(b) && !drained(fd) && !close(fd));
	return 0;
}

static int netns_change(void)
{
	struct ckm_net_query before, after;
	int fd = enroll(), a, b, ns;

	CHECK(fd >= 0 && !pair(SOCK_DGRAM, &a, &b) && !exchange(a, b));
	ns = open("/proc/self/ns/net", O_RDONLY);
	CHECK(ns >= 0 && !query(fd, &before) && !unshare(CLONE_NEWNET));
	CHECK(!exchange(a, b) && !query(fd, &after));
	CHECK(after.send_hits == before.send_hits && after.recv_hits == before.recv_hits);
	CHECK(after.subject >= before.subject + 2 && !setns(ns, CLONE_NEWNET) && !close(ns));
	CHECK(!exchange(a, b) && !query(fd, &after));
	CHECK(after.send_hits == before.send_hits + 1 && after.recv_hits == before.recv_hits + 1);
	CHECK(!close(a) && !close(b) && !drained(fd) && !close(fd));
	return 0;
}

static int abandoned_owner(void)
{
	int sv[2], fd, a, b, k;
	pid_t p;

	CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	p = fork();
	if (!p) {
		CHECK(!close(sv[0]));
		fd = enroll();
		CHECK(fd >= 0 && !pair(SOCK_DGRAM, &a, &b));
		CHECK(!fd_message(sv[1], &a, 1) && !fd_message(sv[1], &b, 1));
		CHECK(!close(a) && !close(b) && !close(fd));
		_exit(0);
	}
	CHECK(!close(sv[1]) && !fd_message(sv[0], &a, 0) && !fd_message(sv[0], &b, 0) && !wait_ok(p));
	for (k = 0; k < 128; k++) {
		fd = create();
		CHECK(fd >= 0 && !close(fd) && !exchange(a, b));
		usleep(1000);
	}
	CHECK(!close(a) && !close(b) && !close(sv[0]));
	return 0;
}

int main(int argc, char **argv)
{
	const char *names[] = { NULL, "ckm_net_allow", "ckm_net_deny", "ckm_net_audit", "ckm_net_legacy" };
	int type, n, failures = 0;
	struct { const char *name; int (*run)(void); } cases[] = {
		{ "created_confined", created_confined }, { "legacy_qualification", legacy_qualification },
		{ "overflow_reuse", overflow }, { "credential_change", credential_change },
		{ "fork_exec", fork_exec }, { "scm_rights", transfer }, { "reload", reload },
		{ "tcp_revoke", revoked }, { "revoke_race", revoke_race },
		{ "batch_exit", batch_exit }, { "abi", abi },
		{ "faults", faults }, { "cpu_cgroup_migration", migrate },
		{ "stack_deny", stack_deny }, { "abandoned_owner", abandoned_owner },
		{ "netns_change", netns_change },
	};
	struct ifreq lo = { .ifr_name = "lo" };
	int ctl;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!getenv("CKM_ISOLATED_GUEST")) return 4;
	if (argc == 5 && !strcmp(argv[1], "--exec"))
		return exec_child(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
	if (argc == 2 && !strcmp(argv[1], "--native")) enabled = 0;
	ctl = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(ctl >= 0 && !ioctl(ctl, SIOCGIFFLAGS, &lo));
	lo.ifr_flags |= IFF_UP;
	CHECK(!ioctl(ctl, SIOCSIFFLAGS, &lo) && !close(ctl));
	for (type = SOCK_STREAM; type <= SOCK_DGRAM; type++)
	for (n = 0; n < 5; n++) {
		pid_t p = fork();
		int status = 0, failed;

		if (!p) { alarm(30); _exit(permissions(type, names[n], n == 2, n == 4)); }
		failed = p < 0 || waitpid(p, &status, 0) != p || !WIFEXITED(status) || WEXITSTATUS(status);
		printf("CKM_NET_PERMISSION transport=%s case=%s kind=%s result=%s\n",
		       type == SOCK_DGRAM ? "udp" : "tcp", names[n] ? names[n] : "unconfined",
		       n == 4 ? "characterization" : "assertion", failed ? "FAIL" : "PASS");
		failures += failed;
	}
	if (enabled) for (n = 0; n < (int)(sizeof(cases) / sizeof(cases[0])); n++) {
		pid_t p = fork();
		int failed;

		if (!p) { alarm(45); _exit(cases[n].run()); }
		failed = wait_ok(p);
		printf("CKM_NET_CASE name=%s result=%s\n", cases[n].name, failed ? "FAIL" : "PASS");
		failures += failed;
	}
	printf("CKM_NET_END mode=%s permission_assertions=8 characterizations=2 lifecycle_cases=%zu failures=%d\n",
		enabled ? "owned" : "native", enabled ? sizeof(cases) / sizeof(cases[0]) : 0, failures);
	return !!failures;
}
