// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/ckernel_m.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d %s errno=%d\n", \
	__func__, __LINE__, #x, errno); return 1; } } while (0)

static int create(unsigned int feature)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = feature };
	int ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC), fd;

	if (ctl < 0)
		return -1;
	fd = ioctl(ctl, CKM_IOC_CREATE, &r);
	close(ctl);
	return fd;
}

static int query(int fd, struct ckm_security_query *q)
{
	memset(q, 0, sizeof(*q));
	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	return ioctl(fd, CKM_IOC_SECURITY_QUERY, q);
}

static int profile(const char *name, int stack)
{
	char command[128];
	int fd = open("/proc/self/attr/current", O_WRONLY), n, ret;

	if (fd < 0)
		return -1;
	n = snprintf(command, sizeof(command), "%s %s", stack ? "stack" : "changeprofile", name);
	ret = write(fd, command, n) == n ? 0 : -1;
	close(fd);
	return ret;
}

static int self_signal(void)
{
	return syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
}

static int wait_ok(pid_t pid)
{
	int status;

	return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		!WEXITSTATUS(status) ? 0 : -1;
}

static int signals(const char *name, int expected_deny, int expect_hits, unsigned int features)
{
	struct ckm_security_query a, b;
	int fd = features ? create(features) : -1, k;
	int iterations = expected_deny || (name && !strcmp(name, "ckm_s_audit")) ? 4 : 200;
	pid_t p;

	CHECK(!features || fd >= 0);
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		if (features) CHECK(!ioctl(fd, CKM_IOC_BIND, 0));
		CHECK(!name || !profile(name, 0));
		signal(SIGUSR1, SIG_IGN);
		memset(&a, 0, sizeof(a));
		if (features) CHECK(!query(fd, &a));
		for (k = 0; k < iterations; k++) {
			int ret = self_signal();

			CHECK(expected_deny ? ret == -1 && (errno == EACCES || errno == EPERM) : ret == 0);
		}
		if (features) {
			CHECK(!query(fd, &b));
			CHECK(expect_hits ? b.signal_hits >= a.signal_hits + iterations : b.signal_hits == a.signal_hits);
		}
		_exit(0);
	}
	CHECK(!wait_ok(p));
	if (fd >= 0) CHECK(!close(fd));
	return 0;
}

static int stack_deny(void)
{
	struct ckm_security_query a, b;
	int fd = create(CKM_FEATURE_SECURITY);

	CHECK(fd >= 0 && !ioctl(fd, CKM_IOC_BIND, 0));
	signal(SIGUSR1, SIG_IGN);
	CHECK(!profile("ckm_s_unmediated", 0) && !self_signal());
	CHECK(!profile("ckm_s_deny", 1));
	CHECK(!query(fd, &a));
	CHECK(self_signal() == -1 && (errno == EACCES || errno == EPERM));
	CHECK(!query(fd, &b) && b.signal_hits == a.signal_hits);
	CHECK(!close(fd));
	return 0;
}

static int load_replacement(const char *path)
{
	pid_t p = fork();

	if (!p) {
		if (!strcmp(path, "/security-reload-initial.profile"))
			execl("/sbin/apparmor_parser", "apparmor_parser", "-K", "-r",
			      "--compile-features", "/features.nopolicydb", path, NULL);
		else
			execl("/sbin/apparmor_parser", "apparmor_parser", "-K", "-r", path, NULL);
		_exit(127);
	}
	return p < 0 ? -1 : wait_ok(p);
}

struct reload_loop { atomic_int stop, errors, completed; };

static void *during_reload(void *arg)
{
	struct reload_loop *l = arg;

	while (!atomic_load(&l->stop)) {
		int ret = self_signal();

		if (ret && errno != EACCES && errno != EPERM)
			atomic_fetch_add(&l->errors, 1);
		atomic_fetch_add(&l->completed, 1);
		usleep(100);
	}
	return NULL;
}

static int reload(int stacked)
{
	struct ckm_security_query a, b;
	int fd = create(CKM_FEATURE_SECURITY), ready[2], go[2], k;
	char byte;
	pid_t p;

	CHECK(!load_replacement("/security-reload-initial.profile"));
	CHECK(fd >= 0 && !pipe(ready) && !pipe(go));
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		struct reload_loop loop = {};
		pthread_t worker;

		close(ready[0]); close(go[1]);
		CHECK(!ioctl(fd, CKM_IOC_BIND, 0));
		if (stacked) CHECK(!profile("ckm_s_unmediated", 0));
		CHECK(!profile("ckm_s_reload", stacked));
		signal(SIGUSR1, SIG_IGN);
		CHECK(!self_signal() && !query(fd, &a) && a.signal_hits > 0);
		CHECK(!pthread_create(&worker, NULL, during_reload, &loop));
		CHECK(write(ready[1], "x", 1) == 1 && read(go[0], &byte, 1) == 1);
		atomic_store(&loop.stop, 1);
		CHECK(!pthread_join(worker, NULL) && !atomic_load(&loop.errors) &&
		      atomic_load(&loop.completed) > 0);
		CHECK(!query(fd, &a));
		for (k = 0; k < 32; k++) {
			CHECK(self_signal() == -1 && (errno == EACCES || errno == EPERM));
			CHECK(open("/tmp/ckm-security-secret", O_RDONLY) == -1 && errno == EACCES);
		}
		CHECK(!query(fd, &b) && b.signal_hits == a.signal_hits);
		CHECK(b.label_hits - a.label_hits == b.label_released - a.label_released);
		_exit(0);
	}
	close(ready[1]); close(go[0]);
	CHECK(read(ready[0], &byte, 1) == 1);
	CHECK(!load_replacement("/security-replace.profile"));
	CHECK(write(go[1], "x", 1) == 1 && !wait_ok(p));
	CHECK(!close(ready[0]) && !close(go[1]) && !close(fd));
	return 0;
}

static int fd_message(int sock, int *fd, int sending)
{
	char control[CMSG_SPACE(sizeof(int))] = {}, byte = 0;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);

	if (sending) {
		c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(c), fd, sizeof(int));
		return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
	}
	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) != 1 || msg.msg_flags & MSG_CTRUNC ||
	    c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
		return -1;
	memcpy(fd, CMSG_DATA(c), sizeof(int));
	return 0;
}

static int transfer(void)
{
	int sv[2], fd, inst;
	char data;
	pid_t p;
	struct ckm_security_query q;

	CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		close(sv[0]);
		inst = create(CKM_FEATURE_SECURITY);
		CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
		CHECK(!profile("ckm_s_unmediated", 0));
		fd = open("/tmp/ckm-security-secret", O_RDONLY);
		CHECK(fd >= 0 && !query(inst, &q) && q.label_hits > 0);
		CHECK(!fd_message(sv[1], &fd, 1) && !close(fd) && !close(inst));
		_exit(0);
	}
	close(sv[1]);
	CHECK(!fd_message(sv[0], &fd, 0) && !wait_ok(p));
	inst = create(CKM_FEATURE_SECURITY);
	CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
	/* Different profile forces native file-context label merging. */
	CHECK(!profile("ckm_s_allow", 0));
	CHECK(read(fd, &data, 1) == 1 && data == 'x');
	CHECK(!close(fd) && !close(inst) && !close(sv[0]));
	return 0;
}

static int registry_churn(void)
{
	int sv[2], fd, inst, round, k, handles[8];
	char data;
	pid_t p;

	CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		close(sv[0]);
		inst = create(CKM_FEATURE_SECURITY);
		CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
		fd = open("/tmp/ckm-security-secret", O_RDONLY);
		CHECK(fd >= 0 && !fd_message(sv[1], &fd, 1));
		CHECK(!close(fd) && !close(inst));
		_exit(0);
	}
	close(sv[1]);
	CHECK(!fd_message(sv[0], &fd, 0) && !wait_ok(p));
	/* A file keeps its retired owner/token valid while other slots recycle. */
	for (round = 0; round < 64; round++) {
		for (k = 0; k < 8; k++) {
			handles[k] = create(CKM_FEATURE_SECURITY);
			CHECK(handles[k] >= 0);
		}
		for (k = 0; k < 8; k++) CHECK(!close(handles[k]));
		usleep(1000);
	}
	CHECK(read(fd, &data, 1) == 1 && data == 'x');
	CHECK(!close(fd) && !close(sv[0]));
	return 0;
}

static int files(void)
{
	struct ckm_security_query q;
	int inst = create(CKM_FEATURE_SECURITY), k, fd, inherited;
	char data;
	pid_t p;

	CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
	CHECK(!unlink("/tmp/ckm-security-writable") || errno == ENOENT);
	for (k = 0; k < 200; k++) {
		fd = open("/tmp/ckm-security-secret", O_RDONLY);
		CHECK(fd >= 0 && read(fd, &data, 1) == 1 && data == 'x' && !close(fd));
	}
	CHECK(!query(inst, &q) && q.label_hits >= 200 && q.open_borrowed >= 200);
	CHECK(q.label_hits == q.label_released);
	for (k = 0; k < 20; k++) {
		fd = open("/tmp/ckm-security-writable", O_CREAT | O_WRONLY | O_APPEND, 0644);
		CHECK(fd >= 0 && write(fd, "a", 1) == 1 && !close(fd));
	}
	fd = open("/tmp/ckm-security-writable", O_PATH);
	CHECK(fd >= 0);
	{
		struct stat st;

		CHECK(!fstat(fd, &st) && st.st_size == 20 && !close(fd));
	}
	inherited = open("/tmp/ckm-security-secret", O_RDONLY);
	CHECK(inherited >= 0);
	p = fork();
	CHECK(p >= 0);
	if (!p) {
		CHECK(!setuid(65534));
		CHECK(read(inherited, &data, 1) == 1 && data == 'x');
		_exit(close(inherited) != 0);
	}
	CHECK(!wait_ok(p));
	CHECK(!ioctl(inst, CKM_IOC_REVOKE, 0));
	CHECK(!close(inherited) && !query(inst, &q));
	CHECK(q.label_hits == q.label_released);
	fd = open("/tmp/ckm-security-secret", O_RDONLY);
	CHECK(fd >= 0 && !close(fd) && !close(inst));
	return 0;
}

static int faults(void)
{
	int nth = open("/proc/self/fail-nth", O_RDWR | O_CLOEXEC);
	int k, failed = 0, completed = 0;
	char number[32];
	const char *knobs[] = { "/sys/kernel/debug/failslab/ignore-gfp-wait",
		"/sys/kernel/debug/failslab/verbose" };

	CHECK(nth >= 0);
	for (k = 0; k < 2; k++) {
		int fd = open(knobs[k], O_WRONLY);

		CHECK(fd >= 0 && write(fd, "0", 1) == 1 && !close(fd));
	}
	for (k = 1; k <= 64; k++) {
		int fd, size = snprintf(number, sizeof(number), "%d", k);

		CHECK(pwrite(nth, number, size, 0) == size);
		fd = create(CKM_FEATURE_SECURITY);
		CHECK(pwrite(nth, "0", 1, 0) == 1);
		if (fd < 0) failed++;
		else { completed++; CHECK(!close(fd)); }
		fd = create(CKM_FEATURE_SECURITY);
		CHECK(fd >= 0 && !close(fd));
	}
	printf("CKM_SECURITY_FAULT probes=64 rejected=%d completed=%d recovery=64\n", failed, completed);
	CHECK(failed > 0 && completed > 0 && !close(nth));
	return 0;
}

static void *file_loop(void *arg)
{
	struct reload_loop *l = arg;

	while (!atomic_load(&l->stop)) {
		int fd = open("/tmp/ckm-security-secret", O_RDONLY);
		char data;

		if (fd < 0 || read(fd, &data, 1) != 1 || data != 'x' || self_signal())
			atomic_fetch_add(&l->errors, 1);
		if (fd >= 0 && close(fd)) atomic_fetch_add(&l->errors, 1);
		atomic_fetch_add(&l->completed, 1);
	}
	return NULL;
}

static int revoke_race(void)
{
	struct reload_loop l = {};
	struct ckm_security_query q;
	pthread_t thread;
	int inst = create(CKM_FEATURE_SECURITY), fd;

	CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
	signal(SIGUSR1, SIG_IGN);
	fd = open("/tmp/ckm-security-secret", O_RDONLY);
	CHECK(fd >= 0 && !close(fd));
	CHECK(!pthread_create(&thread, NULL, file_loop, &l));
	usleep(20000);
	CHECK(!ioctl(inst, CKM_IOC_REVOKE, 0));
	usleep(20000);
	atomic_store(&l.stop, 1);
	CHECK(!pthread_join(thread, NULL) && !atomic_load(&l.errors) && atomic_load(&l.completed) > 0);
	CHECK(!query(inst, &q) && q.label_hits > 0 && q.label_hits == q.label_released);
	CHECK(!close(inst));
	return 0;
}

static int capacity(void)
{
	int inst = create(CKM_FEATURE_SECURITY), n;
	struct ckm_security_query q;

	CHECK(inst >= 0);
	for (n = 0; n < 12; n++) {
		pid_t p = fork();

		CHECK(p >= 0);
		if (!p) {
			char name[32];
			int fd;

			snprintf(name, sizeof(name), "ckm_s_slot%d", n);
			CHECK(!ioctl(inst, CKM_IOC_BIND, 0) && !profile(name, 0));
			signal(SIGUSR1, SIG_IGN);
			CHECK(!self_signal());
			fd = open("/tmp/ckm-security-secret", O_RDONLY);
			CHECK(fd >= 0 && !close(fd));
			_exit(0);
		}
		CHECK(!wait_ok(p));
	}
	CHECK(!query(inst, &q) && q.full > 0 && q.signal_hits > 0 && q.signal_native > 0);
	CHECK(q.label_hits == q.label_released && !close(inst));
	return 0;
}

static int after_exec(int inst)
{
	struct ckm_security_query a, b;

	signal(SIGUSR1, SIG_IGN);
	CHECK(!query(inst, &a) && !self_signal() && !query(inst, &b));
	CHECK(b.signal_hits > a.signal_hits);
	CHECK(!profile("ckm_s_deny", 0));
	CHECK(self_signal() == -1 && (errno == EACCES || errno == EPERM));
	CHECK(!query(inst, &a) && a.signal_hits == b.signal_hits);
	return close(inst) != 0;
}

static int exec_case(void)
{
	int inst = create(CKM_FEATURE_SECURITY);
	char fd[32];

	CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
	signal(SIGUSR1, SIG_IGN);
	CHECK(!self_signal() && !fcntl(inst, F_SETFD, 0));
	snprintf(fd, sizeof(fd), "%d", inst);
	execl("/proc/self/exe", "security_cache", "--after-exec", fd, NULL);
	return 1;
}

static int migration(void)
{
	cpu_set_t available, onecpu;
	struct ckm_security_query q;
	int cpu, count = 0, inst = create(CKM_FEATURE_SECURITY), k, fd;

	CHECK(inst >= 0 && !ioctl(inst, CKM_IOC_BIND, 0));
	CHECK(!sched_getaffinity(0, sizeof(available), &available));
	signal(SIGUSR1, SIG_IGN);
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &available)) continue;
		CPU_ZERO(&onecpu); CPU_SET(cpu, &onecpu);
		CHECK(!sched_setaffinity(0, sizeof(onecpu), &onecpu));
		for (k = 0; k < 100; k++) {
			CHECK(!self_signal());
			fd = open("/tmp/ckm-security-secret", O_RDONLY);
			CHECK(fd >= 0 && !close(fd));
		}
		count++;
	}
	CHECK(count > 1 && !query(inst, &q) && q.signal_hits >= (unsigned int)count * 100);
	CHECK(q.label_hits == q.label_released && !close(inst));
	return 0;
}

static int put(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY), ret;

	if (fd < 0) return -1;
	ret = write(fd, value, strlen(value)) == (ssize_t)strlen(value) ? 0 : -1;
	close(fd);
	return ret;
}

static unsigned long long memory(void)
{
	FILE *f = fopen("/sys/fs/cgroup/ckm-security/memory.current", "r");
	unsigned long long n = ~0ULL;

	if (f) { if (fscanf(f, "%llu", &n) != 1) n = ~0ULL; fclose(f); }
	return n;
}

static int pressure(void)
{
	char bytes[16] = {}, *load;
	pid_t children[16];
	unsigned long long initial, peak = 0, final;
	int round, k, barrier[2];

	CHECK(!put("/sys/fs/cgroup/cgroup.subtree_control", "+memory"));
	CHECK(!mkdir("/sys/fs/cgroup/ckm-security", 0755));
	CHECK(!put("/sys/fs/cgroup/ckm-security/memory.max", "50331648"));
	CHECK(!put("/sys/fs/cgroup/ckm-security/cgroup.procs", "0"));
	initial = memory();
	load = mmap(NULL, 24 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(load != MAP_FAILED);
	memset(load, 1, 24 << 20);
	for (round = 0; round < 4; round++) {
		CHECK(!pipe2(barrier, O_CLOEXEC));
		for (k = 0; k < 16; k++) {
			children[k] = fork();
			CHECK(children[k] >= 0);
			if (!children[k]) {
				char byte;

				close(barrier[1]);
				CHECK(read(barrier[0], &byte, 1) == 1 && !close(barrier[0]));
				_exit(revoke_race());
			}
		}
		CHECK(!close(barrier[0]) && write(barrier[1], bytes, sizeof(bytes)) == sizeof(bytes));
		CHECK(!close(barrier[1]));
		CHECK(!put("/sys/fs/cgroup/ckm-security/memory.reclaim", "8388608") || errno == EAGAIN);
		for (k = 0; k < 16; k++) CHECK(!wait_ok(children[k]));
		final = memory();
		if (final > peak) peak = final;
	}
	CHECK(!munmap(load, 24 << 20));
	usleep(500000);
	final = memory();
	printf("CKM_SECURITY_MEMORY initial=%llu peak_observed=%llu post500ms=%llu limit=50331648\n",
	       initial, peak, final);
	CHECK(initial != ~0ULL && peak <= 50331648 && final != ~0ULL);
	CHECK(!put("/sys/fs/cgroup/cgroup.procs", "0"));
	CHECK(!rmdir("/sys/fs/cgroup/ckm-security"));
	return 0;
}

static int one(const char *name)
{
	if (!strcmp(name, "files")) return files();
	if (!strcmp(name, "exec")) return exec_case();
	if (!strcmp(name, "migration")) return migration();
	if (!strcmp(name, "pressure")) return pressure();
	if (!strcmp(name, "transfer")) return transfer();
	if (!strcmp(name, "registry_churn")) return registry_churn();
	if (!strcmp(name, "reload")) return reload(0);
	if (!strcmp(name, "stacked_reload")) return reload(1);
	if (!strcmp(name, "stack")) return stack_deny();
	if (!strcmp(name, "capacity")) return capacity();
	if (!strcmp(name, "faults")) return faults();
	if (!strcmp(name, "revoke_race")) return revoke_race();
	if (!strcmp(name, "unconfined")) return signals(NULL, 0, 1, CKM_FEATURE_SECURITY);
	if (!strcmp(name, "native_deny")) return signals("ckm_s_deny", 1, 0, 0);
	if (!strcmp(name, "deny")) return signals("ckm_s_deny", 1, 0, CKM_FEATURE_SECURITY);
	if (!strcmp(name, "allow")) return signals("ckm_s_allow", 0, 0, CKM_FEATURE_SECURITY);
	if (!strcmp(name, "audit")) return signals("ckm_s_audit", 0, 0, CKM_FEATURE_SECURITY);
	if (!strcmp(name, "unmediated")) return signals("ckm_s_unmediated", 0, 1, CKM_FEATURE_SECURITY);
	if (!strcmp(name, "implicit_deny")) return signals("ckm_s_implicit_deny", 1, 0, CKM_FEATURE_SECURITY);
	return 1;
}

int main(int argc, char **argv)
{
	const char *names[] = { "unconfined", "unmediated", "allow", "deny", "native_deny",
		"audit", "implicit_deny", "stack", "files", "transfer", "capacity", "faults", "revoke_race", "reload", "stacked_reload",
		"exec", "migration", "pressure", "registry_churn" };
	unsigned int n;
	int fd, failures = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!getenv("CKM_ISOLATED_GUEST")) return 4;
	if (argc == 3 && !strcmp(argv[1], "--after-exec")) return after_exec(atoi(argv[2]));
	if (argc == 2 && !strcmp(argv[1], "--native")) {
		const char *native[] = { NULL, "ckm_s_unmediated", "ckm_s_allow",
			"ckm_s_deny", "ckm_s_audit", "ckm_s_implicit_deny" };

		/* Keep a failing grandchild from executing later test cases. */
		for (n = 0; n < sizeof(native) / sizeof(native[0]); n++) {
			pid_t p = fork();
			int ret;

			CHECK(p >= 0);
			if (!p) _exit(signals(native[n], n == 3 || n == 5, 0, 0));
			ret = wait_ok(p);
			printf("CKM_SECURITY_NATIVE case=%s result=%s\n",
			       native[n] ? native[n] : "unconfined", ret ? "FAIL" : "PASS");
			failures += !!ret;
		}
		printf("CKM_SECURITY_NATIVE cases=6 failures=%d\n", failures);
		return failures != 0;
	}
	fd = open("/tmp/ckm-security-secret", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	CHECK(fd >= 0 && write(fd, "x", 1) == 1 && !close(fd));
	for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
		pid_t p = fork();
		int ret;

		CHECK(p >= 0);
		if (!p) _exit(one(names[n]));
		ret = wait_ok(p);
		printf("CKM_SECURITY case=%s result=%s\n", names[n], ret ? "FAIL" : "PASS");
		failures += !!ret;
	}
	return failures != 0;
}
