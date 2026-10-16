// SPDX-License-Identifier: GPL-2.0
/* Isolated initramfs PID 1 only. Never run this test on the host. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct args { uint32_t version; int32_t online; uint64_t mask; int32_t nid, l3; };
#define CK_INIT _IOW(0xaf, 2, struct args)
static int failures;

static int attach(uint64_t mask)
{
	struct args a = { 1, 1, mask, -1, -1 };
	int fd = open("/dev/ckernel", O_RDWR), ret, saved;
	if (fd < 0) return -1;
	ret = ioctl(fd, CK_INIT, &a); saved = errno;
	close(fd); errno = saved; return ret;
}

static long field(const char *key)
{
	FILE *f = fopen("/proc/ckernel", "r");
	char line[256], name[128]; long value;
	if (!f) return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%127s %ld", name, &value) == 2 && !strcmp(name, key)) {
			fclose(f); return value;
		}
	}
	fclose(f); return -1;
}

static int text(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ssize_t n;
	if (fd < 0) return -1;
	n = write(fd, value, strlen(value)); close(fd);
	return n == (ssize_t)strlen(value) ? 0 : -1;
}

static int zero(void)
{
	if (attach(0)) return 1;
	return field("mm_meta_domain_enabled") || field("task_security_cache_enabled") ||
		field("fast_check") || field("vfs_ref_enabled") || field("socket_lsm_fast");
}

static int unsupported(void)
{
	for (unsigned int i = 0; i < 8; i++) {
		errno = 0;
		if (attach(1ULL << i) != -1 || errno != EOPNOTSUPP) return 1;
	}
	return 0;
}

static int signal_cache(void)
{
	if (attach(1ULL << 8)) return 1;
	if (signal(SIGUSR1, SIG_IGN) == SIG_ERR) return 1;
	for (int i = 0; i < 10; i++)
		if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1)) return 1;
	printf("SIGNAL_HITS %ld\n", field("task_security_cache_hits"));
	return field("task_security_cache_enabled") != 1 ||
		field("task_security_cache_hits") <= 0 || field("fast_check") != 0;
}

static int maple(void)
{
	cpu_set_t set;
	long page = sysconf(_SC_PAGESIZE);
	if (attach(1ULL << 9)) return 1;
	for (int r = 0; r < 16; r++) {
		CPU_ZERO(&set); CPU_SET(r % 2, &set);
		if (sched_setaffinity(0, sizeof(set), &set)) return 1;
		char *p = mmap(NULL, page * 128, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) return 1;
		for (int i = 0; i < 128; i += 2)
			if (mprotect(p + i * page, page, PROT_READ | PROT_WRITE)) return 1;
		if (munmap(p, page * 128)) return 1;
	}
	printf("MAPLE_HITS %ld RETURNS %ld\n", field("mm_meta_hits"), field("mm_meta_returns"));
	return field("mm_meta_domain_enabled") != 1 || field("mm_meta_hits") <= 0 ||
		field("task_security_cache_enabled") != 0;
}

static int overmount(void)
{
	struct stat value;
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) return 1;
	if (mkdir("/work", 0700) || mount("tmpfs", "/work", "tmpfs", 0, NULL)) return 1;
	if (text("/work/value", "old") || attach(0)) return 1;
	for (int i = 0; i < 10; i++)
		if (stat("/work/value", &value) || value.st_size != 3) return 1;
	if (mount("tmpfs", "/work", "tmpfs", 0, NULL) || text("/work/value", "replacement-long")) return 1;
	return stat("/work/value", &value) || value.st_size != 16;
}

static int quota(int ck)
{
	char parent[128], leaf[160], path[192], pid[32];
	int fds[64], n = 0, error;
	snprintf(parent, sizeof(parent), "/cg/%s", ck ? "ck" : "native");
	snprintf(leaf, sizeof(leaf), "%s/leaf", parent);
	if (mkdir(parent, 0700) || mkdir(leaf, 0700)) return 1;
	snprintf(path, sizeof(path), "%s/files.limit", parent);
	if (text(path, "16")) return 1;
	snprintf(path, sizeof(path), "%s/cgroup.procs", leaf);
	snprintf(pid, sizeof(pid), "%d", getpid());
	if (text(path, pid) || (ck && attach(0))) return 1;
	while (n < 64) {
		fds[n] = open("/dev/null", O_RDONLY);
		if (fds[n] < 0) break;
		n++;
	}
	error = errno;
	printf("QUOTA ck=%d opens=%d errno=%d\n", ck, n, error);
	for (int i = 0; i < n; i++) close(fds[i]);
	return n >= 16 || n == 0 || error != EMFILE;
}
static int quota_native(void) { return quota(0); }
static int quota_ck(void) { return quota(1); }

static void test(const char *name, int (*fn)(void))
{
	int status;
	pid_t child = fork();
	if (!child) _exit(fn() ? 1 : 0);
	if (child < 0 || waitpid(child, &status, 0) != child) {
		failures++; printf("CASE %s FAIL fork/wait\n", name); return;
	}
	if (status) failures++;
	printf("CASE %s %s status=%d\n", name, status ? "FAIL" : "PASS", status);
}

static int load(const char *params)
{
	int fd = open("/ckernel.ko", O_RDONLY), ret, saved;
	if (fd < 0) return -1;
	ret = syscall(SYS_finit_module, fd, params, 0); saved = errno;
	close(fd); errno = saved; return ret;
}

int main(void)
{
	const char *blocked[] = { "ckernel_apparmor", "ckernel_acct", "ckernel_vfs_cache",
		"ckernel_vfs_ref_cache", "ckernel_immutable_path_lease", "ckernel_socket_fast",
		"ckernel_file_socket_stock" };
	if (getpid() != 1) {
		fprintf(stderr, "isolated guest PID 1 only\n"); return 2;
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) || mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) { failures++; goto done; }
	for (unsigned int i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
		char param[96];
		snprintf(param, sizeof(param), "%s=1", blocked[i]); errno = 0;
		if (load(param) != -1 || errno != EOPNOTSUPP) {
			printf("QUARANTINE_FAIL %s errno=%d\n", param, errno); failures++; goto done;
		}
		printf("QUARANTINE_PASS %s\n", blocked[i]);
	}
	if (load("ckernel_mm_meta_domain=1 ckernel_task_security_cache=1")) {
		printf("LOAD_FAIL errno=%d\n", errno); failures++; goto done;
	}
	test("mask-zero", zero);
	test("unavailable-features", unsupported);
	test("self-signal-unmediated-only", signal_cache);
	test("maple-two-cpu-smoke", maple);
	test("native-overmount-fallback", overmount);
	if (mount("none", "/cg", "cgroup", 0, "files")) {
		printf("FILES_CONTROLLER_UNAVAILABLE errno=%d\n", errno); failures++;
	} else {
		test("native-ancestor-fd-limit", quota_native);
		test("ckernel-ancestor-fd-limit", quota_ck);
	}
	if (syscall(SYS_delete_module, "ckernel", O_NONBLOCK)) {
		printf("UNLOAD_FAIL errno=%d\n", errno); failures++;
	} else printf("UNLOAD_PASS\n");
done:
	printf("DELIVERY_GUEST_END failures=%d\n", failures);
	sync(); reboot(RB_POWER_OFF);
	for (;;) pause();
}
