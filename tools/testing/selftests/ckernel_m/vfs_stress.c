// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/ckernel_m.h"

#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d %s errno=%d\n", __func__, __LINE__, #x, errno); \
	return 1; } } while (0)

static int put(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC), ret;

	if (fd < 0)
		return -1;
	ret = write(fd, value, strlen(value)) == (ssize_t)strlen(value) ? 0 : -1;
	close(fd);
	return ret;
}

static int create(int ctl)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION,
		.size = sizeof(r), .features = CKM_FEATURE_VFS };

	return ioctl(ctl, CKM_IOC_CREATE, &r);
}

static int fault_case(void)
{
	int ctl, nthfd, n, failures = 0, successes = 0;
	char value[32];

	CHECK(!put("/sys/kernel/debug/failslab/ignore-gfp-wait", "0"));
	CHECK(!put("/sys/kernel/debug/failslab/verbose", "0"));
	/* Per-task nth injection only; global probability stays zero. */
	ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	nthfd = open("/proc/self/fail-nth", O_RDWR | O_CLOEXEC);
	CHECK(ctl >= 0 && nthfd >= 0);
	for (n = 1; n <= 64; n++) {
		int inst, saved;

		snprintf(value, sizeof(value), "%d", n);
		CHECK(pwrite(nthfd, value, strlen(value), 0) == (ssize_t)strlen(value));
		inst = create(ctl);
		saved = errno;
		CHECK(pwrite(nthfd, "0", 1, 0) == 1);
		if (inst >= 0) {
			successes++;
			CHECK(!close(inst));
		} else {
			CHECK(saved == ENOMEM || saved == ENFILE);
			failures++;
		}
		inst = create(ctl);
		CHECK(inst >= 0 && !close(inst));
		usleep(10000);
	}
	CHECK(failures > 0 && successes > 0);
	printf("CKM_STRESS_FAULT rejected=%d completed=%d recovery=64\n", failures, successes);
	CHECK(!close(nthfd) && !close(ctl));
	return 0;
}

static int lease_worker(const char *root, int barrier)
{
	struct ckm_vfs_root r = { .version = CKM_ABI_VERSION,
		.size = sizeof(r), .capacity = 16 };
	struct ckm_vfs_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
	struct statx st;
	int ctl, inst, k;
	char path[256], token;

	ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	CHECK(ctl >= 0);
	inst = create(ctl);
	CHECK(inst >= 0);
	r.fd = open(root, O_PATH | O_CLOEXEC);
	CHECK(r.fd >= 0 && !ioctl(inst, CKM_IOC_VFS_ROOT, &r));
	CHECK(!close(r.fd) && !close(ctl));
	CHECK(!ioctl(inst, CKM_IOC_BIND, 0));
	CHECK(read(barrier, &token, 1) == 1);
	for (k = 0; k < 4096; k++) {
		snprintf(path, sizeof(path), "%s/f%d", root, k % 16);
		CHECK(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st));
		CHECK(st.stx_size == 4096);
	}
	CHECK(!ioctl(inst, CKM_IOC_VFS_QUERY, &q) && q.hits && q.cached == 16);
	CHECK(!ioctl(inst, CKM_IOC_REVOKE, 0));
	CHECK(!close(inst));
	return 0;
}

static unsigned long long number(const char *path)
{
	FILE *f = fopen(path, "r");
	unsigned long long n = ~0ULL;

	if (f) {
		if (fscanf(f, "%llu", &n) != 1)
			n = ~0ULL;
		fclose(f);
	}
	return n;
}

static int batch_case(void)
{
	char root[] = "/tmp/ckm-stress-XXXXXX", path[256], block[4096] = {};
	pid_t children[16];
	unsigned int round;
	int fd, k, p[2], status;
	unsigned long long initial, peak = 0, final;
	char *pressure;

	CHECK(!put("/sys/fs/cgroup/cgroup.subtree_control", "+memory"));
	CHECK(!mkdir("/sys/fs/cgroup/ckm-stress", 0755));
	CHECK(!put("/sys/fs/cgroup/ckm-stress/memory.max", "50331648"));
	CHECK(!put("/sys/fs/cgroup/ckm-stress/cgroup.procs", "0"));
	CHECK(mkdtemp(root));
	CHECK(!mount("stress", root, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m"));
	for (k = 0; k < 16; k++) {
		snprintf(path, sizeof(path), "%s/f%d", root, k);
		fd = open(path, O_CREAT | O_WRONLY, 0644);
		CHECK(fd >= 0 && write(fd, block, sizeof(block)) == sizeof(block) && !close(fd));
	}
	CHECK(!mount(NULL, root, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
	initial = number("/sys/fs/cgroup/ckm-stress/memory.current");
	pressure = mmap(NULL, 24 << 20, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(pressure != MAP_FAILED);
	memset(pressure, 1, 24 << 20);
	for (round = 0; round < 4; round++) {
		CHECK(!pipe2(p, O_CLOEXEC));
		for (k = 0; k < 16; k++) {
			children[k] = fork();
			CHECK(children[k] >= 0);
			if (!children[k]) {
				close(p[1]);
				_exit(lease_worker(root, p[0]));
			}
		}
		CHECK(!close(p[0]) && write(p[1], block, 16) == 16 && !close(p[1]));
		CHECK(!put("/sys/fs/cgroup/ckm-stress/memory.reclaim", "8388608" ) || errno == EAGAIN);
		for (k = 0; k < 16; k++)
			CHECK(waitpid(children[k], &status, 0) == children[k] &&
			      WIFEXITED(status) && !WEXITSTATUS(status));
		final = number("/sys/fs/cgroup/ckm-stress/memory.current");
		if (final > peak)
			peak = final;
	}
	CHECK(!munmap(pressure, 24 << 20));
	CHECK(!umount(root) && !rmdir(root));
	/* Observation window, not a claim of all RCU callbacks being drained. */
	usleep(500000);
	final = number("/sys/fs/cgroup/ckm-stress/memory.current");
	printf("CKM_STRESS_MEMORY initial=%llu peak_observed=%llu post500ms=%llu limit=50331648\n",
	       initial, peak, final);
	CHECK(initial != ~0ULL && final != ~0ULL && peak <= 50331648);
	CHECK(!put("/sys/fs/cgroup/cgroup.procs", "0"));
	CHECK(!rmdir("/sys/fs/cgroup/ckm-stress"));
	return 0;
}

int main(void)
{
	int k, failures = 0;

	if (!getenv("CKM_ISOLATED_GUEST"))
		return 4;
	for (k = 0; k < 2; k++) {
		pid_t p = fork();
		int status, rc;

		if (!p)
			_exit(k ? batch_case() : fault_case());
		if (p < 0 || waitpid(p, &status, 0) != p)
			return 1;
		rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
		printf("CKM_STRESS case=%s result=%s\n", k ? "batch-pressure" : "allocation-fail", rc ? "FAIL" : "PASS");
		failures += !!rc;
	}
	return !!failures;
}
