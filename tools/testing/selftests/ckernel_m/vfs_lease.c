// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/ckernel_m.h"

#define REQUIRE(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno); \
	return 1; } } while (0)

struct reader {
	const char *path;
	atomic_int stop, errors;
};

static int remove_one(const char *p, const struct stat *s, int type, struct FTW *f)
{
	(void)s; (void)type; (void)f;
	return remove(p);
}

static int query(int inst, struct ckm_vfs_query *q)
{
	memset(q, 0, sizeof(*q));
	q->version = CKM_ABI_VERSION;
	q->size = sizeof(*q);
	return ioctl(inst, CKM_IOC_VFS_QUERY, q);
}

static void *read_many(void *arg)
{
	struct reader *r = arg;
	struct statx st;

	while (!atomic_load(&r->stop)) {
		if (statx(AT_FDCWD, r->path, 0, STATX_BASIC_STATS, &st) && errno != ENOENT)
			atomic_fetch_add(&r->errors, 1);
	}
	return NULL;
}

static int test_case(const char *kind)
{
	struct ckm_create request = { .version = CKM_ABI_VERSION,
		.size = sizeof(request), .features = CKM_FEATURE_VFS };
	struct ckm_vfs_root reg = { .version = CKM_ABI_VERSION,
		.size = sizeof(reg), .capacity = 2 };
	struct ckm_vfs_query q, before;
	struct statx st, old;
	char root[] = "/tmp/ckm-vfs-lease-XXXXXX";
	char mountpoint[PATH_MAX], path[PATH_MAX], newpath[PATH_MAX], sub[PATH_MAX];
	int ctl, inst, fd, n;
	pid_t child;

	ctl = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	REQUIRE(ctl >= 0);
	inst = ioctl(ctl, CKM_IOC_CREATE, &request);
	if (inst < 0 && errno == EOPNOTSUPP) {
		close(ctl);
		return 4;
	}
	REQUIRE(inst >= 0);
	close(ctl);
	REQUIRE(mkdtemp(root) && !chmod(root, 0755));
	snprintf(mountpoint, sizeof(mountpoint), "%s/objects", root);
	snprintf(path, sizeof(path), "%s/objects/sub/file", root);
	snprintf(newpath, sizeof(newpath), "%s/objects/sub/new", root);
	snprintf(sub, sizeof(sub), "%s/objects/sub", root);
	REQUIRE(!mkdir(mountpoint, 0755));
	REQUIRE(!mount("ckm-vfs-lease", mountpoint, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m,mode=0755"));
	REQUIRE(!mkdir(sub, 0755));
	fd = open(path, O_CREAT | O_RDWR | O_EXCL, 0644);
	REQUIRE(fd >= 0 && write(fd, "old", 3) == 3 && !close(fd));
	if (!strcmp(kind, "readonly_alias")) {
		char alias[PATH_MAX];

		snprintf(alias, sizeof(alias), "%s/alias", root);
		REQUIRE(!mkdir(alias, 0755));
		REQUIRE(!mount(mountpoint, alias, NULL, MS_BIND, NULL));
		REQUIRE(!mount(NULL, alias, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL));
		reg.fd = open(alias, O_PATH | O_CLOEXEC);
		REQUIRE(reg.fd >= 0);
		REQUIRE(ioctl(inst, CKM_IOC_VFS_ROOT, &reg) == -1 && errno == EOPNOTSUPP);
		REQUIRE(!close(reg.fd) && !umount(alias) && !rmdir(alias));
	}
	if (!strcmp(kind, "capacity")) {
		fd = open(newpath, O_CREAT | O_RDWR | O_EXCL, 0644);
		REQUIRE(fd >= 0 && !close(fd));
		for (n = 0; n < 3; n++) {
			char extra[PATH_MAX];

			snprintf(extra, sizeof(extra), "%s/objects/item%d", root, n);
			fd = open(extra, O_CREAT | O_RDWR | O_EXCL, 0644);
			REQUIRE(fd >= 0 && !close(fd));
		}
	}
	if (!strcmp(kind, "reclaim_space")) {
		fd = open(newpath, O_CREAT | O_RDWR | O_EXCL, 0644);
		REQUIRE(fd >= 0 && !fallocate(fd, 0, 0, 3 * 1024 * 1024) && !close(fd));
	}
	REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
	reg.fd = open(mountpoint, O_PATH | O_CLOEXEC);
	REQUIRE(reg.fd >= 0);
	if (!strcmp(kind, "invalid_abi")) {
		reg.reserved[0] = 1;
		REQUIRE(ioctl(inst, CKM_IOC_VFS_ROOT, &reg) == -1 && errno == EINVAL);
		reg.reserved[0] = 0;
		reg.capacity = CKM_VFS_MAX_ENTRIES + 1;
		REQUIRE(ioctl(inst, CKM_IOC_VFS_ROOT, &reg) == -1 && errno == EINVAL);
		reg.capacity = 2;
	}
	REQUIRE(!ioctl(inst, CKM_IOC_VFS_ROOT, &reg));
	REQUIRE(ioctl(inst, CKM_IOC_VFS_ROOT, &reg) == -1 && errno == EBUSY);
	close(reg.fd);
	if (!strcmp(kind, "launcher")) {
		int status;

		child = fork();
		REQUIRE(child >= 0);
		if (!child) {
			execl("/ckmctl", "ckmctl", "--vfs", mountpoint, "2",
			      "/tests/vfs_lease", "check", path, NULL);
			_exit(127);
		}
		REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
	}
	REQUIRE(!ioctl(inst, CKM_IOC_BIND, 0));
	for (n = 0; n < 100; n++)
		REQUIRE(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) && st.stx_size == 3);
	old = st;
	REQUIRE(!query(inst, &before) && before.hits > 0 && before.cached == 1);
	if (!strcmp(kind, "capacity")) {
		REQUIRE(!statx(AT_FDCWD, newpath, 0, STATX_BASIC_STATS, &st));
		for (n = 0; n < 3; n++) {
			char extra[PATH_MAX];

			snprintf(extra, sizeof(extra), "%s/objects/item%d", root, n);
			REQUIRE(!statx(AT_FDCWD, extra, 0, STATX_BASIC_STATS, &st));
		}
		REQUIRE(!query(inst, &q) && q.cached == 2 && q.full > 0);
	} else if (!strcmp(kind, "reclaim_space")) {
		REQUIRE(!statx(AT_FDCWD, newpath, 0, STATX_BASIC_STATS, &st));
		REQUIRE(!query(inst, &q) && q.cached == 2);
		REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL));
		REQUIRE(!unlink(newpath));
		fd = open(newpath, O_CREAT | O_RDWR | O_EXCL, 0644);
		REQUIRE(fd >= 0 && !fallocate(fd, 0, 0, 3 * 1024 * 1024) && !close(fd));
	} else if (!strcmp(kind, "rename") || !strcmp(kind, "permission")) {
		REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL));
		if (!strcmp(kind, "permission"))
			REQUIRE(!chmod(sub, 0700));
		else {
			REQUIRE(!unlink(path));
			fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644);
			REQUIRE(fd >= 0 && write(fd, "new!", 4) == 4 && !close(fd));
		}
		REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
		if (!strcmp(kind, "permission")) {
			int status;

			child = fork();
			REQUIRE(child >= 0);
			if (!child) {
				if (setuid(65534))
					_exit(1);
				_exit(!(statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) == -1 && errno == EACCES));
			}
			REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
		} else {
			REQUIRE(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st));
			REQUIRE(st.stx_ino != old.stx_ino && st.stx_size == 4);
		}
		REQUIRE(!query(inst, &q) && q.stopped && !q.cached);
	} else if (!strcmp(kind, "revoke_race")) {
		struct reader r = { .path = path };
		pthread_t threads[2];

		REQUIRE(!pthread_create(&threads[0], NULL, read_many, &r));
		REQUIRE(!pthread_create(&threads[1], NULL, read_many, &r));
		usleep(10000);
		REQUIRE(!ioctl(inst, CKM_IOC_REVOKE, 0));
		for (n = 0; n < 100; n++)
			REQUIRE(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st));
		atomic_store(&r.stop, 1);
		REQUIRE(!pthread_join(threads[0], NULL) && !pthread_join(threads[1], NULL));
		REQUIRE(!atomic_load(&r.errors));
	} else if (!strcmp(kind, "remount_race")) {
		struct reader r = { .path = path };
		pthread_t threads[2];

		REQUIRE(!pthread_create(&threads[0], NULL, read_many, &r));
		REQUIRE(!pthread_create(&threads[1], NULL, read_many, &r));
		for (n = 0; n < 30; n++) {
			REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL));
			REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
		}
		atomic_store(&r.stop, 1);
		REQUIRE(!pthread_join(threads[0], NULL) && !pthread_join(threads[1], NULL));
		REQUIRE(!atomic_load(&r.errors));
		REQUIRE(!query(inst, &q) && q.stopped && !q.cached);
	} else if (!strcmp(kind, "overmount")) {
		REQUIRE(!mount("replacement", mountpoint, "tmpfs", MS_NOSUID | MS_NODEV, "size=1m"));
		REQUIRE(statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) == -1 && errno == ENOENT);
		REQUIRE(!umount2(mountpoint, 0));
		REQUIRE(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) && st.stx_ino == old.stx_ino);
	} else if (!strcmp(kind, "fork_exec")) {
		int status;

		child = fork();
		REQUIRE(child >= 0);
		if (!child) {
			execl("/tests/vfs_lease", "vfs_lease", "check", path, NULL);
			_exit(127);
		}
		REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
	} else if (!strcmp(kind, "rw_fallback")) {
		REQUIRE(!mount(NULL, mountpoint, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL));
		REQUIRE(!query(inst, &before));
		for (n = 0; n < 20; n++)
			REQUIRE(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st));
		REQUIRE(!query(inst, &q) && q.hits == before.hits && q.stopped && !q.cached);
	} else if (!strcmp(kind, "flags_errors")) {
		REQUIRE(statx(AT_FDCWD, path, 0x80000000, STATX_BASIC_STATS, &st) == -1 && errno == EINVAL);
		REQUIRE(statx(-1000, "file", 0, STATX_BASIC_STATS, &st) == -1 && errno == EBADF);
		REQUIRE(statx(AT_FDCWD, newpath, 0, STATX_BASIC_STATS, &st) == -1 && errno == ENOENT);
	}
	REQUIRE(!query(inst, &q));
	printf("CKM_VFS_COUNTS case=%s hits=%llu retries=%llu native=%llu full=%llu cached=%u bytes=%llu\n",
	       kind, q.hits, q.retries, q.native, q.full, q.cached, q.metadata_payload_bytes);
	if (strcmp(kind, "revoke_race"))
		REQUIRE(!umount2(mountpoint, 0));
	else {
		for (n = 0; n < 100; n++) {
			REQUIRE(!query(inst, &q));
			if (q.stopped)
				break;
			usleep(10000);
		}
		REQUIRE(q.stopped && !umount2(mountpoint, 0));
	}
	/* fs_pin kill occurs during deferred mount cleanup, not necessarily umount return. */
	for (n = 0; n < 100; n++) {
		REQUIRE(!query(inst, &q));
		if (q.stopped && !q.cached)
			break;
		usleep(10000);
	}
	REQUIRE(q.stopped && !q.cached);
	close(inst);
	REQUIRE(!nftw(root, remove_one, 32, FTW_DEPTH | FTW_PHYS | FTW_MOUNT));
	return 0;
}

int main(int argc, char **argv)
{
	const char *cases[] = { "hit_umount", "invalid_abi", "rename", "permission", "capacity",
		"revoke_race", "overmount", "fork_exec", "rw_fallback", "flags_errors", "reclaim_space",
		"remount_race", "readonly_alias", "launcher" };
	unsigned int n;
	int failures = 0;

	if (argc == 3 && !strcmp(argv[1], "check")) {
		struct statx st;

		for (n = 0; n < 100; n++)
			REQUIRE(!statx(AT_FDCWD, argv[2], 0, STATX_BASIC_STATS, &st) && st.stx_size == 3);
		return 0;
	}
	if (getuid() || !getenv("CKM_ISOLATED_GUEST"))
		return 4;
	REQUIRE(!unshare(CLONE_NEWNS) && !mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
	setvbuf(stdout, NULL, _IONBF, 0);
	for (n = 0; n < sizeof(cases) / sizeof(cases[0]); n++) {
		pid_t p = fork();
		int status, rc;
		const char *result;

		REQUIRE(p >= 0);
		if (!p)
			_exit(test_case(cases[n]));
		REQUIRE(waitpid(p, &status, 0) == p);
		rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
		result = rc ? "FAIL" : "PASS";
		if (rc == 4)
			result = "SKIP";
		printf("CKM_VFS_TEST case=%s result=%s rc=%d\n", cases[n],
		       result, rc);
		if (rc == 4)
			return 4;
		failures += rc != 0;
	}
	return failures ? 1 : 0;
}
