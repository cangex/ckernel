// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <linux/magic.h>

static const char *tool;
static char self[PATH_MAX];

#define REQUIRE(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); \
	return 1; } } while (0)

static int set_value(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, value, strlen(value));
	close(fd);
	return n == (ssize_t)strlen(value) ? 0 : -1;
}

static long long shmem_bytes(const char *path)
{
	FILE *f = fopen(path, "re");
	char key[128];
	long long value, result = -1;

	if (!f)
		return -1;
	while (fscanf(f, "%127s %lld", key, &value) == 2)
		if (!strcmp(key, "shmem")) {
			result = value;
			break;
		}
	fclose(f);
	return result;
}

static int put(const char *path, const char *content)
{
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	size_t len = strlen(content);
	int rc;

	if (fd < 0)
		return -1;
	rc = write(fd, content, len) == (ssize_t)len ? 0 : -1;
	if (close(fd))
		rc = -1;
	return rc;
}

static int check_content(const char *path, const char *expected)
{
	char data[32] = {};
	int fd = open(path, O_RDONLY | O_CLOEXEC), n;

	REQUIRE(fd >= 0);
	n = read(fd, data, sizeof(data));
	close(fd);
	REQUIRE(n == (int)strlen(expected) && !memcmp(data, expected, n));
	return 0;
}

static int child_check(const char *target, const char *source, const char *kind)
{
	char a[PATH_MAX], b[PATH_MAX], dir[PATH_MAX];
	struct stat x, y, old;
	struct statfs fs;
	int fd;

	if (!strcmp(kind, "exit7"))
		return 7;
	if (!strcmp(kind, "signal")) {
		kill(getpid(), SIGTERM);
		return 1;
	}
	if (!strcmp(kind, "interrupt-copy")) {
		pause();
		return 1;
	}
	snprintf(a, sizeof(a), "%s/file", target);
	snprintf(b, sizeof(b), "%s/file", source);
	snprintf(dir, sizeof(dir), "%s/sub", target);
	REQUIRE(!statfs(target, &fs) && fs.f_type == TMPFS_MAGIC);
	REQUIRE(!stat(a, &x) && !stat(b, &y));
	REQUIRE(x.st_dev != y.st_dev || x.st_ino != y.st_ino);
	REQUIRE(x.st_mode == y.st_mode && x.st_uid == y.st_uid && x.st_gid == y.st_gid);
	REQUIRE(x.st_mtim.tv_sec == y.st_mtim.tv_sec && x.st_mtim.tv_nsec == y.st_mtim.tv_nsec);
	REQUIRE(x.st_atim.tv_sec == y.st_atim.tv_sec && x.st_atim.tv_nsec == y.st_atim.tv_nsec);
	REQUIRE(!check_content(a, "original") && !stat(dir, &old) && S_ISDIR(old.st_mode));
	if (!strcmp(kind, "accounting")) {
		long long charged = shmem_bytes(getenv("CKM_TEST_MEMORY_STAT"));

		printf("CKM_PRIVATE_ACCOUNTING during_shmem=%lld\n", charged);
		REQUIRE(charged >= 4 * 1024 * 1024);
	}
	if (!strcmp(kind, "ro")) {
		fd = open(a, O_WRONLY | O_TRUNC);
		REQUIRE(fd == -1 && errno == EROFS);
	} else {
		fd = open(a, O_WRONLY | O_TRUNC);
		REQUIRE(fd >= 0 && write(fd, "private", 7) == 7 && !close(fd));
		REQUIRE(!check_content(b, "original"));
	}
	fd = open(a, O_RDONLY | O_CLOEXEC);
	REQUIRE(fd >= 0 && !umount2(target, MNT_DETACH));
	REQUIRE(!fstat(fd, &old) && old.st_ino == x.st_ino);
	close(fd);
	/* Restore an empty mount solely so the supervisor can test ordinary unmount. */
	REQUIRE(!mount("child-cleanup", target, "tmpfs", MS_NODEV | MS_NOSUID, "size=4096"));
	return 0;
}

static int remove_one(const char *path, const struct stat *st, int type,
		      struct FTW *where)
{
	(void)st;
	(void)type;
	(void)where;
	return remove(path);
}

static int status_of(pid_t p)
{
	int st;

	while (waitpid(p, &st, 0) != p) {
		if (errno != EINTR)
			return 125;
	}
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static int scenario(const char *kind)
{
	char root[] = "/tmp/ckm-private-XXXXXX";
	char src[PATH_MAX], dst[PATH_MAX], file[PATH_MAX], extra[PATH_MAX];
	char cgmount[PATH_MAX], cgleaf[PATH_MAX], cgstat[PATH_MAX], cgprocs[PATH_MAX];
	struct timespec times[2] = { {1700000000, 123456789}, {1700000001, 234567890} };
	const char *mode = !strcmp(kind, "ro") ? "ro" : "rw";
	const char *bytes = !strcmp(kind, "bytes") ? "4" : "1048576";
	const char *nodes = !strcmp(kind, "inodes") ? "1" : "128";
	int wanted = 125, got, fd, i;
	pid_t p;
	DIR *dir;
	struct dirent *de;

	REQUIRE(mkdtemp(root));
	snprintf(src, sizeof(src), "%s/source", root);
	snprintf(dst, sizeof(dst), "%s/target", root);
	snprintf(file, sizeof(file), "%s/source/file", root);
	snprintf(extra, sizeof(extra), "%s/source/sub", root);
	REQUIRE(!mkdir(src, 0750) && !mkdir(dst, 0700) && !mkdir(extra, 0710));
	REQUIRE(!put(file, "original") && !chmod(file, 0640));
	REQUIRE(!utimensat(AT_FDCWD, file, times, 0));
	if (!strcmp(kind, "accounting") || !strcmp(kind, "interrupt-copy")) {
		char big[PATH_MAX];
		off_t size = !strcmp(kind, "accounting") ? 4 * 1024 * 1024 : 128 * 1024 * 1024;

		bytes = "268435456";
		snprintf(big, sizeof(big), "%s/source/big", root);
		fd = open(big, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
		REQUIRE(fd >= 0 && !ftruncate(fd, size) && !close(fd));
	}
	if (!strcmp(kind, "accounting")) {
		char control[PATH_MAX];

		snprintf(cgmount, sizeof(cgmount), "%s/cgroup", root);
		snprintf(cgleaf, sizeof(cgleaf), "%s/cgroup/copy", root);
		snprintf(cgstat, sizeof(cgstat), "%s/cgroup/copy/memory.stat", root);
		snprintf(cgprocs, sizeof(cgprocs), "%s/cgroup/copy/cgroup.procs", root);
		REQUIRE(!mkdir(cgmount, 0700) && !mount("ckm-test", cgmount, "cgroup2", 0, NULL));
		snprintf(control, sizeof(control), "%s/cgroup/cgroup.subtree_control", root);
		REQUIRE(!set_value(control, "+memory"));
		REQUIRE(!mkdir(cgleaf, 0700));
		snprintf(control, sizeof(control), "%s/cgroup/copy/memory.max", root);
		REQUIRE(!set_value(control, "33554432"));
		REQUIRE(!setenv("CKM_TEST_MEMORY_STAT", cgstat, 1));
	}
	if (!strcmp(kind, "ro") || !strcmp(kind, "rw") || !strcmp(kind, "isolation"))
		wanted = 0;
	else if (!strcmp(kind, "accounting"))
		wanted = 0;
	else if (!strcmp(kind, "exit7"))
		wanted = 7;
	else if (!strcmp(kind, "signal"))
		wanted = 128 + SIGTERM;
	else if (!strcmp(kind, "xattr"))
		REQUIRE(!setxattr(file, "user.ckm", "x", 1, 0));
	else if (!strcmp(kind, "hardlink")) {
		snprintf(extra, sizeof(extra), "%s/source/alias", root);
		REQUIRE(!link(file, extra));
	} else if (!strcmp(kind, "symlink")) {
		snprintf(extra, sizeof(extra), "%s/source/alias", root);
		REQUIRE(!symlink("file", extra));
	} else if (!strcmp(kind, "fifo")) {
		snprintf(extra, sizeof(extra), "%s/source/fifo", root);
		REQUIRE(!mkfifo(extra, 0600));
	} else if (!strcmp(kind, "suid"))
		REQUIRE(!chmod(file, 04750));
	else if (!strcmp(kind, "nonempty")) {
		snprintf(extra, sizeof(extra), "%s/target/keep", root);
		REQUIRE(!put(extra, "keep"));
	} else if (!strcmp(kind, "mount"))
		REQUIRE(!mount("nested", extra, "tmpfs", 0, "size=4096"));
	else if (!strcmp(kind, "depth")) {
		fd = open(extra, O_RDONLY | O_DIRECTORY);
		REQUIRE(fd >= 0);
		for (i = 0; i < 66; i++) {
			int next;

			REQUIRE(!mkdirat(fd, "d", 0700));
			next = openat(fd, "d", O_RDONLY | O_DIRECTORY);
			close(fd);
			REQUIRE(next >= 0);
			fd = next;
		}
		close(fd);
	}
	p = fork();
	REQUIRE(p >= 0);
	if (!p) {
		if (!strcmp(kind, "accounting") && set_value(cgprocs, "0"))
			_exit(126);
		if (!strcmp(kind, "userns")) {
			if (unshare(CLONE_NEWUSER) || set_value("/proc/self/uid_map", "0 0 1"))
				_exit(126);
		}
		if (!strcmp(kind, "unprivileged") && setuid(65534))
			_exit(126);
		if (!strcmp(kind, "no-contract"))
			execl(tool, tool, "--source", src, "--target", dst,
			      "--mode", mode, "--bytes", bytes, "--inodes", nodes,
			      "--", self, "child", dst, src, kind, NULL);
		else
			execl(tool, tool, "--source", src, "--target", dst,
			      "--mode", mode, "--bytes", bytes, "--inodes", nodes,
			      "--source-stable", "--", self, "child", dst, src, kind, NULL);
		_exit(127);
	}
	if (!strcmp(kind, "interrupt-copy")) {
		char info[64], line[8192];
		int seen = 0;

		snprintf(info, sizeof(info), "/proc/%d/mountinfo", p);
		for (i = 0; i < 5000 && !seen; i++) {
			FILE *f = fopen(info, "re");

			if (f) {
				while (fgets(line, sizeof(line), f))
					if (strstr(line, "ckm-private-tree")) {
						seen = 1;
						break;
					}
				fclose(f);
			}
			if (!seen)
				usleep(1000);
		}
		REQUIRE(seen && !kill(p, SIGTERM));
	}
	got = status_of(p);
	REQUIRE(got == wanted);
	REQUIRE(!check_content(file, "original"));
	/* The caller's mount namespace and target directory must stay unchanged. */
	dir = opendir(dst);
	REQUIRE(dir);
	i = 0;
	while ((de = readdir(dir)))
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
			i++;
	closedir(dir);
	REQUIRE(i == (!strcmp(kind, "nonempty") ? 1 : 0));
	if (!strcmp(kind, "mount"))
		REQUIRE(!umount(extra));
	if (!strcmp(kind, "accounting")) {
		long long remaining = -1;

		for (i = 0; i < 200; i++) {
			remaining = shmem_bytes(cgstat);
			if (!remaining)
				break;
			usleep(10000);
		}
		printf("CKM_PRIVATE_ACCOUNTING after_shmem=%lld\n", remaining);
		REQUIRE(!remaining && !rmdir(cgleaf) && !umount(cgmount));
	}
	REQUIRE(!nftw(root, remove_one, 32, FTW_DEPTH | FTW_PHYS | FTW_MOUNT));
	return 0;
}

int main(int argc, char **argv)
{
	const char *cases[] = { "rw", "ro", "isolation", "bytes", "inodes", "xattr",
		"hardlink", "symlink", "fifo", "suid", "nonempty", "mount", "depth",
		"unprivileged", "no-contract", "exit7", "signal", "accounting", "interrupt-copy", "userns" };
	unsigned int n;
	int failures = 0;
	ssize_t len;

	if (argc == 5 && !strcmp(argv[1], "child"))
		return child_check(argv[2], argv[3], argv[4]);
	tool = getenv("CKM_MOUNT_PREPARE");
	if (!tool)
		tool = "/ckm_mount_prepare";
	if (getuid() || !getenv("CKM_ISOLATED_GUEST") || access(tool, X_OK)) {
		puts("SKIP: requires explicit isolated guest and preparation tool");
		return 4;
	}
	REQUIRE(!unshare(CLONE_NEWNS));
	REQUIRE(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	REQUIRE(len > 0);
	self[len] = 0;
	setvbuf(stdout, NULL, _IONBF, 0);
	for (n = 0; n < sizeof(cases) / sizeof(cases[0]); n++) {
		pid_t child = fork();
		int result;

		REQUIRE(child >= 0);
		if (!child)
			_exit(scenario(cases[n]));
		result = status_of(child);
		printf("CKM_PRIVATE_TEST case=%s result=%s rc=%d\n",
		       cases[n], result ? "FAIL" : "PASS", result);
		failures += result != 0;
	}
	return failures ? 1 : 0;
}
