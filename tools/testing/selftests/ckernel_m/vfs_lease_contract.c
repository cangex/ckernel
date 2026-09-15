// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { \
	fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno); \
	return 1; } } while (0)

static int remove_one(const char *p, const struct stat *s, int type, struct FTW *f)
{
	(void)s; (void)type; (void)f;
	return remove(p);
}

static int create_file(int dir, const char *name)
{
	int fd = openat(dir, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);

	if (fd >= 0 && write(fd, "original", 8) != 8) {
		close(fd);
		return -1;
	}
	return fd;
}

static int test_case(const char *kind)
{
	char root[] = "/tmp/ckm-lease-contract-XXXXXX";
	char path[PATH_MAX], alias[PATH_MAX], name[PATH_MAX];
	struct stat old, current;
	int dir, fd, newer;

	REQUIRE(mkdtemp(root) && !chmod(root, 0755));
	snprintf(path, sizeof(path), "%s/objects", root);
	snprintf(alias, sizeof(alias), "%s/alias", root);
	snprintf(name, sizeof(name), "%s/objects/file", root);
	REQUIRE(!mkdir(path, 0755) && !mkdir(alias, 0755));
	REQUIRE(!mount("lease-contract", path, "tmpfs", 0, "size=1m,mode=0755"));
	dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	REQUIRE(dir >= 0);
	fd = create_file(dir, "file");
	REQUIRE(fd >= 0 && !fstat(fd, &old));
	close(fd);
	fd = openat(dir, "file", O_PATH | O_CLOEXEC);
	REQUIRE(fd >= 0);
	if (!strcmp(kind, "pin_umount")) {
		close(dir);
		REQUIRE(umount2(path, 0) == -1 && errno == EBUSY);
		close(fd);
		REQUIRE(!umount2(path, 0));
		puts("CKM_CONTRACT pin_umount held_path=EBUSY released_path=success");
	} else if (!strcmp(kind, "name_replacement")) {
		REQUIRE(!unlinkat(dir, "file", 0));
		newer = create_file(dir, "file");
		REQUIRE(newer >= 0 && !fstat(newer, &current));
		REQUIRE(old.st_ino != current.st_ino);
		REQUIRE(!fstat(fd, &current) && old.st_ino == current.st_ino);
		close(newer); close(fd); close(dir);
		REQUIRE(!umount2(path, 0));
		puts("CKM_CONTRACT name_replacement pinned_object_is_not_current_name=1");
	} else if (!strcmp(kind, "readonly_alias")) {
		REQUIRE(!mount(path, alias, NULL, MS_BIND, NULL));
		REQUIRE(!mount(NULL, alias, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL));
		REQUIRE(!fchmodat(dir, "file", 0600, 0));
		snprintf(name, sizeof(name), "%s/alias/file", root);
		REQUIRE(!stat(name, &current) && current.st_ino == old.st_ino);
		REQUIRE((current.st_mode & 0777) == 0600);
		close(fd); close(dir);
		REQUIRE(!umount2(alias, 0) && !umount2(path, 0));
		puts("CKM_CONTRACT readonly_alias writable_alias_changes_same_inode=1");
	} else if (!strcmp(kind, "directory_permission")) {
		pid_t child;
		int status;

		REQUIRE(!fchmod(dir, 0700));
		child = fork();
		REQUIRE(child >= 0);
		if (!child) {
			if (setuid(65534))
				_exit(1);
			if (!fstat(fd, &current) && stat(name, &current) == -1 && errno == EACCES)
				_exit(0);
			_exit(1);
		}
		REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
		close(fd); close(dir);
		REQUIRE(!umount2(path, 0));
		puts("CKM_CONTRACT directory_permission pinned_getattr_success_path_lookup_EACCES=1");
	} else {
		close(dir);
		REQUIRE(!mount(NULL, path, NULL, MS_REMOUNT | MS_RDONLY, NULL));
		REQUIRE(!mount(NULL, path, NULL, MS_REMOUNT, NULL));
		REQUIRE(!chmod(name, 0600) && !fstat(fd, &current));
		REQUIRE((current.st_mode & 0777) == 0600);
		close(fd);
		REQUIRE(!umount2(path, 0));
		puts("CKM_CONTRACT private_readonly remount_rw_changes_pinned_inode=1");
	}
	REQUIRE(!nftw(root, remove_one, 32, FTW_DEPTH | FTW_PHYS | FTW_MOUNT));
	return 0;
}

int main(void)
{
	const char *cases[] = { "pin_umount", "name_replacement", "readonly_alias",
		"directory_permission", "private_readonly" };
	unsigned int n;
	int failures = 0;

	if (getuid() || !getenv("CKM_ISOLATED_GUEST"))
		return 4;
	REQUIRE(!unshare(CLONE_NEWNS) && !mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
	setvbuf(stdout, NULL, _IONBF, 0);
	for (n = 0; n < sizeof(cases) / sizeof(cases[0]); n++) {
		pid_t p = fork();
		int status, rc;

		REQUIRE(p >= 0);
		if (!p)
			_exit(test_case(cases[n]));
		REQUIRE(waitpid(p, &status, 0) == p);
		rc = !WIFEXITED(status) || WEXITSTATUS(status);
		printf("CKM_CONTRACT_TEST case=%s result=%s\n", cases[n], rc ? "FAIL" : "PASS");
		failures += rc != 0;
	}
	return failures ? 1 : 0;
}
