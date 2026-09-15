// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <linux/magic.h>
#include <linux/openat2.h>

#define MAX_DEPTH 64
#define MAX_INODES 1048576ULL
#define PREPARE_FAILURE 125

struct copy_state {
	uint64_t bytes, nodes, limit_bytes, limit_nodes;
};

static volatile sig_atomic_t interrupted;

static void handle_signal(int sig)
{
	interrupted = sig;
}

static int fail(int error)
{
	errno = error;
	return -1;
}

static int open_source(int dirfd, const char *name, bool top)
{
	struct open_how how = {
		.flags = O_PATH | O_CLOEXEC | O_NOFOLLOW,
		.resolve = RESOLVE_NO_SYMLINKS |
			(top ? 0 : RESOLVE_BENEATH | RESOLVE_NO_XDEV),
	};
	struct stat st;
	char path[64];
	int pinned, fd, saved;

	pinned = syscall(SYS_openat2, dirfd, name, &how, sizeof(how));
	if (pinned < 0)
		return -1;
	if (fstat(pinned, &st)) {
		saved = errno;
		close(pinned);
		return fail(saved);
	}
	if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
		close(pinned);
		return fail(EOPNOTSUPP);
	}
	/* Reopen the pinned, type-checked object, not an attacker-replaced name. */
	snprintf(path, sizeof(path), "/proc/self/fd/%d", pinned);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NONBLOCK);
	saved = errno;
	close(pinned);
	errno = saved;
	return fd;
}

static bool same_object(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
		a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
		a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
		a->st_size == b->st_size &&
		a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
		a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
		a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
		a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int no_xattrs(int fd)
{
	ssize_t n = flistxattr(fd, NULL, 0);

	if (n == 0 || (n < 0 && errno == EOPNOTSUPP))
		return 0;
	return n > 0 ? fail(EOPNOTSUPP) : -1;
}

static int validate_source(int fd, struct stat *st)
{
	struct statx sx;

	if (fstat(fd, st))
		return -1;
	if ((!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode)) ||
	    (st->st_mode & (S_ISUID | S_ISGID)) ||
	    (S_ISREG(st->st_mode) && st->st_nlink != 1))
		return fail(EOPNOTSUPP);
	if (statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
		  STATX_BASIC_STATS, &sx))
		return -1;
	/* Mount-root identity changes on copy; other reported attributes do not. */
	if (sx.stx_attributes & ~STATX_ATTR_MOUNT_ROOT)
		return fail(EOPNOTSUPP);
	return no_xattrs(fd);
}

static int set_metadata(int fd, const struct stat *st)
{
	struct timespec times[2] = { st->st_atim, st->st_mtim };
	struct stat out;

	if (fchown(fd, st->st_uid, st->st_gid) ||
	    fchmod(fd, st->st_mode & 07777) || futimens(fd, times) ||
	    no_xattrs(fd) || fstat(fd, &out))
		return -1;
	if (out.st_uid != st->st_uid || out.st_gid != st->st_gid ||
	    (out.st_mode & 07777) != (st->st_mode & 07777) ||
	    out.st_atim.tv_sec != st->st_atim.tv_sec ||
	    out.st_atim.tv_nsec != st->st_atim.tv_nsec ||
	    out.st_mtim.tv_sec != st->st_mtim.tv_sec ||
	    out.st_mtim.tv_nsec != st->st_mtim.tv_nsec)
		return fail(EIO);
	return 0;
}

static int write_all(int fd, const char *buf, size_t n)
{
	while (n) {
		ssize_t w = write(fd, buf, n);

		if (w < 0 && errno == EINTR && !interrupted)
			continue;
		if (w <= 0)
			return w == 0 ? fail(EIO) : -1;
		buf += w;
		n -= w;
	}
	return 0;
}

static int copy_file(int src, int dst, const struct stat *st,
		     struct copy_state *state)
{
	char buf[65536];
	uint64_t done = 0;
	struct stat after;

	if (st->st_size < 0 || (uint64_t)st->st_size >
	    state->limit_bytes - state->bytes)
		return fail(ENOSPC);
	for (;;) {
		ssize_t n;

		if (interrupted)
			return fail(EINTR);
		n = read(src, buf, sizeof(buf));
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -1;
		if (!n)
			break;
		if ((uint64_t)n > (uint64_t)st->st_size - done)
			return fail(ESTALE);
		if (write_all(dst, buf, n))
			return -1;
		done += n;
	}
	if (done != (uint64_t)st->st_size || fstat(src, &after) ||
	    !same_object(st, &after))
		return fail(ESTALE);
	if (no_xattrs(src) || set_metadata(dst, st))
		return -1;
	state->bytes += done;
	return 0;
}

static int copy_dir(int src, int dst, unsigned int depth,
		    struct copy_state *state)
{
	struct stat before, after;
	DIR *dir;
	int duplicate, result = -1, saved;

	if (depth > MAX_DEPTH)
		return fail(ELOOP);
	if (validate_source(src, &before))
		return -1;
	duplicate = dup(src);
	if (duplicate < 0)
		return -1;
	dir = fdopendir(duplicate);
	if (!dir) {
		close(duplicate);
		return -1;
	}
	for (;;) {
		struct dirent *de;
		struct stat st;
		int in, out = -1, rc;

		if (interrupted) {
			errno = EINTR;
			goto end;
		}
		errno = 0;
		de = readdir(dir);
		if (!de) {
			if (errno)
				goto end;
			break;
		}
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (state->nodes == state->limit_nodes) {
			errno = ENOSPC;
			goto end;
		}
		/* Check type before opening, so an unsupported device is never opened. */
		if (fstatat(src, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
			goto end;
		if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
			errno = EOPNOTSUPP;
			goto end;
		}
		in = open_source(src, de->d_name, false);
		if (in < 0)
			goto end;
		rc = validate_source(in, &after);
		if (rc || !same_object(&st, &after)) {
			saved = rc ? errno : ESTALE;
			close(in);
			errno = saved;
			goto end;
		}
		state->nodes++;
		if (S_ISDIR(st.st_mode)) {
			if (!mkdirat(dst, de->d_name, 0700))
				out = openat(dst, de->d_name,
					     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		} else {
			out = openat(dst, de->d_name,
				     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
				     0600);
		}
		if (out < 0) {
			saved = errno;
			close(in);
			errno = saved;
			goto end;
		}
		rc = S_ISDIR(st.st_mode) ? copy_dir(in, out, depth + 1, state) :
			copy_file(in, out, &st, state);
		saved = errno;
		if (close(out) && !rc) {
			rc = -1;
			saved = errno;
		}
		close(in);
		if (rc) {
			errno = saved;
			goto end;
		}
	}
	if (fstat(src, &after) || !same_object(&before, &after)) {
		errno = ESTALE;
		goto end;
	}
	if (no_xattrs(src) || set_metadata(dst, &before))
		goto end;
	result = 0;
end:
	saved = errno;
	closedir(dir);
	errno = saved;
	return result;
}

static int initial_root(void)
{
	unsigned long long inside, outside, length;
	FILE *f;
	char tail;
	int n;

	if (getuid() || geteuid())
		return fail(EPERM);
	f = fopen("/proc/self/uid_map", "re");
	if (!f)
		return -1;
	n = fscanf(f, "%llu %llu %llu %c", &inside, &outside, &length, &tail);
	fclose(f);
	return n == 3 && inside == 0 && outside == 0 && length == 4294967295ULL ?
		0 : fail(EPERM);
}

static int empty_directory(int fd)
{
	DIR *dir = fdopendir(dup(fd));
	struct dirent *de;
	int rc = 0, saved;

	if (!dir)
		return -1;
	errno = 0;
	while ((de = readdir(dir))) {
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			rc = fail(ENOTEMPTY);
			break;
		}
	}
	if (!rc && errno)
		rc = -1;
	saved = errno;
	closedir(dir);
	errno = saved;
	return rc;
}

static uint64_t positive(const char *s)
{
	char *end;
	const char *p;
	unsigned long long n;

	errno = 0;
	if (!*s)
		return 0;
	for (p = s; *p; p++)
		if (*p < '0' || *p > '9')
			return 0;
	n = strtoull(s, &end, 10);
	return errno || *end ? 0 : n;
}

int main(int argc, char **argv)
{
	struct copy_state state = { .nodes = 1 };
	const char *source = NULL, *target = NULL, *mode = NULL;
	struct sigaction action = { .sa_handler = handle_signal };
	struct stat st, target_st, cwd_st;
	struct statfs fs;
	char options[128];
	int arg, src = -1, dst = -1, old = -1, status, result = PREPARE_FAILURE;
	bool stable = false, mounted = false;
	pid_t child;

	for (arg = 1; arg < argc && strcmp(argv[arg], "--"); arg++) {
		if (!strcmp(argv[arg], "--source-stable")) {
			stable = true;
			continue;
		}
		if (arg + 1 == argc)
			goto usage;
		if (!strcmp(argv[arg], "--source"))
			source = argv[++arg];
		else if (!strcmp(argv[arg], "--target"))
			target = argv[++arg];
		else if (!strcmp(argv[arg], "--mode"))
			mode = argv[++arg];
		else if (!strcmp(argv[arg], "--bytes"))
			state.limit_bytes = positive(argv[++arg]);
		else if (!strcmp(argv[arg], "--inodes"))
			state.limit_nodes = positive(argv[++arg]);
		else
			goto usage;
	}
	if (arg + 1 >= argc || !source || !target || !mode || !stable ||
	    source[0] != '/' || target[0] != '/' ||
	    (strcmp(mode, "ro") && strcmp(mode, "rw")) ||
	    !state.limit_bytes || !state.limit_nodes ||
	    state.limit_bytes > LLONG_MAX ||
	    state.limit_nodes > MAX_INODES)
		goto usage;
	if (initial_root())
		goto error;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL))
		goto error;
	umask(077);
	src = open_source(AT_FDCWD, source, true);
	old = open_source(AT_FDCWD, target, true);
	if (src < 0 || old < 0 || validate_source(src, &st) ||
	    !S_ISDIR(st.st_mode) || fstat(old, &target_st) ||
	    !S_ISDIR(target_st.st_mode) || empty_directory(old))
		goto error;
	if (st.st_dev == target_st.st_dev && st.st_ino == target_st.st_ino) {
		errno = EINVAL;
		goto error;
	}
	if (stat(".", &cwd_st))
		goto error;
	if (cwd_st.st_dev == target_st.st_dev && cwd_st.st_ino == target_st.st_ino) {
		errno = EINVAL;
		goto error;
	}
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		goto error;
	snprintf(options, sizeof(options), "size=%llu,nr_inodes=%llu,mode=0700",
		 (unsigned long long)state.limit_bytes,
		 (unsigned long long)state.limit_nodes);
	if (mount("ckm-private-tree", target, "tmpfs", MS_NOSUID | MS_NODEV, options))
		goto error;
	mounted = true;
	dst = open_source(AT_FDCWD, target, true);
	if (dst < 0 || fstatfs(dst, &fs) || fs.f_type != TMPFS_MAGIC ||
	    copy_dir(src, dst, 0, &state))
		goto error;
	if (!strcmp(mode, "ro") &&
	    mount(NULL, target, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
		goto error;
	close(dst);
	dst = -1;
	close(src);
	src = -1;
	close(old);
	old = -1;
	if (interrupted) {
		errno = EINTR;
		goto error;
	}
	printf("CKM_PRIVATE_READY bytes=%llu nodes=%llu mode=%s\n",
	       (unsigned long long)state.bytes, (unsigned long long)state.nodes, mode);
	fflush(stdout);
	child = fork();
	if (child < 0)
		goto error;
	if (!child) {
		if (setpgid(0, 0))
			_exit(126);
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		execvp(argv[arg + 1], &argv[arg + 1]);
		perror("exec");
		_exit(127);
	}
	setpgid(child, child);
	for (;;) {
		pid_t waited;
		struct timespec pause = { .tv_nsec = 10000000 };

		if (interrupted)
			kill(-child, interrupted);
		waited = waitpid(child, &status, WNOHANG);

		if (waited == child)
			break;
		if (waited < 0 && errno != EINTR)
			goto error;
		nanosleep(&pause, NULL);
	}
	result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	goto cleanup;
error:
	perror("ckm_mount_prepare");
cleanup:
	if (src >= 0)
		close(src);
	if (dst >= 0)
		close(dst);
	if (old >= 0)
		close(old);
	if (mounted && umount2(target, 0)) {
		perror("private mount still busy; namespace teardown will release it");
		result = PREPARE_FAILURE;
	}
	return result;
usage:
	fprintf(stderr, "usage: %s --source ABS --target EMPTY_ABS --source-stable "
		"--mode ro|rw --bytes N --inodes N -- COMMAND [ARGS]\n", argv[0]);
	return PREPARE_FAILURE;
}
