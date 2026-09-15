// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

int test_main(int argc, char **argv)
{
	char path[] = "/tmp/ckm-deny-XXXXXX";
	int fd;
	pid_t child;
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = 4, .filter = insns };

	(void)argc; (void)argv;
	if (geteuid())
		return SKIP;
	child = fork();
	if (!child) {
		const char *denied = "changeprofile ckm_missing_profile_m0m2";
		int result;

		fd = open("/proc/self/attr/current", O_WRONLY);
		if (fd < 0)
			_exit(SKIP);
		result = write(fd, denied, strlen(denied));
		if (result < 0 && (errno == EINVAL || errno == EOPNOTSUPP))
			_exit(SKIP);
		_exit(result < 0 && (errno == ENOENT || errno == EACCES) ? 0 : 1);
	}
	fd = child_result(child);
	CHECK(!fd || fd == SKIP);
	printf("# %s AppArmor transition to nonexistent profile\n", fd == SKIP ? "SKIP" : "PASS");
	fd = mkstemp(path);
	CHECK(fd >= 0 && !fchmod(fd, 0600));
	close(fd);
	child = fork();
	if (!child) {
		if (setgid(65534) || setuid(65534))
			_exit(1);
		fd = open(path, O_RDONLY);
		_exit(fd < 0 && errno == EACCES ? 0 : 1);
	}
	CHECK(!child_result(child));
	unlink(path);
	CHECK(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	CHECK(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog));
	CHECK(syscall(SYS_getppid) < 0 && errno == EPERM);
	puts("# PASS DAC denial and seccomp; SKIP AppArmor policy reload: no policy loader in minimal guest");
	return 0;
}
