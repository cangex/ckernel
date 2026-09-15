// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <sys/wait.h>

int child_result(pid_t pid)
{
	int status;

	if (pid < 0)
		return 1;
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			return 1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int main(int argc, char **argv)
{
	int result;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(60);
	result = test_main(argc, argv);
	printf("TAP version 13\n1..1\n%s 1 - %s%s\n",
	       result == 0 || result == SKIP ? "ok" : "not ok", argv[0],
	       result == SKIP ? " # SKIP required facility unavailable" : "");
	return result;
}
