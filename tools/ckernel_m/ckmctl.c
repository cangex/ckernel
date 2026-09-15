// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include "../../include/uapi/linux/ckernel_m.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r) };
	struct ckm_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
	char *end;
	unsigned long n;
	int control, instance, status, attempt;
	struct timespec start, finish;
	pid_t child;

	if (argc < 3) {
		fprintf(stderr, "usage: %s MAX_NODES PROGRAM [ARGS...] (0 = Core only)\n", argv[0]);
		return 2;
	}
	errno = 0;
	n = strtoul(argv[1], &end, 10);
	if (errno || end == argv[1] || *end || n > 4096)
		return 2;
	r.max_nodes = n;
	r.features = n ? CKM_FEATURE_MAPLE : 0;
	control = open("/dev/ckernel-m", O_RDWR | O_CLOEXEC);
	if (control < 0) {
		perror("open control");
		return 1;
	}
	instance = ioctl(control, CKM_IOC_CREATE, &r);
	if (instance < 0) {
		perror("create");
		close(control);
		return 1;
	}
	close(control);
	child = fork();
	if (!child) {
		if (ioctl(instance, CKM_IOC_BIND, 0UL)) {
			perror("bind");
			_exit(125);
		}
		execvp(argv[2], argv + 2);
		perror("exec");
		_exit(126);
	}
	if (child < 0) {
		perror("fork");
		close(instance);
		return 1;
	}
	while (waitpid(child, &status, 0) < 0)
		if (errno != EINTR)
			return 1;
	if (ioctl(instance, CKM_IOC_QUERY, &q) ||
	    clock_gettime(CLOCK_MONOTONIC, &start)) {
		perror("query or clock");
		close(instance);
		return 1;
	}
	printf("cookie=%llu state=%u tasks=%u mms=%u nodes=%u cpu_hits=%llu numa_hits=%llu misses=%llu fallbacks=%llu returned=%llu cached=%llu borrowed=%llu retired=%llu metadata_bytes=%llu node_bytes=%llu\n",
	       q.cookie, q.state, q.tasks, q.mms, q.nodes, q.hits_cpu,
	       q.hits_numa, q.misses, q.fallbacks, q.returned, q.cached,
	       q.borrowed, q.retired, q.metadata_bytes, q.node_bytes);
	if (ioctl(instance, CKM_IOC_REVOKE, 0UL)) {
		perror("revoke");
		close(instance);
		return 1;
	}
	for (attempt = 0; attempt < 500; attempt++) {
		q = (struct ckm_query) { .version = CKM_ABI_VERSION, .size = sizeof(q) };
		if (ioctl(instance, CKM_IOC_QUERY, &q)) {
			perror("query during drain");
			close(instance);
			return 1;
		}
		if (!q.tasks && !q.mms && !q.nodes)
			break;
		usleep(10000);
	}
	printf("drain tasks=%u mms=%u nodes=%u\n", q.tasks, q.mms, q.nodes);
	if (!clock_gettime(CLOCK_MONOTONIC, &finish))
		printf("drain_poll_elapsed_ns=%lld (includes 10ms polling granularity)\n",
		       (long long)(finish.tv_sec - start.tv_sec) * 1000000000LL +
		       finish.tv_nsec - start.tv_nsec);
	close(instance);
	if (attempt == 500) {
		fprintf(stderr, "drain timeout (references remain)\n");
		return 1;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
