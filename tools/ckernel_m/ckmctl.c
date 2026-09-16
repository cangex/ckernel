// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include "../../include/uapi/linux/ckernel_m.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	int security = argc > 1 && (!strcmp(argv[1], "--security") ||
		!strcmp(argv[1], "--vfs-open-security"));
	int open_vfs = argc > 1 && (!strcmp(argv[1], "--vfs-open") ||
		!strcmp(argv[1], "--vfs-open-security"));
	int vfs = open_vfs || (argc > 1 && !strcmp(argv[1], "--vfs"));
	int program = vfs ? 4 : 2;
	struct ckm_vfs_query vq;
	struct ckm_vfs_open_query oq = {};
	struct ckm_security_query sq = {};

	if (argc <= program) {
		fprintf(stderr, "usage: %s MAX_NODES PROGRAM [ARGS...] (0 = Core only)\n", argv[0]);
		fprintf(stderr, "       %s --vfs READONLY_ROOT MAX_ENTRIES PROGRAM [ARGS...]\n", argv[0]);
		fprintf(stderr, "       %s --vfs-open READONLY_ROOT MAX_ENTRIES PROGRAM [ARGS...]\n", argv[0]);
		fprintf(stderr, "       %s --security PROGRAM [ARGS...]\n", argv[0]);
		fprintf(stderr, "       %s --vfs-open-security READONLY_ROOT MAX_ENTRIES PROGRAM [ARGS...]\n", argv[0]);
		return 2;
	}
	errno = 0;
	n = 0;
	if (!security || vfs) {
		n = strtoul(argv[vfs ? 3 : 1], &end, 10);
		if (errno || end == argv[vfs ? 3 : 1] || *end ||
		    n > (vfs ? CKM_VFS_MAX_ENTRIES : 4096) || (vfs && !n))
			return 2;
	}
	r.max_nodes = vfs ? 0 : n;
	r.features = vfs ? CKM_FEATURE_VFS : n ? CKM_FEATURE_MAPLE : 0;
	if (open_vfs)
		r.features |= CKM_FEATURE_VFS_OPEN;
	if (security)
		r.features |= CKM_FEATURE_SECURITY;
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
	if (vfs) {
		struct ckm_vfs_root root = { .version = CKM_ABI_VERSION,
			.size = sizeof(root), .capacity = n };

		root.fd = open(argv[2], O_PATH | O_CLOEXEC);
		if (root.fd < 0 || ioctl(instance, CKM_IOC_VFS_ROOT, &root)) {
			perror("register VFS root");
			if (root.fd >= 0)
				close(root.fd);
			close(instance);
			return 1;
		}
		close(root.fd);
	}
	child = fork();
	if (!child) {
		if (ioctl(instance, CKM_IOC_BIND, 0UL)) {
			perror("bind");
			_exit(125);
		}
		execvp(argv[program], argv + program);
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
	if (vfs) {
		vq = (struct ckm_vfs_query){ .version = CKM_ABI_VERSION, .size = sizeof(vq) };
		if (ioctl(instance, CKM_IOC_VFS_QUERY, &vq)) {
			perror("VFS query"); close(instance); return 1;
		}
		printf("vfs_hits=%llu vfs_native=%llu vfs_retries=%llu vfs_cached=%u vfs_payload_bytes=%llu\n",
		       vq.hits, vq.native, vq.retries, vq.cached, vq.metadata_payload_bytes);
	}
	if (open_vfs) {
		oq = (struct ckm_vfs_open_query){ .version = CKM_ABI_VERSION, .size = sizeof(oq) };
		if (ioctl(instance, CKM_IOC_VFS_OPEN_QUERY, &oq)) {
			perror("VFS open query"); close(instance); return 1;
		}
		printf("vfs_open_hits=%llu native=%llu released=%llu\n", oq.hits, oq.native, oq.released);
	}
	if (security) {
		sq = (struct ckm_security_query){ .version = CKM_ABI_VERSION, .size = sizeof(sq) };
		if (ioctl(instance, CKM_IOC_SECURITY_QUERY, &sq)) {
			perror("security query"); close(instance); return 1;
		}
		printf("signal_hits=%llu signal_native=%llu label_loans=%llu label_native=%llu label_released=%llu open_borrowed=%llu learned=%llu full=%llu contended=%llu stale=%llu management_payload_bytes=%llu\n",
		       sq.signal_hits, sq.signal_native, sq.label_hits, sq.label_native,
		       sq.label_released, sq.open_borrowed, sq.label_learned, sq.full,
		       sq.contended, sq.stale, sq.management_bytes);
	}
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
		if (vfs) {
			vq = (struct ckm_vfs_query){ .version = CKM_ABI_VERSION, .size = sizeof(vq) };
			if (ioctl(instance, CKM_IOC_VFS_QUERY, &vq)) {
				perror("VFS drain query"); close(instance); return 1;
			}
		}
		if (open_vfs) {
			oq = (struct ckm_vfs_open_query){ .version = CKM_ABI_VERSION, .size = sizeof(oq) };
			if (ioctl(instance, CKM_IOC_VFS_OPEN_QUERY, &oq)) {
				perror("VFS open drain query"); close(instance); return 1;
			}
		}
		if (security) {
			sq = (struct ckm_security_query){ .version = CKM_ABI_VERSION, .size = sizeof(sq) };
			if (ioctl(instance, CKM_IOC_SECURITY_QUERY, &sq)) {
				perror("security drain query"); close(instance); return 1;
			}
		}
		if (!q.tasks && !q.mms && !q.nodes && (!vfs || (vq.stopped && !vq.cached)) &&
		    (!open_vfs || oq.hits == oq.released) &&
		    (!security || (q.state >= CKM_DRAINING && sq.label_hits == sq.label_released)))
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
