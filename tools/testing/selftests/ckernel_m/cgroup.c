// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#if __has_include("../../../../include/uapi/linux/ckernel_m.h")
#include "../../../../include/uapi/linux/ckernel_m.h"
#define HAVE_CKM_ABI
#endif

#ifndef HAVE_CKM_ABI
int test_main(int argc, char **argv)
{
	(void)argc; (void)argv;
	return SKIP;
}
#else
static int put(const char *group, const char *file, const char *value)
{
	char path[256];
	int fd, rc;

	snprintf(path, sizeof(path), "%s/%s", group, file);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	rc = write(fd, value, strlen(value)) == (ssize_t)strlen(value) ? 0 : -1;
	close(fd);
	return rc;
}

static int in_groups(const char *a, const char *b, const char *worker)
{
	struct ckm_create r = { .version = CKM_ABI_VERSION, .size = sizeof(r),
		.features = CKM_FEATURE_MAPLE, .max_nodes = 128 };
	struct ckm_query q;
	int control, fd, move, attempt;
	pid_t child;

	CHECK(!put(a, "cgroup.procs", "0"));
	control = open("/dev/ckernel-m", O_RDWR);
	CHECK(control >= 0);
	for (move = 0; move < 2; move++) {
		fd = ioctl(control, CKM_IOC_CREATE, &r);
		if (fd < 0 && errno == EOPNOTSUPP) {
			r.features = 0;
			r.max_nodes = 0;
			fd = ioctl(control, CKM_IOC_CREATE, &r);
		}
		CHECK(fd >= 0);
		child = fork();
		if (!child) {
			if (put(b, "cgroup.procs", "0"))
				_exit(1);
			_exit(ioctl(fd, CKM_IOC_BIND, 0UL) < 0 && errno == EXDEV ? 0 : 1);
		}
		CHECK(!child_result(child));
		child = fork();
		if (!child) {
			if (ioctl(fd, CKM_IOC_BIND, 0UL) ||
			    (move && put(b, "cgroup.procs", "0")))
				_exit(1);
			execl(worker, worker, NULL);
			_exit(1);
		}
		CHECK(!child_result(child));
		q = (struct ckm_query) { .version = CKM_ABI_VERSION, .size = sizeof(q) };
		CHECK(!ioctl(fd, CKM_IOC_QUERY, &q));
		printf("# nonroot-memcg move=%d features=%u hits=%llu fallback=%llu nodes=%u\n",
		       move, q.features, q.hits_cpu + q.hits_numa, q.fallbacks, q.nodes);
		if (r.features && move)
			CHECK(!q.hits_cpu && !q.hits_numa && q.fallbacks);
		if (r.features && !move)
			CHECK(q.hits_cpu + q.hits_numa);
		CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0UL));
		for (attempt = 0; attempt < 500; attempt++) {
			q = (struct ckm_query) { .version = CKM_ABI_VERSION, .size = sizeof(q) };
			CHECK(!ioctl(fd, CKM_IOC_QUERY, &q));
			if (!q.tasks && !q.mms && !q.nodes)
				break;
			usleep(10000);
		}
		close(fd);
		CHECK(attempt < 500);
	}
	close(control);
	return 0;
}

int test_main(int argc, char **argv)
{
	char a[128], b[128], worker[512], *slash;
	int rc, length;
	pid_t child;

	(void)argc;
	if (!getenv("CKM_ISOLATED_GUEST") || access("/cg/cgroup.controllers", R_OK) ||
	    access("/dev/ckernel-m", R_OK))
		return SKIP;
	snprintf(a, sizeof(a), "/cg/ckm-%d-a", getpid());
	snprintf(b, sizeof(b), "/cg/ckm-%d-b", getpid());
	CHECK(!mkdir(a, 0755));
	if (mkdir(b, 0755)) {
		rmdir(a);
		return 1;
	}
	CHECK(!put(a, "memory.max", "67108864"));
	CHECK(!put(b, "memory.max", "67108864"));
	length = snprintf(worker, sizeof(worker), "%s", argv[0]);
	if (length < 0 || (size_t)length >= sizeof(worker) - 32) {
		rmdir(a);
		rmdir(b);
		return 1;
	}
	slash = strrchr(worker, '/');
	if (slash)
		strcpy(slash + 1, "maple_lifecycle");
	else
		strcpy(worker, "./maple_lifecycle");
	child = fork();
	if (!child)
		_exit(in_groups(a, b, worker));
	rc = child_result(child);
	if (rmdir(a) || rmdir(b))
		rc = 1;
	return rc;
}
#endif
