// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static int below(const char *a, const char *b)
{
	size_t n = strlen(b);
	return !strncmp(a, b, n) && (!a[n] || a[n] == '/' || !strcmp(b, "/"));
}

static unsigned int bucket(uint64_t id)
{
	return ((id * 11400714819323198485ULL) >> 55) & 511;
}

static void reindex(struct cis_context *ctx)
{
	unsigned int i, p;
	memset(ctx->registry_index, 0, sizeof(ctx->registry_index));
	for (i=0;i<CIS_MAX_ROOTS;i++) if (ctx->roots[i].used) {
		p=bucket(ctx->roots[i].id);
		while (ctx->registry_index[p]) p=(p+1)&511;
		ctx->registry_index[p]=i+1;
	}
}

struct cis_root *cis_registry_lookup(struct cis_context *ctx,uint64_t id,uint64_t generation)
{
	unsigned int p=bucket(id), n;
	for (n=0;n<512;n++,p=(p+1)&511) {
		struct cis_root *r;
		if (!ctx->registry_index[p]) return NULL;
		r=&ctx->roots[ctx->registry_index[p]-1];
		if (r->id==id) return r->generation==generation && r->ready ? r : NULL;
	}
	return NULL;
}

int cis_registry_add(struct cis_context *ctx, int fd, const char *name,
		     struct cis_root **out)
{
	struct stat st;
	struct statfs fs;
	struct cis_root *r = NULL;
	char link[64], path[4096];
	ssize_t n;
	unsigned int i;
	if (fd < 0 || fstat(fd, &st) || fstatfs(fd, &fs)) return -EBADF;
	if (!S_ISDIR(st.st_mode) || fs.f_type != CGROUP2_SUPER_MAGIC) return -EOPNOTSUPP;
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	n = readlink(link, path, sizeof(path) - 1);
	if (n < 0 || n == sizeof(path) - 1) return -EINVAL;
	path[n] = 0;
	if (strstr(path, " (deleted)")) return -ENOENT;
	if (!below(path, "/sys/fs/cgroup")) return -EXDEV;
	for (i = 0; i < CIS_MAX_ROOTS; i++) {
		struct cis_root *x = &ctx->roots[i];
		if (!x->used) { if (!r) r = x; continue; }
		/* One host cgroup2 view is supported; mount aliases cannot bypass overlap. */
		if (x->dev != st.st_dev) return -EXDEV;
		if (x->id == st.st_ino || below(path, x->path) || below(x->path, path))
			return -EEXIST;
	}
	if (!r) return -ENOSPC;
	memset(r, 0, sizeof(*r));
	for (i = 0; i < 5; i++) r->metric_fd[i] = -1;
	r->fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (r->fd < 0) return -errno;
	r->id = st.st_ino;
	r->dev = st.st_dev;
	r->generation = ctx->boot_generation + ++ctx->serial;
	r->epoch = ctx->epoch;
	r->state = CIS_WARMUP;
	snprintf(r->name, sizeof(r->name), "%s", name);
	snprintf(r->path, sizeof(r->path), "%s", path);
	r->next_ns = cis_clock_ns() + (ctx->active % 1000) * 1000000ULL;
	if (cis_metrics_open(r)) { close(r->fd); return -EIO; }
	r->used = 1;
	if (cis_capture_root(ctx, r, 1)) {
		cis_metrics_close(r); close(r->fd); r->used = 0; return -EIO;
	}
	r->ready = 1;
	reindex(ctx);
	ctx->active++;
	*out = r;
	return 0;
}

int cis_registry_remove(struct cis_context *ctx, uint64_t id, uint64_t generation)
{
	unsigned int i;
	for (i = 0; i < CIS_MAX_ROOTS; i++) {
		struct cis_root *r = &ctx->roots[i];
		if (!r->used || r->id != id || r->generation != generation) continue;
		r->ready = 0;
		if (r->state == CIS_DIAGNOSING && ctx->diagnostic) ctx->diagnostic--;
		cis_capture_diagnostic(ctx, r, 0);
		cis_capture_root(ctx, r, 0);
		cis_report(ctx, "unregister", r, "pending intervals are incomplete, not zero");
		cis_metrics_close(r);
		close(r->fd);
		r->used = 0;
		reindex(ctx);
		ctx->active--;
		return 0;
	}
	return -ENOENT;
}

void cis_registry_destroy(struct cis_context *ctx)
{
	unsigned int i;
	for (i = 0; i < CIS_MAX_ROOTS; i++)
		if (ctx->roots[i].used)
			cis_registry_remove(ctx, ctx->roots[i].id, ctx->roots[i].generation);
}
