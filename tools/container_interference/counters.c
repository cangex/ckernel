// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "include/cis.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint64_t cis_clock_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int cis_metrics_open(struct cis_root *r)
{
	static const char *names[] = { "cpu.stat", "cpu.pressure", "memory.pressure", "memory.current", "memory.events" };
	unsigned int i;
	for (i = 0; i < 5; i++) {
		r->metric_fd[i] = openat(r->fd, names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (r->metric_fd[i] < 0) { cis_metrics_close(r); return -errno; }
	}
	return 0;
}

void cis_metrics_close(struct cis_root *r)
{
	unsigned int i;
	for (i = 0; i < 5; i++)
		if (r->metric_fd[i] >= 0) { close(r->metric_fd[i]); r->metric_fd[i] = -1; }
}

static int read_value(int fd, char *buf, size_t len)
{
	ssize_t n = pread(fd, buf, len - 1, 0);
	if (n <= 0 || (size_t)n == len - 1) return -EIO;
	buf[n] = 0;
	return 0;
}

static int field(const char *buf, const char *key, uint64_t *value)
{
	const char *s = buf;
	size_t len = strlen(key);
	while (s && *s) {
		if (!strncmp(s, key, len) && (s[len] == ' ' || s[len] == '=')) {
			char *end;
			unsigned long long v;
			errno = 0; v = strtoull(s + len + 1, &end, 10);
			if (errno || end == s + len + 1) return -EINVAL;
			*value = v; return 0;
		}
		s = strchr(s, '\n'); if (s) s++;
	}
	return -ENOENT;
}

static int psi(const char *buf, uint64_t *value)
{
	const char *p;
	if (strncmp(buf, "some ", 5)) return -EINVAL;
	p = strstr(buf, "total=");
	if (!p || (strchr(buf, '\n') && p > strchr(buf, '\n'))) return -EINVAL;
	return field(p, "total", value);
}

int cis_metrics_read(struct cis_root *r, struct cis_metric *m)
{
	char b[4096];
	memset(m, 0, sizeof(*m));
	m->time_ns = cis_clock_ns();
	if (read_value(r->metric_fd[0], b, sizeof(b)) ||
	    field(b, "usage_usec", &m->usage_us) ||
	    field(b, "throttled_usec", &m->throttle_us)) return -EIO;
	if (read_value(r->metric_fd[1], b, sizeof(b)) || psi(b, &m->cpu_wait_us)) return -EIO;
	if (read_value(r->metric_fd[2], b, sizeof(b)) || psi(b, &m->memory_wait_us)) return -EIO;
	if (read_value(r->metric_fd[3], b, sizeof(b))) return -EIO;
	errno = 0; m->memory_current = strtoull(b, NULL, 10); if (errno) return -EIO;
	if (read_value(r->metric_fd[4], b, sizeof(b)) ||
	    field(b, "high", &m->memory_high) || field(b, "oom", &m->memory_oom)) return -EIO;
	return 0;
}
