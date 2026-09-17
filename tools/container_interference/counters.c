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
	static const char *names[] = { "cpu.stat", "cpu.pressure", "memory.pressure", "memory.current", "memory.events", "cgroup.events" };
	unsigned int i;
	for(i=0;i<4;i++) r->config_fd[i]=-1;
	for (i = 0; i < 6; i++) {
		r->metric_fd[i] = openat(r->fd, names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (r->metric_fd[i] < 0) { cis_metrics_close(r); return -errno; }
	}
	return 0;
}

void cis_metrics_close(struct cis_root *r)
{
	unsigned int i;
	for (i = 0; i < 6; i++)
		if (r->metric_fd[i] >= 0) { close(r->metric_fd[i]); r->metric_fd[i] = -1; }
	for (i = 0; i < 4; i++)
		if (r->config_fd[i] >= 0) { close(r->config_fd[i]); r->config_fd[i] = -1; }
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
	if(read_value(r->metric_fd[5],b,sizeof(b)) || field(b,"populated",&m->populated)) return -EIO;
	if (read_value(r->metric_fd[3], b, sizeof(b))) return -EIO;
	errno = 0; m->memory_current = strtoull(b, NULL, 10); if (errno) return -EIO;
	if (read_value(r->metric_fd[4], b, sizeof(b)) ||
	    field(b, "high", &m->memory_high) || field(b, "oom", &m->memory_oom)) return -EIO;
	/* Empty roots retain charged memory; only CPU/PSI freshness is deferred. */
	if (!m->populated && r->full_metrics_ns &&
	    m->time_ns-r->full_metrics_ns<5000000000ULL) return 1;
	if (read_value(r->metric_fd[0], b, sizeof(b)) ||
	    field(b, "usage_usec", &m->usage_us) ||
	    field(b, "throttled_usec", &m->throttle_us)) return -EIO;
	if (read_value(r->metric_fd[1], b, sizeof(b)) || psi(b, &m->cpu_wait_us)) return -EIO;
	if (read_value(r->metric_fd[2], b, sizeof(b)) || psi(b, &m->memory_wait_us)) return -EIO;
	r->full_metrics_ns=m->time_ns;
	return 0;
}

int cis_config_epoch(struct cis_context *ctx,struct cis_root *r,uint64_t now)
{
	static const char *names[]={"cpu.max","memory.max","cpuset.cpus.effective","cpuset.mems.effective"};
	uint64_t hash=1469598103934665603ULL;
	char b[4096];
	unsigned int i,j,missing=0;
	int error=-EIO;
	if(now<r->config_due_ns) return 0;
	r->config_due_ns=now+5000000000ULL;
	for(i=0;i<4;i++) {
		/* Keep a root-relative handle, not a cached value or a path-name identity. */
		if(r->config_fd[i]<0)
			r->config_fd[i]=openat(r->fd,names[i],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
		if(r->config_fd[i]<0) {
			if(errno!=ENOENT && errno!=ENODEV && errno!=EOPNOTSUPP) { error=-errno; goto invalid; }
			missing++; hash^=i+1; continue;
		}
		if(read_value(r->config_fd[i],b,sizeof(b))) {
			close(r->config_fd[i]); r->config_fd[i]=-1;
			goto invalid;
		}
		for(j=0;b[j];j++) { hash^=(unsigned char)b[j]; hash*=1099511628211ULL; }
		hash^=0xff; hash*=1099511628211ULL;
	}
	if(missing) cis_report(ctx,"config_partial",r,"some resource controller settings unavailable; configuration attribution incomplete");
	if(r->config_hash && r->config_hash!=hash) {
		if(r->state==CIS_DIAGNOSING) { cis_capture_diagnostic(ctx,r,0); if(ctx->diagnostic) ctx->diagnostic--; }
		r->epoch++; r->samples=r->deviations=0; r->pending=0;
		r->previous.time_ns=0; r->state=CIS_WARMUP;
		cis_report(ctx,"config_epoch",r,"resource configuration changed; new baseline, no attribution across epochs");
	}
	r->config_hash=hash; return 0;
invalid:
	if(r->state==CIS_DIAGNOSING) {
		cis_capture_diagnostic(ctx,r,0);
		if(ctx->diagnostic) ctx->diagnostic--;
	}
	r->epoch++; r->config_due_ns=0; r->config_hash=0;
	r->samples=r->deviations=0; r->pending=0;
	r->previous.time_ns=0; r->state=CIS_WARMUP;
	return error;
}
