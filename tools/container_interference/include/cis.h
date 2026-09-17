/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CIS_H
#define CIS_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define CIS_VERSION 2
#define CIS_MAX_ROOTS 256
#define CIS_MAX_DEPTH 32
#define CIS_MAX_HISTORY 32
#define CIS_SOCKET "/run/cis.sock"
enum cis_command { CIS_REGISTER = 1, CIS_UNREGISTER, CIS_STATUS, CIS_DIAGNOSE, CIS_STOP };
enum cis_state { CIS_WARMUP, CIS_AMBIENT, CIS_SUSPECT, CIS_DIAGNOSING, CIS_COOLDOWN };
struct cis_request {
	uint32_t version, size, command, reserved;
	uint64_t id, generation;
	uint64_t start_ns;
	char name[64];
};
struct cis_reply { int32_t error; uint32_t size; uint64_t id, generation; char text[256]; };
struct cis_metric {
	uint64_t time_ns, usage_us, throttle_us, cpu_wait_us, memory_wait_us;
	uint64_t memory_current, memory_high, memory_oom;
	uint64_t populated;
};
struct cis_root {
	int used, fd, metric_fd[6], config_fd[4], ready, pending, manual_diagnostic;
	int psi_fd[2];
	uint64_t fast_alert_ns;
	uint64_t fast_lock_start_ns;
	unsigned int fast_lock_samples;
	unsigned int diagnostic_kind;
	unsigned int ip_samples, lock_samples, reclaim_samples;
	uint64_t id, generation, epoch, next_ns, deadline_ns, last_diag_ns;
	uint64_t requested_start_ns, diagnostic_start_ns;
	uint64_t config_hash, config_due_ns, policy_epoch;
	uint64_t full_metrics_ns;
	dev_t dev;
	char name[64], path[4096];
	enum cis_state state;
	unsigned int samples, deviations;
	double baseline_wait, baseline_usage;
	struct cis_metric previous;
};
struct cis_context {
	struct cis_root roots[CIS_MAX_ROOTS];
	unsigned short registry_index[512];
	uint64_t boot_generation, serial, epoch, next_export_ns;
	unsigned int active, diagnostic, warmup, queue_cursor;
	unsigned int max_diagnostics, cooldown_s, window_ms, ip_hz;
	unsigned int entry_rate_limit;
	unsigned int metrics_reads, errors, dropped, unknown;
	uint64_t memory_limit, user_cpu_limit_ns, last_process_ns, last_budget_ns;
	int mode, stopping, output_fd, socket_fd;
	int profile_loop;
	int fast_alert, psi_epoll;
	void *capture;
	void *symbols;
};
uint64_t cis_clock_ns(void);
int cis_registry_add(struct cis_context *, int, const char *, struct cis_root **);
int cis_registry_remove(struct cis_context *, uint64_t, uint64_t);
void cis_registry_destroy(struct cis_context *);
struct cis_root *cis_registry_lookup(struct cis_context *, uint64_t, uint64_t);
int cis_metrics_open(struct cis_root *);
/* 0: full snapshot, 1: empty-root CPU/PSI deferred, negative: invalid sample. */
int cis_metrics_read(struct cis_root *, struct cis_metric *);
void cis_metrics_close(struct cis_root *);
int cis_config_epoch(struct cis_context *, struct cis_root *, uint64_t);
void cis_baseline_update(struct cis_context *, struct cis_root *, const struct cis_metric *);
void cis_baseline_idle(struct cis_context *, struct cis_root *, const struct cis_metric *, int);
void cis_diagnostics_tick(struct cis_context *, uint64_t);
void cis_report(struct cis_context *, const char *, const struct cis_root *, const char *);
const char *cis_state_name(enum cis_state);
int cis_capture_start(struct cis_context *, const char *);
int cis_capture_root(struct cis_context *, struct cis_root *, int);
int cis_capture_diagnostic(struct cis_context *, struct cis_root *, int);
int cis_capture_poll(struct cis_context *);
int cis_capture_fd(struct cis_context *);
void cis_capture_stop(struct cis_context *);
void cis_budget_tick(struct cis_context *, uint64_t);
int cis_symbols_load(struct cis_context *);
const char *cis_symbol(struct cis_context *, uint64_t);
void cis_symbols_free(struct cis_context *);
int cis_fast_open(struct cis_context *, struct cis_root *);
void cis_fast_close(struct cis_context *, struct cis_root *);
void cis_fast_poll(struct cis_context *);
#endif
