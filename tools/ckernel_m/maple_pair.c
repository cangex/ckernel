// SPDX-License-Identifier: GPL-2.0
/* Same-kernel target/bystander probe. Only run in a disposable isolated VM. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../include/uapi/linux/ckernel_m.h"

#define MAX_SAMPLES 32768
#define MAX_THREADS 4096
#define RUN_NS 1000000000ULL
#define LOG_REGION (512UL << 10)
#define CHECK(x) do { if (!(x)) { perror(#x); exit(1); } } while (0)
static const char *mode, *scenario, *layout;
static int round_no;
static char line_prefix[256];
static int log_fd;
static unsigned int log_region;
static size_t log_used;
static uint64_t run_ns = RUN_NS;
static int live_inventory;
static int record_timeline;

static void emit(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void emit(const char *format, ...)
{
	char line[4096];
	va_list args;
	int prefix_len = snprintf(line, sizeof(line), "%s", line_prefix), length;

	va_start(args, format);
	length = vsnprintf(line + prefix_len, sizeof(line) - prefix_len, format, args);
	va_end(args);
	CHECK(length >= 0 && (size_t)(prefix_len + length) < sizeof(line));
	CHECK(log_used + prefix_len + length < LOG_REGION);
	/* Shared memfd positions are not an atomic multi-writer append API.
	 * Each single-threaded producer owns a disjoint, prefaulted region.
	 */
	CHECK(pwrite(log_fd, line, prefix_len + length,
		     log_region * LOG_REGION + log_used) == prefix_len + length);
	log_used += prefix_len + length;
}

static uint64_t now(void)
{
	struct timespec t;
	CHECK(!clock_gettime(CLOCK_MONOTONIC_RAW, &t));
	return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static uint64_t usec(struct timeval t)
{
	return (uint64_t)t.tv_sec * 1000000 + t.tv_usec;
}

static void put(const char *group, const char *file, const char *value)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", group, file);
	fd = open(path, O_WRONLY);
	CHECK(fd >= 0);
	CHECK(write(fd, value, strlen(value)) == (ssize_t)strlen(value));
	CHECK(!close(fd));
}

static void affinity(int cpu, int sibling)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sibling >= 0)
		CPU_SET(sibling, &set);
	CHECK(!sched_setaffinity(0, sizeof(set), &set));
}

static void prefix(const char *type, const char *role)
{
	snprintf(line_prefix, sizeof(line_prefix), "CKM_PAIR type=%s round=%d mode=%s scenario=%s layout=%s role=%s ",
	       type, round_no, mode, scenario, layout, role);
}

static int cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static void split_merge(char *p, size_t page, unsigned int pages)
{
	unsigned int n;

	for (n = 0; n < pages; n += 2)
		CHECK(!mprotect(p + n * page, page, PROT_READ));
	CHECK(!mprotect(p, pages * page, PROT_READ | PROT_WRITE));
}

static void wait_ok(pid_t pid)
{
	int status;

	CHECK(pid > 0);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status));
}

static void worker(const char *role, int cpu, int ready, int go)
{
	static uint64_t samples[MAX_SAMPLES];
	static uint64_t begins[MAX_SAMPLES];
	static uint64_t sorted[MAX_SAMPLES];
	uint64_t *ranked = samples;
	struct rusage before, after, children_before, children_after;
	unsigned int count = 0, pages = 256;
	int target = !strcmp(role, "target");
	int follow = !target && !strcmp(layout, "pair");
	size_t page = (size_t)sysconf(_SC_PAGESIZE);
	char *p, ch;
	uint64_t start, end, cold = 0;

	affinity(cpu, -1);
	if (target && !strcmp(scenario, "exhaust"))
		pages = 1024;
	p = mmap(NULL, pages * page, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED);
	CHECK(write(ready, "R", 1) == 1);
	CHECK(read(go, &ch, 1) == 1 && ch == 'G');
	if (follow)
		CHECK(!fcntl(go, F_SETFL, O_NONBLOCK));
	CHECK(!getrusage(RUSAGE_SELF, &before));
	CHECK(!getrusage(RUSAGE_CHILDREN, &children_before));
	start = now();
	CHECK(write(ready, "B", 1) == 1);
	do {
		uint64_t begin = now();

		if (target && !strcmp(scenario, "migration"))
			affinity(cpu + (count & 1), -1);
		if (target && !strcmp(scenario, "exit")) {
			pid_t child[2];
			int n;

			for (n = 0; n < 2; n++) {
				child[n] = fork();
				if (!child[n]) {
					split_merge(p, page, pages);
					_exit(0);
				}
				CHECK(child[n] > 0);
			}
			for (n = 0; n < 2; n++)
				wait_ok(child[n]);
		} else if (target && !strcmp(scenario, "pressure")) {
			size_t bytes = 40UL << 20, pos;
			volatile char *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

			CHECK(memory != MAP_FAILED);
			for (pos = 0; pos < bytes; pos += page)
				memory[pos] = (char)pos;
			split_merge(p, page, pages);
			CHECK(!munmap((void *)memory, bytes));
		} else {
			split_merge(p, page, pages);
		}
		end = now();
		if (!count)
			cold = end - begin;
		CHECK(count < MAX_SAMPLES);
		if (record_timeline)
			begins[count] = begin;
		samples[count++] = end - begin;
		if (follow) {
			ssize_t got = read(go, &ch, 1);

			if (got == 1) { CHECK(ch == 'S'); break; }
			CHECK(got == -1 && errno == EAGAIN);
		}
	} while (follow || end - start < run_ns);
	if (follow)
		CHECK(!fcntl(go, F_SETFL, 0));
	CHECK(!getrusage(RUSAGE_SELF, &after));
	CHECK(!getrusage(RUSAGE_CHILDREN, &children_after));
	CHECK(write(ready, "D", 1) == 1);
	CHECK(read(go, &ch, 1) == 1 && ch == 'E');
	if (record_timeline) {
		unsigned int first, last;

		for (first = 0; first < count; first = last) {
			uint64_t max = 0;

			for (last = first; last < count &&
			     begins[last] - begins[first] < 100000000ULL; last++)
				if (samples[last] > max)
					max = samples[last];
			prefix("timeblock", role);
			emit("start_ns=%llu end_ns=%llu operations=%u max_ns=%llu\n",
			       (unsigned long long)begins[first],
			       (unsigned long long)(begins[last - 1] + samples[last - 1]),
			       last - first, (unsigned long long)max);
		}
		memcpy(sorted, samples, count * sizeof(*samples));
		ranked = sorted;
	}
	qsort(ranked, count, sizeof(ranked[0]), cmp);
	prefix("latency", role);
	emit("operations=%u duration_ns=%llu start_ns=%llu end_ns=%llu cold_ns=%llu p50_ns=%llu p95_ns=%llu p99_ns=%llu "
	       "max_ns=%llu user_us=%llu system_us=%llu children_user_us=%llu children_system_us=%llu "
	       "maxrss_kib=%ld nvcsw=%ld nivcsw=%ld\n", count,
	       (unsigned long long)(end - start), (unsigned long long)start,
	       (unsigned long long)end, (unsigned long long)cold,
	       (unsigned long long)ranked[(count * 50 + 99) / 100 - 1],
	       (unsigned long long)ranked[(count * 95 + 99) / 100 - 1],
	       (unsigned long long)ranked[(count * 99 + 99) / 100 - 1],
	       (unsigned long long)ranked[count - 1],
	       (unsigned long long)(usec(after.ru_utime) - usec(before.ru_utime)),
	       (unsigned long long)(usec(after.ru_stime) - usec(before.ru_stime)),
	       (unsigned long long)(usec(children_after.ru_utime) - usec(children_before.ru_utime)),
	       (unsigned long long)(usec(children_after.ru_stime) - usec(children_before.ru_stime)),
	       after.ru_maxrss, after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw);
	if (record_timeline) {
		unsigned int n;
		uint64_t threshold = ranked[(count * 99 + 99) / 100 - 1];

		for (n = 0; n < count; n++)
			if (samples[n] >= threshold) {
				prefix("tail_operation", role);
				emit("index=%u start_ns=%llu end_ns=%llu latency_ns=%llu threshold_ns=%llu\n",
				       n, (unsigned long long)begins[n],
				       (unsigned long long)(begins[n] + samples[n]),
				       (unsigned long long)samples[n], (unsigned long long)threshold);
			}
	}
	CHECK(!munmap(p, pages * page));
}

static void query(int fd, const char *role)
{
	struct ckm_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
	struct ckm_diagnostics d = { .version = CKM_ABI_VERSION, .size = sizeof(d) };
	unsigned int n;
	uint64_t sum = 0;

	CHECK(!ioctl(fd, CKM_IOC_QUERY, &q));
	prefix("inventory", role);
	emit("cookie=%llu nodes=%u cached=%llu borrowed=%llu retired=%llu pending=%llu node_bytes=%llu "
	       "metadata_bytes=%llu hits_cpu=%llu hits_numa=%llu misses=%llu fallbacks=%llu\n",
	       q.cookie, q.nodes, q.cached, q.borrowed, q.retired, q.pending_metadata, q.node_bytes,
	       q.metadata_bytes, q.hits_cpu, q.hits_numa, q.misses, q.fallbacks);
	if (ioctl(fd, CKM_IOC_DIAGNOSTICS, &d)) {
		CHECK(errno == ENOTTY);
		prefix("diagnostics_unavailable", role);
		emit("reason=older_kernel\n");
		return;
	}
	for (n = 0; n < CKM_FB_COUNT; n++) {
		sum += d.reasons[n];
		if (d.reasons[n]) {
			prefix("reason", role);
			emit("id=%u count=%llu\n", n, d.reasons[n]);
		}
	}
	/* Worker allocation has quiesced; do not waive accounting consistency. */
	CHECK(sum == q.fallbacks);
	prefix("diagnostics", role);
	emit("bulk_calls=%llu bulk_requested=%llu bulk_completed=%llu bulk_failed=%llu "
	       "registered=%llu alloc_failed=%llu dispose_inactive=%llu dispose_full=%llu\n",
	       d.bulk_calls, d.bulk_requested, d.bulk_completed, d.bulk_failed,
	       d.registered, d.alloc_failed, d.dispose_inactive, d.dispose_full);
}

static void supervise(const char *self, const char *role, const char *group,
		      int cpu, int ready, int go)
{
	struct ckm_create c = { .version = CKM_ABI_VERSION, .size = sizeof(c) };
	char cpu_s[16], ready_s[16], go_s[16];
	int fd = -1, control, attempt;
	pid_t child;

	log_region = !strcmp(role, "target") ? 1 : 3;
	log_used = 0;
	affinity(cpu, cpu + 1);
	put(group, "cgroup.procs", "0");
	if (strcmp(mode, "native")) {
		if (!strcmp(mode, "maple")) {
			c.features = CKM_FEATURE_MAPLE;
			c.max_nodes = !strcmp(role, "target") && !strcmp(scenario, "exhaust") ? 4 : 128;
		}
		control = open("/dev/ckernel-m", O_RDWR);
		CHECK(control >= 0);
		fd = ioctl(control, CKM_IOC_CREATE, &c);
		CHECK(fd >= 0);
		CHECK(!close(control));
	}
	snprintf(cpu_s, sizeof(cpu_s), "%d", cpu);
	snprintf(ready_s, sizeof(ready_s), "%d", ready);
	snprintf(go_s, sizeof(go_s), "%d", go);
	child = fork();
	if (!child) {
		if (fd >= 0)
			CHECK(!ioctl(fd, CKM_IOC_BIND, 0UL));
		execl(self, self, "--worker", role, cpu_s, ready_s, go_s, NULL);
		_exit(127);
	}
	if (live_inventory && fd >= 0) {
		int status;
		pid_t finished;
		unsigned int tick = 0;

		/* Querying records takes its owner lock: this is diagnostic-only. */
		affinity(3, -1);
		while (!(finished = waitpid(child, &status, WNOHANG))) {
			struct ckm_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
			uint64_t begin = now(), end;

			CHECK(!ioctl(fd, CKM_IOC_QUERY, &q));
			end = now();
			prefix("live_inventory", role);
			emit("tick=%u start_ns=%llu end_ns=%llu nodes=%u cached=%llu borrowed=%llu "
			       "retired=%llu pending=%llu hits=%llu misses=%llu fallbacks=%llu\n",
			       tick++, (unsigned long long)begin, (unsigned long long)end,
			       q.nodes, q.cached, q.borrowed, q.retired, q.pending_metadata,
			       q.hits_cpu + q.hits_numa, q.misses, q.fallbacks);
			usleep(10000);
		}
		CHECK(finished == child && WIFEXITED(status) && !WEXITSTATUS(status));
	} else {
		wait_ok(child);
	}
	if (fd >= 0) {
		uint64_t start = now();

		query(fd, role);
		CHECK(!ioctl(fd, CKM_IOC_REVOKE, 0UL));
		for (attempt = 0; attempt < 1000; attempt++) {
			struct ckm_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };

			CHECK(!ioctl(fd, CKM_IOC_QUERY, &q));
			if (!q.tasks && !q.mms && !q.nodes)
				break;
			usleep(10000);
		}
		CHECK(attempt < 1000);
		prefix("drain", role);
		emit("elapsed_ns=%llu final_nodes=0\n", (unsigned long long)(now() - start));
		CHECK(!close(fd));
	}
}

struct thread { int pid; uint64_t start, runtime; char name[64]; };
struct snapshot {
	int nr;
	struct thread threads[MAX_THREADS];
	unsigned long long cpu[8];
};
static struct snapshot before, running, drained;

static void snapshot(struct snapshot *s)
{
	DIR *dir = opendir("/proc");
	struct dirent *entry;
	FILE *stat = fopen("/proc/stat", "r");

	CHECK(dir != NULL);
	CHECK(stat != NULL);
	CHECK(fscanf(stat, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
		&s->cpu[0], &s->cpu[1], &s->cpu[2], &s->cpu[3],
		&s->cpu[4], &s->cpu[5], &s->cpu[6], &s->cpu[7]) == 8);
	fclose(stat);
	s->nr = 0;
	while ((entry = readdir(dir))) {
		char path[128], buf[2048], *tail, *token, *save;
		unsigned long long runtime, delay, slices;
		uint64_t flags = 0, start = 0;
		int field = 3, pid = atoi(entry->d_name);
		FILE *f;

		if (pid <= 0)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/stat", pid);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (!fgets(buf, sizeof(buf), f)) { fclose(f); continue; }
		fclose(f);
		tail = strrchr(buf, ')');
		if (!tail)
			continue;
		*tail++ = 0;
		for (token = strtok_r(tail, " ", &save); token; token = strtok_r(NULL, " ", &save), field++) {
			if (field == 9) flags = strtoull(token, NULL, 10);
			if (field == 22) { start = strtoull(token, NULL, 10); break; }
		}
		if (!(flags & 0x00200000UL))
			continue;
		snprintf(path, sizeof(path), "/proc/%d/schedstat", pid);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (fscanf(f, "%llu %llu %llu", &runtime, &delay, &slices) != 3) {
			fclose(f); continue;
		}
		fclose(f);
		CHECK(s->nr < MAX_THREADS);
		s->threads[s->nr] = (struct thread) { .pid = pid, .start = start, .runtime = runtime };
		snprintf(s->threads[s->nr].name, sizeof(s->threads[s->nr].name), "%s", strchr(buf, '(') + 1);
		s->nr++;
	}
	closedir(dir);
	CHECK(s->nr > 0);
}

static void background(const struct snapshot *a, const struct snapshot *b, const char *interval)
{
	uint64_t sum = 0;
	int n, m, matched = 0;

	for (n = 0; n < b->nr; n++) {
		for (m = 0; m < a->nr; m++)
			if (a->threads[m].pid == b->threads[n].pid && a->threads[m].start == b->threads[n].start) {
				uint64_t delta = b->threads[n].runtime - a->threads[m].runtime;

				sum += delta;
				matched++;
				if (delta) {
					prefix("kthread", "system");
					emit("interval=%s name=%s pid=%d runtime_ns=%llu\n", interval,
					       b->threads[n].name, b->threads[n].pid, (unsigned long long)delta);
				}
				break;
			}
	}
	prefix("background", "system");
	emit("interval=%s matched_cpu_ns=%llu missing_before=%d new_after=%d\n", interval,
	       (unsigned long long)sum, a->nr - matched, b->nr - matched);
	prefix("cpu_ticks", "system");
	emit("interval=%s hz=%ld system=%llu irq=%llu softirq=%llu steal=%llu\n", interval,
	       sysconf(_SC_CLK_TCK), b->cpu[2] - a->cpu[2], b->cpu[5] - a->cpu[5],
	       b->cpu[6] - a->cpu[6], b->cpu[7] - a->cpu[7]);
}

static void memory(const char *group, const char *role, const char *point)
{
	const char *files[] = { "memory.current", "memory.peak", "memory.stat", "memory.events" };
	unsigned int n;

	for (n = 0; n < sizeof(files) / sizeof(files[0]); n++) {
		char path[256], key[128];
		unsigned long long value;
		FILE *f;

		snprintf(path, sizeof(path), "%s/%s", group, files[n]);
		f = fopen(path, "r");
		CHECK(f != NULL);
		if (n < 2) {
			CHECK(fscanf(f, "%llu", &value) == 1);
			prefix("memory", role);
			emit("point=%s key=%s value=%llu\n", point, files[n], value);
		} else {
			while (fscanf(f, "%127s %llu", key, &value) == 2) {
				prefix("memory", role);
				emit("point=%s key=%s value=%llu\n", point, key, value);
				if (!strcmp(key, "oom") || !strcmp(key, "oom_kill"))
					CHECK(!value);
			}
		}
		fclose(f);
	}
}

int main(int argc, char **argv)
{
	const char *roles[] = { "target", "bystander" };
	char groups[2][128], ch;
	int ready[2][2], go[2][2], active[2], n;
	pid_t children[2];
	uint64_t start, mid, end;

	setvbuf(stdout, NULL, _IONBF, 0);
	CHECK(getenv("CKM_ISOLATED_GUEST"));
	mode = getenv("CKM_PAIR_MODE"); scenario = getenv("CKM_PAIR_SCENARIO");
	layout = getenv("CKM_PAIR_LAYOUT");
	CHECK(mode && scenario && layout && getenv("CKM_PAIR_ROUND"));
	CHECK(!strcmp(mode, "native") || !strcmp(mode, "core") || !strcmp(mode, "maple"));
	CHECK(!strcmp(scenario, "steady") || !strcmp(scenario, "exhaust") ||
	      !strcmp(scenario, "migration") || !strcmp(scenario, "exit") || !strcmp(scenario, "pressure"));
	CHECK(!strcmp(layout, "target-only") || !strcmp(layout, "bystander-only") || !strcmp(layout, "pair"));
	round_no = atoi(getenv("CKM_PAIR_ROUND"));
	if (getenv("CKM_PAIR_SECONDS")) {
		char *end;
		unsigned long seconds = strtoul(getenv("CKM_PAIR_SECONDS"), &end, 10);

		CHECK(!*end && seconds >= 1 && seconds <= 30);
		run_ns = seconds * 1000000000ULL;
	}
	live_inventory = getenv("CKM_PAIR_LIVE") != NULL;
	record_timeline = live_inventory || getenv("CKM_PAIR_TIMELINE") != NULL;
	alarm(90);
	if (argc == 6 && !strcmp(argv[1], "--worker")) {
		CHECK(getenv("CKM_PAIR_LOG_FD"));
		log_fd = atoi(getenv("CKM_PAIR_LOG_FD"));
		log_region = !strcmp(argv[2], "target") ? 2 : 4;
		worker(argv[2], atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
		return 0;
	}
	CHECK(argc == 1);
	affinity(3, -1);
	/* Keep serial-console traffic out of both measurement intervals. The
	 * controller prefaults the fixed log buffer before creating test cgroups.
	 */
	log_fd = syscall(SYS_memfd_create, "ckm-pair-log", 0);
	CHECK(log_fd >= 0 && !ftruncate(log_fd, 4UL << 20));
	{
		char value[32];
		void *buffer = mmap(NULL, 4UL << 20, PROT_READ | PROT_WRITE, MAP_SHARED, log_fd, 0);

		CHECK(buffer != MAP_FAILED);
		memset(buffer, 0, 4UL << 20);
		CHECK(!munmap(buffer, 4UL << 20));
		snprintf(value, sizeof(value), "%d", log_fd);
		CHECK(!setenv("CKM_PAIR_LOG_FD", value, 1));
	}
	active[0] = strcmp(layout, "bystander-only") != 0;
	active[1] = strcmp(layout, "target-only") != 0;
	for (n = 0; n < 2; n++) {
		if (!active[n])
			continue;
		snprintf(groups[n], sizeof(groups[n]), "/cg/pair-%d-%d", getpid(), n);
		CHECK(!mkdir(groups[n], 0755));
		put(groups[n], "memory.max", "134217728");
		if (!n && !strcmp(scenario, "pressure"))
			put(groups[n], "memory.high", "33554432");
		CHECK(!pipe(ready[n]) && !pipe(go[n]));
		children[n] = fork();
		CHECK(children[n] >= 0);
		if (!children[n]) {
			close(ready[n][0]); close(go[n][1]);
			supervise(argv[0], roles[n], groups[n], n ? 2 : 0, ready[n][1], go[n][0]);
			_exit(0);
		}
		close(ready[n][1]); close(go[n][0]);
		CHECK(read(ready[n][0], &ch, 1) == 1 && ch == 'R');
		memory(groups[n], roles[n], "ready");
	}
	snapshot(&before);
	start = now();
	/* Start the bystander first and acknowledge its measurement boundary. */
	for (n = 1; n >= 0; n--)
		if (active[n]) {
			CHECK(write(go[n][1], "G", 1) == 1);
			CHECK(read(ready[n][0], &ch, 1) == 1 && ch == 'B');
		}
	if (active[0]) {
		CHECK(read(ready[0][0], &ch, 1) == 1 && ch == 'D');
		if (active[1]) CHECK(write(go[1][1], "S", 1) == 1);
	}
	if (active[1]) CHECK(read(ready[1][0], &ch, 1) == 1 && ch == 'D');
	mid = now();
	snapshot(&running);
	for (n = 0; n < 2; n++)
		if (active[n]) {
			memory(groups[n], roles[n], "finished");
			CHECK(write(go[n][1], "E", 1) == 1);
		}
	for (n = 0; n < 2; n++)
		if (active[n]) wait_ok(children[n]);
	/* Fixed observation tail; node drain alone is not all background completion. */
	usleep(250000);
	end = now();
	snapshot(&drained);
	background(&before, &running, "foreground");
	background(&running, &drained, "cleanup");
	prefix("window", "system");
	emit("foreground_ns=%llu cleanup_ns=%llu\n", (unsigned long long)(mid - start),
	       (unsigned long long)(end - mid));
	for (n = 0; n < 2; n++)
		if (active[n]) {
			memory(groups[n], roles[n], "drained");
			close(ready[n][0]); close(go[n][1]);
			CHECK(!rmdir(groups[n]));
		}
	{
		char *buffer = mmap(NULL, 4UL << 20, PROT_READ, MAP_SHARED, log_fd, 0);
		unsigned int region;

		CHECK(buffer != MAP_FAILED);
		for (region = 0; region < 5; region++) {
			char *begin = buffer + region * LOG_REGION;
			size_t length = strnlen(begin, LOG_REGION);

			CHECK(length < LOG_REGION && (!length || begin[length - 1] == '\n'));
			CHECK(write(STDOUT_FILENO, begin, length) == (ssize_t)length);
		}
		CHECK(!munmap(buffer, 4UL << 20));
		CHECK(!close(log_fd));
	}
	puts("CKM_PAIR_END failures=0");
	return 0;
}
