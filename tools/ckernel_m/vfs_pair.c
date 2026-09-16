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
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../include/uapi/linux/ckernel_m.h"

#define MAX_SAMPLES 262144
#define MAX_THREADS 4096
#define LOG_REGION (512UL << 10)
#define CHECK(x) do { if (!(x)) { perror(#x); exit(1); } } while (0)
static const char *mode, *scenario, *layout;
static int round_no;
static int open_workload;
static char line_prefix[256];
static int log_fd;
static unsigned int log_region;
static size_t log_used;

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
	CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
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
	snprintf(line_prefix, sizeof(line_prefix), "CKM_VFS_PAIR type=%s round=%d mode=%s scenario=%s layout=%s role=%s operation=%s ",
	       type, round_no, mode, scenario, layout, role,
	       open_workload ? "open-fstat-close" : "statx");
}

static int cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static void wait_ok(pid_t pid)
{
	int status;
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status));
}

static char object_root[256];
static unsigned int operations = 200000;
static unsigned int interval_ns;
static int swap_roles;

static void make_objects(const char *root)
{
	char name[320];
	unsigned int n;
	CHECK(!mkdir(root, 0755));
	CHECK(!mount("ckm-vfs-pair", root, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m,mode=0755"));
	for (n = 0; n < 32; n++) {
		int fd;
		snprintf(name, sizeof(name), "%s/file%u", root, n);
		fd = open(name, O_CREAT | O_EXCL | O_WRONLY, 0644);
		CHECK(fd >= 0 && write(fd, "sample", 6) == 6 && !close(fd));
	}
	CHECK(!mount(NULL, root, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
}

static void operation(const char *path)
{
	if (open_workload) {
		struct stat st;
		int fd = open(path, O_RDONLY | O_CLOEXEC);

		CHECK(fd >= 0 && !fstat(fd, &st) && st.st_size == 6 && !close(fd));
	} else {
		struct statx st;

		CHECK(!statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) && st.stx_size == 6);
	}
}

static void worker(const char *role, int cpu, int ready, int go)
{
	static uint64_t samples[MAX_SAMPLES];
	static uint64_t response[MAX_SAMPLES];
	struct rusage before, after;
	char names[32][320], ch;
	unsigned int count, files = !strcmp(scenario, "exhaust") ? 32 : 16;
	uint64_t start, end, first;
	struct timespec pace;
	int target = !strcmp(role, "target");

	affinity(cpu, -1);
	memset(samples, 0, sizeof(samples));
	memset(response, 0, sizeof(response));
	for (count = 0; count < 32; count++)
		snprintf(names[count], sizeof(names[count]), "%s/file%u", object_root, count);
	first = now();
	operation(names[0]);
	first = now() - first;
	for (count = 0; count < 64; count++)
		operation(names[count % files]);
	CHECK(write(ready, "R", 1) == 1 && read(go, &ch, 1) == 1 && ch == 'G');
	CHECK(!getrusage(RUSAGE_SELF, &before));
	CHECK(!clock_gettime(CLOCK_MONOTONIC, &pace));
	start = now();
	CHECK(write(ready, "B", 1) == 1);
	for (count = 0; count < operations; count++) {
		uint64_t begin;

		if (interval_ns) {
			int rc;
			pace.tv_nsec += interval_ns;
			if (pace.tv_nsec >= 1000000000L) {
				pace.tv_sec++;
				pace.tv_nsec -= 1000000000L;
			}
			do {
				rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &pace, NULL);
			} while (rc == EINTR);
			CHECK(!rc);
		}
		begin = now();
		if (target && !strcmp(scenario, "migration") && !(count % 128))
			affinity(cpu + ((count / 128) & 1), -1);
		if (target && !strcmp(scenario, "invalidate") && count == operations / 2) {
			CHECK(!mount(NULL, object_root, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL));
			CHECK(!mount(NULL, object_root, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
		}
		operation(names[count % files]);
		end = now();
		samples[count] = end - begin;
		response[count] = interval_ns ? end - ((uint64_t)pace.tv_sec * 1000000000ULL + pace.tv_nsec) : end - begin;
	}
	end = now();
	CHECK(!getrusage(RUSAGE_SELF, &after));
	CHECK(write(ready, "D", 1) == 1 && read(go, &ch, 1) == 1 && ch == 'E');
	qsort(samples, operations, sizeof(samples[0]), cmp);
	qsort(response, operations, sizeof(response[0]), cmp);
	prefix("latency", role);
	emit("operations=%u interval_ns=%u duration_ns=%llu start_ns=%llu end_ns=%llu cold_ns=%llu p50_ns=%llu p95_ns=%llu p99_ns=%llu max_ns=%llu user_us=%llu system_us=%llu maxrss_kib=%ld nvcsw=%ld nivcsw=%ld\n",
	     operations, interval_ns, (unsigned long long)(end-start), (unsigned long long)start,
	     (unsigned long long)end, (unsigned long long)first,
	     (unsigned long long)samples[(operations * 50 + 99)/100-1],
	     (unsigned long long)samples[(operations * 95 + 99)/100-1],
	     (unsigned long long)samples[(operations * 99 + 99)/100-1],
	     (unsigned long long)samples[operations-1],
	     (unsigned long long)(usec(after.ru_utime)-usec(before.ru_utime)),
	     (unsigned long long)(usec(after.ru_stime)-usec(before.ru_stime)),
	     after.ru_maxrss, after.ru_nvcsw-before.ru_nvcsw, after.ru_nivcsw-before.ru_nivcsw);
	prefix("response_latency", role);
	emit("operations=%u interval_ns=%u p50_ns=%llu p95_ns=%llu p99_ns=%llu max_ns=%llu\n",
	     operations, interval_ns,
	     (unsigned long long)response[(operations * 50 + 99)/100-1],
	     (unsigned long long)response[(operations * 95 + 99)/100-1],
	     (unsigned long long)response[(operations * 99 + 99)/100-1],
	     (unsigned long long)response[operations-1]);
}

static void query(int fd, const char *role)
{
	struct ckm_vfs_query q = { .version = CKM_ABI_VERSION, .size = sizeof(q) };
	CHECK(!ioctl(fd, CKM_IOC_VFS_QUERY, &q));
	if (!strcmp(mode, "vfs") && !open_workload)
		CHECK(q.hits > 0);
	prefix("vfs_inventory", role);
	emit("capacity=%u cached=%u stopped=%u hits=%llu retries=%llu native=%llu full=%llu metadata_payload_bytes=%llu\n",
	     q.capacity, q.cached, q.stopped, q.hits, q.retries, q.native, q.full, q.metadata_payload_bytes);
	if (open_workload) {
		struct ckm_vfs_open_query oq = { .version = CKM_ABI_VERSION, .size = sizeof(oq) };

		CHECK(!ioctl(fd, CKM_IOC_VFS_OPEN_QUERY, &oq));
		if (!strcmp(mode, "vfs"))
			CHECK(oq.hits > 0 && oq.hits == oq.released);
		prefix("open_inventory", role);
		emit("hits=%llu native=%llu released=%llu\n", oq.hits, oq.native, oq.released);
	}
}

static void supervise(const char *self, const char *role, const char *group,
		      int cpu, int ready, int go)
{
	struct ckm_create c = { .version = CKM_ABI_VERSION, .size = sizeof(c) };
	int fd = -1, control, attempt;
	pid_t child;
	(void)self;
	log_region = !strcmp(role, "target") ? 1 : 3;
	log_used = 0;
	affinity(cpu, cpu + 1);
	put(group, "cgroup.procs", "0");
	if (strcmp(mode, "native")) {
		CHECK(!unshare(CLONE_NEWNS) && !mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
		snprintf(object_root, sizeof(object_root), "/tmp/ckm-vfs-private-%d", getpid());
		make_objects(object_root);
	}
	if (!strcmp(mode, "core") || !strcmp(mode, "vfs")) {
		if (!strcmp(mode, "vfs"))
			c.features = CKM_FEATURE_VFS | (open_workload ? CKM_FEATURE_VFS_OPEN : 0);
		control = open("/dev/ckernel-m", O_RDWR);
		CHECK(control >= 0);
		fd = ioctl(control, CKM_IOC_CREATE, &c);
		CHECK(fd >= 0 && !close(control));
		if (c.features) {
			struct ckm_vfs_root reg = { .version = CKM_ABI_VERSION,
				.size = sizeof(reg), .capacity = 16 };
			reg.fd = open(object_root, O_PATH);
			CHECK(reg.fd >= 0 && !ioctl(fd, CKM_IOC_VFS_ROOT, &reg) && !close(reg.fd));
		}
	}
	child = fork();
	CHECK(child >= 0);
	if (!child) {
		if (fd >= 0)
			CHECK(!ioctl(fd, CKM_IOC_BIND, 0UL));
		log_region = !strcmp(role, "target") ? 2 : 4;
		log_used = 0;
		worker(role, cpu, ready, go);
		_exit(0);
	}
	wait_ok(child);
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
		emit("elapsed_ns=%llu final_nodes=0\n", (unsigned long long)(now()-start));
		CHECK(!close(fd));
	}
	if (strcmp(mode, "native"))
		CHECK(!umount(object_root) && !rmdir(object_root));
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
		if (!fgets(buf, sizeof(buf), f)) {
			fclose(f);
			continue;
		}
		fclose(f);
		tail = strrchr(buf, ')');
		if (!tail)
			continue;
		*tail++ = 0;
		for (token = strtok_r(tail, " ", &save); token; token = strtok_r(NULL, " ", &save), field++) {
			if (field == 9)
				flags = strtoull(token, NULL, 10);
			if (field == 22) {
				start = strtoull(token, NULL, 10);
				break;
			}
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
	open_workload = getenv("CKM_PAIR_OPEN") != NULL;
	mode = getenv("CKM_PAIR_MODE"); scenario = getenv("CKM_PAIR_SCENARIO");
	layout = getenv("CKM_PAIR_LAYOUT");
	CHECK(mode && scenario && layout && getenv("CKM_PAIR_ROUND"));
	CHECK(!strcmp(mode, "native") || !strcmp(mode, "core") || !strcmp(mode, "private") || !strcmp(mode, "vfs"));
	CHECK(!strcmp(scenario, "steady") || !strcmp(scenario, "exhaust") ||
	      !strcmp(scenario, "migration") || !strcmp(scenario, "invalidate"));
	CHECK(!strcmp(layout, "target-only") || !strcmp(layout, "bystander-only") || !strcmp(layout, "pair"));
	round_no = atoi(getenv("CKM_PAIR_ROUND"));
	if (getenv("CKM_VFS_PACED")) {
		interval_ns = 20000;
		operations = 20000;
	}
	swap_roles = getenv("CKM_VFS_SWAP") != NULL;
	alarm(90);
	CHECK(argc == 1);
	affinity(4, -1);
	CHECK(!unshare(CLONE_NEWNS) && !mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
	if (!strcmp(mode, "native")) {
		snprintf(object_root, sizeof(object_root), "/tmp/ckm-vfs-shared-%d", getpid());
		make_objects(object_root);
	}
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
		CHECK(!pipe(ready[n]) && !pipe(go[n]));
		children[n] = fork();
		CHECK(children[n] >= 0);
		if (!children[n]) {
			close(ready[n][0]); close(go[n][1]);
			supervise(argv[0], roles[n], groups[n], (n ^ swap_roles) ? 2 : 0, ready[n][1], go[n][0]);
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
	if (active[0])
		CHECK(read(ready[0][0], &ch, 1) == 1 && ch == 'D');
	if (active[1])
		CHECK(read(ready[1][0], &ch, 1) == 1 && ch == 'D');
	mid = now();
	snapshot(&running);
	for (n = 0; n < 2; n++)
		if (active[n]) {
			memory(groups[n], roles[n], "finished");
			CHECK(write(go[n][1], "E", 1) == 1);
		}
	for (n = 0; n < 2; n++)
		if (active[n])
			wait_ok(children[n]);
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
	if (!strcmp(mode, "native"))
		CHECK(!umount(object_root) && !rmdir(object_root));
	puts("CKM_VFS_PAIR_END failures=0");
	return 0;
}
