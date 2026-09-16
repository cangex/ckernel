================================
Container Interference Sensing v1
================================

Status and scope
================

CIS is an experimental host-admin observer for registered, non-overlapping
cgroup-v2 container roots. It does not change scheduling, allocation, security,
filesystem or socket semantics. It is independent of CKernel and CKernel-M.
Implementation is not a declaration that the performance gates have passed.
Consult the machine-readable acceptance inventory shipped with each experiment.

The initial build target is ARM64 OLK commit
3832db9d09e243ef4a0ef969801c5ab689bdff64 (snapshot tree
90bda14c1a6dcc2df4ae12c28fa4e0ff82f2fbd8). No host kernel deployment is required
or authorized by the tests. All new-kernel tests run in a disposable VM.

Build
=====

Build the complete baseline Image and modules in an external O= directory.
Enable the options in tools/testing/selftests/container_interference/config.
The tested userspace dependencies are GCC 10, clang 12, libbpf 0.8.1, libelf,
zlib and bpftool. BTF must come from the tested kernel, not an unrelated host::

  make -C tools/container_interference VMLINUX_BTF=/absolute/O/vmlinux
  make -C tools/testing/selftests/container_interference

CO-RE makes field offsets relocatable, but does not prove event protocols or
architecture-specific interrupt-context handling portable. Revalidate both
before using a different kernel or architecture. Hardware sampling falls back
only to explicitly reported kernel CPU-clock samples, never fake cycles.

Operation
=========

Run in the host PID, mount and initial user namespaces. Do not expose the socket
or reports to tenants. The daemon requires access to perf/BPF/cgroup resources
and at least 4096 file descriptors. A typical administrator session is::

  cisd --mode ip --socket /run/cis.sock --bpf /absolute/cis.bpf.o \
       --output /admin-only/new-run.jsonl
  cisctl register /sys/fs/cgroup/container-root container-name
  cisctl status
  cisctl diagnose ID GENERATION lock
  cisctl unregister ID GENERATION
  cisctl stop

Check cisctl usage for exact arguments. Registration transfers a directory FD;
names are display labels, not identities. The daemon accepts only the canonical
host cgroup2 mount; bind-mount aliases and overlapping registrations are rejected.
Descendant lookup is bounded to 32 ancestors. Missing identity is unknown.
Container registration is explicit; CIS does not discover runtime containers by
process name. Cgroup v1 is unsupported. The selftest runtime uses real Linux
namespaces, cgroups and readonly rootfs, but is not a production OCI runtime.

Modes are off, metrics and ip. Off retains only the control plane. Metrics reads
full PSI/resource files each second for populated roots. Empty roots retain
one-second presence/memory checks and a five-second CPU/PSI refresh, with explicit
freshness and no business-baseline training. IP adds fixed-period
kernel-IP sampling, without permanent full stacks or syscall tracing. A bounded
two-second diagnostic can select sched, lock, reclaim or work. Automatic windows
are triggered by sustained anomalies; explicit windows use the same budget and
cooldown. No business interference percentage is inferred from CPU time alone.

The local control protocol is version 2. Rebuild the daemon and every client
together; version 1 clients are rejected, not interpreted using a different
layout. The diagnostic request may specify start_ns in CLOCK_MONOTONIC time,
no more than two seconds ahead. Links must be ready before that instant or the
request fails. Zero selects an immediate interval after attachment. BPF filters
both ends of the interval, and diagnostic_start records readiness, start and
deadline. The future form is used by the isolated matched-window tests.

The optional --entry-rate-limit argument may lower, never raise, the default
200000 entries/second budget. The chosen value is always reported. Tests using
an injected low limit validate detachment, not performance under a real
200000-entry/second storm. Production acceptance retains the default.

--profile-loop is a development-only observer profiler, disabled by default.
It reports control, metric, capture-management and state/budget CPU segments.
The measurement includes its own instrumentation and is not performance
acceptance. Fixed-rate business workload testing must leave it disabled.

Stopping and failures
====================

SIGTERM and stop close the links, perf FDs and maps. SIGKILL also releases
un-pinned kernel resources, but leaves the UNIX socket path: confirm the old
daemon is dead before removing its stale socket. A new daemon requires explicit
re-registration and creates new generations. Never unlink a live daemon socket.

Errors, buffer losses, unknown identity, unmatched/expired pairs and degradation
are report records, not zero values. When the process or entry budget trips,
collectors are detached. Continued metrics overrun disables polling as well.
A successful daemon exit is not evidence that coverage remained active.
Unavailable process CPU/RSS budget inputs stop capture and metrics. They must
not be interpreted as zero consumption. The legacy user_cpu_ns report field
means total process CPU, not user-only CPU; process_cpu_ns now names it correctly.

Reports contain kernel addresses and cross-container information and are
administrator-only. The fixed-size JSONL format is versioned. Do not stream it
to a slow terminal during performance measurement; use an administrator-owned
local output and export after the test. File-system writeback and observer
background CPU remain measurement costs, not free work.

See Documentation/container-interference/design.rst, attribution.rst,
coverage.rst and overhead.rst for the evidence and acceptance boundaries.
