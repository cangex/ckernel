.. SPDX-License-Identifier: GPL-2.0

======================
Experimental CKernel-M
======================

Scope
=====

CKernel-M is an opt-in experiment in instance-owned kernel state. It does
not launch a second Linux kernel, provide a new security boundary, change
rootfs contents, or replace namespaces/cgroups. This version implements
an ownership core and an experimental mm/VMA Maple node inventory only.
FD accounting, AppArmor, VFS, sockets and system-call permission checks
remain native. Do not use old CKernel runck protocols with this ABI.

CONFIG_CKERNEL_M is a built-in bool, default off, requiring a 64-bit NUMA
kernel with cgroups and kernel memory accounting. CONFIG_CKERNEL_M_MAPLE
is a separate default-off option requiring SLUB. There is no unload path.
All new kernels must first be booted in a disposable VM. Do not install
them as the developer host's kernel without separate authorization.

Control and launch
==================

The 0600 misc device /dev/ckernel-m accepts CREATE. It returns a CLOEXEC
anonymous instance fd. Every ioctl requires CAP_SYS_ADMIN in the initial
user namespace, including operations on transferred instance fds. Cookies
are diagnostic identities, not permission tokens. CREATE validates version,
structure size, reserved fields, features and capacity. QUERY returns a
snapshot; BIND attaches only the caller; REVOKE is idempotent.

Build the small launcher with::

  make -C tools/ckernel_m
  tools/ckernel_m/ckmctl 0 /path/to/test
  tools/ckernel_m/ckmctl 128 /path/to/test

Zero selects Core only. A nonzero bound (up to 4096 tracked nodes) requests
Maple inventory. The supervisor retains the handle while the child binds
and execs. Closing the last control handle revokes the instance, so simply
binding and execing with the only handle marked CLOEXEC is NOT a launcher.
Binding is refused for existing attachments, multithreaded callers, shared
mm/files, wrong cgroup or incompatible CPU range. Unsupported optimization
conditions later use the original allocator, not a new syscall error.

The initial mm is not relabelled at BIND. A subsequent exec or non-CLONE_VM
fork creates an owned mm; CLONE_VM keeps the existing owner. Tasks inherit
an instance reference. The final task_struct release, not merely a process
exit notification, drops its task reference. Nodes retain their own owner
through Maple RCU callbacks. The mm ownership reference ends after
exit_mmap; physical mm references held by lazy TLB users do not retain the
instance. See ../ckernel-m/design.rst and reentry.rst.

Capacity and counters
=====================

There are at most 256 live instance objects. max_nodes includes tracked
nodes and records pending final release, not all VMA nodes or user pages.
Excess allocations use native SLUB. CPU inventory has four owner slots
with two nodes per slot. An owner does not synchronously evict another
owner. Each sparsely created instance/NUMA pool holds at most 32 idle nodes.
All idle, borrowed and retired nodes together remain within max_nodes.

QUERY reports CPU/NUMA hits, misses, native fallbacks, returns and node
states. metadata_bytes is the sum of requested direct structure sizes,
not total charged pages: SLUB/percpu padding, XArray internal nodes and
static shared index/CPU tables are additional. node_bytes counts tracked
nodes not yet freed; pending_metadata counts side records after node free.
Counters are observational, not hard-limit accounting. Concurrent snapshots
can observe in-progress reservation/transition; evaluate conservation only
after quiescence. All memory costs must be included in performance claims.

Validation boundary
===================

Selftests live in tools/testing/selftests/ckernel_m. The suite reports
PASS/FAIL/SKIP rather than treating missing facilities as success. KUnit
tests require CONFIG_KUNIT and CONFIG_CKERNEL_M_KUNIT_TEST. Diagnostic
kernels and production-like timing configurations must remain separate.
Compilation and a small guest smoke test do not prove memcg migration,
all fault paths, CPU hotplug races or improved NUMA isolation. Consult the
external validation report for precisely which tests have actually run.

Optional mechanism probe
========================

tools/ckernel_m/maple_probe is opt-in and requires CKM_ISOLATED_GUEST=1.
Use CKM_PROBE_MODE as a label, CKM_PROBE_ROUND as a round identifier, and
CKM_PROBE_SCENARIO=steady or exhaust. Run it directly (native), under
ckmctl 0 (core), or ckmctl 128/4 (inventory). It pins its own task to CPU 0
of the guest, performs a fixed number of real VMA split/merge cycles,
and reports cold, steady and task CPU times. It does not collect perf.

The exhaust scenario uses more VMA regions and a smaller inventory budget
in the external harness. Check misses/fallbacks instead of assuming it
exhausted the pool. Run opposite mode orders in alternate rounds. These
are VM mechanism observations, not a container interference rate, a
cross-NUMA isolation result, or an equal-memory-budget cache comparison.
