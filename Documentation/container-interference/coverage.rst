===================
Coverage boundaries
===================

Implemented surfaces
====================

* Host cgroup-v2 FD registration, root generations, descendants and migration.
* PSI, cpu.stat, memory.events/current and populated status.
* Fixed-period kernel IP perf sampling with loss/throttle/multiplex metadata.
* Short sched_stat_wait, contention_begin/end, direct and memcg reclaim stacks.
* Bounded workqueue submit/execute/cancel lineage, with unresolved requeue.
* Conservative E0/E1 and overlapping-mutex co-waiter E2 output.

Implementation is not validated coverage. A capability file being present is
not an operational test. Preserve raw boot, load, sample and selftest evidence
for each claimed collector. Stack absence, PMU multiplexing, IRQ ambiguity,
map/buffer loss and unsupported ancestry are reported, not filtered away.

Unsupported or limited
======================

* Cgroup v1, overlapping roots, noncanonical host-mount registration.
* Non-4-KiB kernel pages: capture is rejected until the kernel-memory reserve
  has been re-audited. CPU hotplug during capture is not validated coverage.
* Arbitrary lock ownership, comprehensive spinlock coverage or hold-time truth.
* All asynchronous owners, merged work, RCU provenance and all cancel APIs.
* Automatic business throughput/latency or application interference percentage.
* Cache-line contention from ordinary LLC misses. SPE requires actual platform
  exposure and a separately validated decoder; absent hardware is UNSUPPORTED.
* Unconditional automatic identification of the container causing a wait.
* Bare-metal NUMA performance conclusions from an ARM64 KVM test.

Validation layers
=================

logic_test exercises state transitions and the two-target cap. identity tests
exercise runtime registration, overlap, descendant execution, migration,
deletion/rename, restart and deadline behavior. Migration requires raw sample
checking in addition to a successful cgroup.procs write. The isolated module
provides two mutexes and per-open async ownership truth. Userspace futex tests
are never presented as evidence for kernel spinlocks.

CPU quota, same-CPU competitor and memory.high scenarios are separate from
fixture tests. A configured pressure source is not sufficient: the relevant
event and its cgroup/window must be present. Address reuse unit tests and live
object-lifecycle tests have distinct status. Idle registration at 256 roots
does not imply 256 active-container performance validation.

The acceptance checker requires verified artifacts for PASS, treats core SKIP
as incomplete and permits UNSUPPORTED only for optional SPE. Test execution
success, implementation status and acceptance status must remain distinct.
