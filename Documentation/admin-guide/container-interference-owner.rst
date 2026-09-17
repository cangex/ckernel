Fast candidates and bounded ownership evidence
=============================================

Status and scope
----------------

This is an opt-in extension of CIS, not a new isolation mechanism. Enable
CONFIG_CIS_OBSERVE on a non-RT diagnostic kernel. The default is disabled.
The static tracepoint is inactive outside an explicitly attached diagnostic.
The extension changes no lock algorithm, mutex layout, permission rule or
container resource allocation. It has not passed the full S6 low-overhead
scale acceptance; previous S6 failures remain failures.

Run cisd with --fast-alert to request event-driven CPU/memory PSI candidates.
Each registered root installs two ``some 20000 500000`` triggers, sharing a
single userspace epoll loop. These are 20 ms accumulated stall in a 500 ms
window, not a 20 ms detection guarantee. PSI kernel monitor work, trigger
memory and descendant workload effects belong in the observer budget.
The warmup baseline remains in place for learned anomalies. A candidate
does not mean a peer container is responsible. CPU throttling, sleeping
mutex waits and low-sample spin paths are not universally covered by PSI.

Three sampled explicit lock-slowpath IPs within 250 ms can request an owner window without
waiting for baseline warmup. This uses the existing global IP sampling
budget; generic _raw_spin_lock/mutex_lock and unsupported rwsem symbols do
not trigger it. It is not continuous syscall or allocation tracing. A lock-symbol
candidate is not proof of contention. Availability, cooldown and the two
target limit still apply. ``cisctl diagnose ... owner`` requests the same
bounded collector manually. On kernels without the new tracepoint it is
unavailable, never silently replaced with a fabricated holder.

Ownership protocol
------------------

The non-RT mutex observation records successful owner acquisition, entry
to unlock, unlock completion, contended wait, mutex initialization and an
ABORT terminal event at the native failed-acquisition exit. The errno is
preserved. Interruptible EINTR, fatal-signal killable cancellation and a
wait-die ww_mutex EDEADLK are exercised separately in the disposable fixture.
This does not claim all ww_mutex policies or PREEMPT_RT coverage.
The native owner snapshot rejects unstable reads and handoff/pickup flags.
It is protected by RCU but remains a point observation: it is not a record
of how long the task owned the mutex.

For lockref, only the actual fallback spin-lock acquisitions in lib/lockref.c
are observed. The cmpxchg path is unchanged. Dentry initialization and final
free supply lifecycle boundaries. Direct d_lock acquisitions elsewhere in
VFS are not automatically covered. When lockref_put_or_lock returns with
the lock held, ESCAPE explicitly ends coverage. Generic qspinlock state
does not contain a task owner; no owner is inferred from its tail or from
the current waiter. A lockref address alone is not proof of a dentry; a
source stack or a verified object lifetime is required for that label.

The BPF collector watches at most 64 objects, caches at most 128 observed
acquisitions of watched objects, and keeps at most 128 holder-task mappings.
It does not cache every host acquisition to reconstruct prehistory. The first
already-held interval can therefore remain only a snapshot and an unknown
duration. This avoids host-wide owner-cache updates on every acquisition.
An entry stores
the registered root and generation, host task ID and task start time.
The watch epoch is a diagnostic interval identifier, not a persistent
global object ID. RESET, RETIRE and ESCAPE invalidate pending histories.
Target removal/deadline makes the watch inactive; completion clears that
target's entries. Task-ID reuse never transfers ownership.

The lockref export is a bounded prefix of at most 64 observed transitions
per watched object per diagnostic window. A LIMIT event (phase 11) closes
the prefix explicitly; subsequent operations remain unobserved. This is
not a full-window total, uniform sampling or a latency distribution.
The per-object admission atomic is confined to this short prefix, not a
host-global hot counter. Entry cost after the prefix still counts towards
the global diagnostic budget. Mutex windows retain their time bound.

Export buffers use 2--16 pages per CPU, with at most 4 MiB payload across
possible CPUs. Diagnostic export wakes through the perf epoll FD instead
of waiting for the ambient poll. Buffer metadata, maps, PMU pages, process
RSS and kernel PSI work are separate costs. Budget failures detach probes;
process-budget failure also closes PSI trigger FDs rather than just stopping
output. Lost records, recursion gaps and unresolvable identity remain visible.

Evidence interpretation
-----------------------

``owner_report.py LOG`` sorts source timestamps, de-duplicates cached
acquire observations and joins:

* WAIT to the same task and nonzero attempt ID's ACQUIRE or ABORT;
* a holder's ACQUIRE to its own RELEASE_BEGIN;
* their time intersection, with identical object, kind and watch epoch.

RELEASE_END is not a hold endpoint because a new owner can acquire before
the previous unlock call returns. Snapshots alone never generate durations.
An aborted acquisition ends at ABORT, not at a later trylock. A failed wait
may still have a valid observed-holder intersection before cancellation.
The protocol-2 attempt is keyed by task start time, object kind/address and
watch epoch; the bounded 1024-entry attempt map is cleared on target teardown.
Legacy protocol-1 records are readable, but cannot pass the new E2 gate.
Missing acquire/release, escaped locks, incomplete waits and limit boundaries
do not receive invented endpoints. A task cannot block itself in the emitted
cross-task edge. Same-container edges are labelled separately.

A closed edge with relation_type=holder_waiter supports an E2 dependency: while the waiter was in this
observed acquisition, the named task exclusively held this same object.
It is not E3 workload causality, the entire wait duration, pure spinning
cycles or an application interference percentage. After release there may
still be queueing, wakeup delay and scheduler delay. These are not charged
to the old owner. Event loss or a recursion gap downgrades the log's joins
to INCOMPLETE rather than manufacturing precise attribution.
The separate generic contention report can emit relation_type=cowaiter.
That never identifies a holder; consumers must inspect both type and level.

Scheduler switch observations mark sleeping, runnable-deschedule or
preempt-flagged off-CPU intervals of a known holder. They are a lower bound,
not proof that an unmarked interval was entirely on CPU. The bounded map
currently follows one watched object per task; nested locks and eviction
can leave additional off-CPU gaps. A sched_switch preempt flag can also be
produced by a voluntary kernel reschedule implementation. A true involuntary
preemption test therefore uses PREEMPT=y and a bounded busy holder without
cond_resched, plus a runnable CPU competitor. Sleeping holds are separate.

Tests and operational limits
----------------------------

Run owner_test.py for private-object, handoff, snapshot-only, address-reuse,
escape, preemption accounting and lost-record regressions. The disposable
VM fixture adds real kernel mutex truth records and dget/dput operations on
real shared/private dentries. Test-only 40 us fallback delays and 80 us
d_lock seeds induce an observable slow path without disabling cmpxchg.
Direct seed ownership is intentionally outside the collector's coverage.
These injected tests are not normal application performance evidence.

Use registered container roots for both participants. Root IDs, task IDs,
object addresses and source stacks are administrator-only information.
Do not load the fixture on the host. Do not present the extension as
universal mutex/spinlock ownership, complete VFS attribution, bounded
application latency, or passed ambient/diagnostic overhead gates.

Reproduction and mechanical checks
---------------------------------

Build the tools and fixture against the exact running diagnostic kernel,
including matching BTF and Module.symvers. For the involuntary-preemption
case also enable CONFIG_PREEMPT=y. The selftest ``owner_vm_init.sh`` is an
init script only for a disposable initramfs containing the compiled CIS
tools at /, the fixture at /cis_fixture.ko, and the existing fleet test
rootfs at /container-root. It mounts fresh cgroup v2 and shuts that guest
down; it must never be invoked on a shared host.

Preserve the complete serial output. On the build/analysis machine run::

  python3 tools/testing/selftests/container_interference/owner_test.py
  python3 tools/testing/selftests/container_interference/owner_vm_check.py \
      --require-preempt /path/to/guest-serial.log

The checker requires private-object negative results, bidirectional real
ownership in shared cases, address-reuse boundaries, actual busy-holder
preemption and automatically triggered dentry diagnosis. A fleet exit code
alone cannot pass it. It checks the emitted subset against fixture operation
truth; it does not measure full-window recall or generalize zero observed
contradictions to a production false-positive rate.

Low-rate export and release gates
--------------------------------

Periodic drain and detach consume the perf buffers even when their wakeup
watermark has not been reached. Otherwise a short, low-volume aborted wait
could leave a valid stack export but no exported transition records.

Release acceptance is bound to a versioned collector profile. A sched-only
DIAG result does not admit owner-mutex or owner-dentry. Each default owner
collector needs its own precise-window cost results, actual episode coverage
and protocol version. A single successful relation does not establish recall.
The current candidate is experimental; protocol tests do not establish R6/S6.
