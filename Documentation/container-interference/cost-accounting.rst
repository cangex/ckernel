Observer cost accounting and R0--R8 gates
=======================================

Measured process CPU
--------------------

``budget`` records now distinguish total process CPU from user CPU. The
guard divides CLOCK_PROCESS_CPUTIME_ID deltas by actual monotonic elapsed
time. getrusage user/system totals are separate cumulative observations;
they must not be added again to total process CPU. The first interval is
labelled startup, not treated as an arbitrary one-second steady interval.
Missing RSS/CPU accounting fails closed.

The management limit remains 20 ms CPU per second. It is not 2% of all host
CPUs. Detached probes, closed PSI triggers or missing collection cannot
satisfy a coverage gate. Initialization, registration, steady state and
teardown remain real costs even when not inside the business window.
Lifecycle records separate startup and synchronous teardown wall/CPU time,
plus process CPU totals before final exit. They explicitly exclude async
kernel work, and do not pretend to include the final close/free/exit tail.

Presence/metric reads retain one-second cadence using forty fixed 25 ms
deadline buckets. Empty roots still report memory and presence each second;
their CPU/PSI fields retain the separately disclosed five-second policy.
Missed deadlines skip backlog, not present stale reads as fresh samples.
Bulk administrative registration is limited to 16 requests/second; this
does not lower business sampling frequency or change the diagnostic window.
Four root-relative configuration FDs are retained per registered root, not
four cached values. Each epoch check still reads current values. Stale/failed
reads retire the diagnostic and reset learning; optional absent controllers
remain explicitly partial. Unregister closes every retained descriptor.

Memory is not a sum of convenient counters
-----------------------------------------

``kernel_memory_inventory`` records map memory from fixed-OLK fdinfo, BPF
program pages, perf output mappings and IP mappings. Mapped pages overlap
process RSS and cgroup charges. Do not sum these fields into a fabricated
total. fdinfo program pages do not include all JIT/auxiliary/BTF state;
PSI worker/trigger costs and perf objects also require explicit accounting.

The old 16 MiB estimate remains labelled ``unmeasured_kernel_reserve_bytes``
as an engineering guard. ``memory_accounting_complete=0`` explicitly blocks
claiming that this proves the complete 64 MiB resident-cost requirement.
The control cgroup's memory.current is a charge boundary, not proof of the
owner of every kernel allocation. Per-CPU IRQ/softirq and system-time deltas
include changed application work and unknown background activity.

Native PSI re-entry and teardown
-------------------------------

The fixed OLK source has nontrivial work behind a pressure-file operation:
``kernel/sched/psi.c:psi_show`` takes the group's ``avgs_lock`` and calls
``collect_percpu_times``, which visits possible CPUs. Reading CPU and memory
pressure separately does not imply one free shared snapshot. Persistent FDs
avoid path lookup, not this aggregation work.

The privileged 500 ms triggers in ``fast.c`` use PSI_POLL. The first trigger
on a group creates a ``psimon`` thread; ``psi_rtpoll_worker`` uses
``sched_set_fifo_low``. Its execution is not daemon process CPU. Two triggers
on one group share that worker, rather than creating two independent workers.
Exact task attribution and costs remain to be measured; matching a task name
alone is insufficient evidence in a general host environment.

Closing a trigger reaches ``kernel/cgroup/cgroup.c:cgroup_pressure_release``
and ``psi_trigger_destroy``. The latter calls ``synchronize_rcu`` and, for the
last trigger, ``kthread_stop``. CIS currently closes these FDs serially on its
control thread. The measured multi-second full-mode teardown is consistent
with this synchronous path, but is not a measured attribution of every
nanosecond to RCU. Unregistering roots can also delay other control work.
No RCU guarantee has been removed and this version does not hide that cost
in an unaccounted cleanup thread. Moving cleanup asynchronously would need
bounded ownership, shutdown, accounting and service-latency regression tests.

Reproducible reports
--------------------

``observer_cost.py`` checks a predeclared six-mode, two-workload, five-pair
component experiment. OFF/OFF variability is reported separately from
observer effects. ``control_cost.py`` checks all six 128/256 idle-root cases,
registration/retirement identity, continuous metrics, detach errors and
process CPU. Neither can satisfy active-container S6 or an owner diagnostic
cost test. ``overhead.py --rounds 10 --full-mode-only --require-fast-alert``
checks the separately frozen adjacent-pair ambient screen.

The latter is a new experiment, not an extension of an old five-pair set.
All old failures remain in their original artifacts. No discarded trials,
post-hoc stopping, changed P99 definition or lowered thresholds are allowed.
The source and guest executable hashes must be recorded for each run.

``cost_snapshots.py`` preserves per-CPU USER_HZ deltas, including IRQ,
softirq and steal. It keeps observer-cgroup CPU and memory charges separate.
Guest ticks are already part of user/nice; iowait is not reliable blocked
time. Sequential snapshots are not atomic or exclusive-owner measurements.
Missing, duplicate, truncated or incompatible CPU sets are quality errors.

Capture maintenance visits ready buffers each loop and drains all buffers
at least every 100 ms in ambient mode. Active diagnostics and teardown
still force a full drain, including below-watermark records. This reduces
empty-buffer scans, not PMU events. Candidate latency must be revalidated;
changing delivery cadence is not evidence of a successful cost gate.

``detection_report.py`` accepts independently recorded episode truth and
one same-clock event stream. It includes misses and unserved targets, rejects
overlapping truth for one identity, and separates warning latency from
candidate-to-ready latency (queueing plus attachment). Raw OWNER events do
not stand in for a completed validated relation or a report timestamp.
``detection_latency.py`` uses a one-sided binomial deadline test per gate:
ten fast samples cannot establish P99. Independent episodes and workload
strength must be validated outside this parser. Passing latency alone never
passes R3 or R6 cost/accuracy/coverage acceptance.

Stage boundaries
----------------

R0 fixes attempt identity, failed acquisition and typed evidence. Its
bounded mechanism tests do not cover nested holders, all identity migration,
all direct d_lock operations or normal-application attribution. Those remain
R4 work. R1/R2 reports expose cost and uncertainty; a wide tail interval is
not a low-overhead pass. R3 latency needs independent episodes, not hundreds
of transitions from one fixture episode. R5 resource extensions and R7/R8
compatibility or pilot work must not be credited from these earlier logs.

Only a profile that passes every applicable cost, coverage and correctness
gate may claim R6. Host kernel deployment and production intervention remain
outside the isolated-VM authorization. No R0--R8 completion is implied merely
by the existence of implementation files or a successful guest shutdown.
