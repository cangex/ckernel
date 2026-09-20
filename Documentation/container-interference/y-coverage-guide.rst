Public-resource prototype: coverage and use
===========================================

This is a bounded, periodic profiling system, not a kernel optimization and
not continuous whole-machine attribution. Containers normally use separate
directories, files, FD tables, address spaces and connections. The useful
question is which *public backend* these independent operations reach.

Default scope and optional tools
-------------------------------

The reduced survey and public-resource specialists do not implicitly attach
private FD-table, shared-user-lock, private Socket, or Maple-context tracing.
Legacy owner/sync/rwsem/fd/net/allocator extensions remain explicitly selected
tools for workloads with actual shared objects. Removing default eligibility
does not delete these tests, nor prove lower idle cost: idle producers were
already detached. The demonstrated source saving includes removal of Maple
context callbacks from backend-only allocation profiling.

Filesystem, transmit queue and selected-CPU profiles require explicit bounded
selection. They are not silently activated by matching an application name.
The CPU selection is disjoint from management affinity. A profile permit
allows at most four registered roots, two targets, two-second windows and
32 sessions in the isolated 8-vCPU, 4-GiB VM. These limits have not been
converted into an untested 48/256-active-container production claim.

Resource interpretation
-----------------------

* Ancestor resource accounting: sampled updates bind to the native owning
  cgroup counter and its generation. Common versus separate parents and
  rollback have tests. This identifies shared accounting, not a held mutex
  or proven cache-line bouncing. Native charges are never skipped.
* Allocator backend: selected SLUB cache/node operations and guarded node
  lock relations have positive/negative tests. Physical-page PCP refill,
  drain and direct buddy paths are sampled by node/zone. Neither a shared
  zone address nor allocator wall time identifies all zone-lock holders.
* Memory pressure: native reclaim intervals identify the reclaiming task.
  Local high counters and ancestor topology give additional context, not
  the missing identity of every scanned page or unique pressure producer.
* Filesystem backend: private directories can still share an ext4 journal,
  allocation groups, legacy orphan list or orphan-file infrastructure.
  Selected superblock/lease identity prevents joining separate filesystems.
  Commit waiting and orphan operations are observable; group use is not
  proof of group-lock contention. Contributor/holder coverage is incomplete.
* Block I/O and writeback: request lifetimes, queue/tag identity and capacity,
  selected tag-wait associations and native dirty-pause facts are observable.
  Submitter, billed owner and worker are separate. Complete tag occupancy,
  exclusive dirtier, device-internal causes and a unique blocker are not
  inferred from the largest producer or a shared queue.
* Public transmit queue: exact device/queue/qdisc lease observes admission,
  service and backlog points for independent sockets. Direct root-bound
  traffic can identify participating containers. Forwarded/retired or
  transformed traffic retains unknown origin; service is not wire delivery.
  These are participation/pressure observations, not Socket-lock ownership.
* CPU/background: selected-CPU runnable switch-out intervals can be associated
  with another registered executor on that same CPU. Quota is a separate
  boundary fact. Nested IRQ/softirq time is a per-CPU union; work execution
  and observed slices are available, but submitter/merged-work origin remains
  unknown. A runnable interval does not establish scheduler eligibility or
  a unique causal blocker. SPE is unsupported in the current VM.

The stage validation documents retain the exact source generation and cases.
Fixture-proven adapters are distinguished from observations in ordinary
private-object workloads. A quiet joint window does not erase a positive
fixture test, but neither does that fixture make the quiet window positive.

How to read a result
--------------------

Configured sharing is context. Sampled common-resource participation is a
fact. A closed wait with a validated object/lifetime is stronger evidence.
Identifying the unique container that caused degradation requires still more
information or a controlled causal intervention. E1/E2 is not E3, and unknown
is not silently attributed to a worker, current task or busy neighbor.

Each report retains source and parser hashes, exact identities/generations,
window boundaries, losses, source filters, quality, bounded output omissions
and post-window object absence. Partial/over-budget captures publish no
accepted relations. Private/unselected resources, address reuse, owner changes,
migration, revocation and failure/cleanup have explicit negative checks.

Cost and deployment boundary
----------------------------

Worker preparation, collection, drain and source callbacks are distinct.
Joint cohorts additionally retain business/management cgroup CPU and memory,
whole-VM CPU, matched kernel-thread ticks and first-analysis cost. Kernel-thread
ticks include unrelated work and miss short-lived tasks; interrupt work may
run in business context. These are not a complete exclusive observer bill.
BPF map/program/perf inventory records measured parts and exclusions.

Management cgroup cumulative memory peak includes the harness, controller,
workers and raw-file cache. It is not per-capture RSS. Missing memory.stat
fields remain unknown, not zero. Final archive export and independent replay
are outside business timing and are separately identified. Fixed offered-rate
throughput with no timeout is not saturated service-capacity acceptance.
P99 remains record-only under the prototype authorization.

No physical deployment, universal low-overhead certification, automated
governance, network/allocator redesign, hardware contention attribution or
zero cross-container blocking claim follows from this prototype.
