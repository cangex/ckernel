M2 fallback convergence and same-kernel interference probe
=========================================================

Scope
-----

This change retains native allocation elasticity, GFP, memcg and RCU rules.
It does not add admission control, a private allocator, a new Maple node layout,
or a promise that teardown latency is bounded. Core, FD, VFS and LSM semantics
remain unchanged. The optional instance inventory remains a prototype.

Allocation changes
------------------

Owned-tree bulk allocation formerly called the single-node helper for every
requested node, including requests for which pooling was unsupported. It now
tries eligible local nodes until a request must be delegated. The remaining
requests go through one native kmem_cache_alloc_bulk() call. A later batch can
use newly returned inventory; the current batch does not wait for it.

Mixed batches retain explicit ownership: already obtained nodes use the normal
tracked/native free discriminator on rollback. Native SLUB rolls back its own
failed batch. A real single-node backend allocation failure is not retried.
Post-allocation locality/charge mismatches return that already allocated native
node; they do not allocate a second copy. Full-budget probes use
atomic_add_unless(), avoiding an increment/decrement pair when already full.
RCU and node accounting lifetimes are unchanged.

Diagnostics
-----------

CKM_IOC_DIAGNOSTICS is a separate read-only ioctl on an instance handle. The
original CREATE/BIND/QUERY/REVOKE numbers and structure layouts are unchanged.
The existing initial-user-namespace CAP_SYS_ADMIN check applies. Version, size,
reserved fields and user pointers are checked. There is no global hot counter.
Counters use the existing per-instance per-CPU allocation; its increased byte
cost is included in the instance metadata estimate.

reasons[] counts node requests delegated to native handling. The first failed
pool decision gets its exact reason. Unchecked remainder requests get
CKM_FB_BULK_REMAINDER, not a fabricated individual GFP/budget diagnosis.
Post-allocation rejection also counts as native handling. Reason totals equal
the original fallbacks counter when allocation is quiescent. A live query is a
non-atomic diagnostic snapshot, not a transactional accounting API.

misses counts actual eligible inventory misses, not skipped remainder nodes.
bulk_calls counts native bulk invocations; bulk_requested and bulk_completed
count node requests, bulk_failed counts failed invocations. registered counts
new tracking records. alloc_failed counts failed backend node requests, not
optional side-record failures that successfully fall back. Disposition counts
distinguish inactive-owner return from unavailable/full local storage. They do
not assert that all shared backend reentries have disappeared.

Probe interpretation
--------------------

tools/ckernel_m/maple_pair runs only with CKM_ISOLATED_GUEST in a disposable
VM. Target and bystander have separate processes, mm/files and cgroups in the
same kernel. A fresh group per trial has memory.max=128 MiB. The pressure target
also has memory.high=32 MiB and temporarily faults 40 MiB. OOM/oom_kill is a
test failure, not an accepted performance sample.

Target uses vCPU 0 (migration alternates 0/1); bystander uses vCPU 2; controller
uses vCPU 3. CPU migration in the probe is within one guest NUMA node. Existing
topology correctness tests separately cover cross-node migration/hotplug.
The bystander runs until the target finishes, rather than terminating early
because it completed a fixed operation count. Both modes also have isolated
baselines in the same image. A complete operation is a VMA split/merge cycle,
or the explicitly identified exit/pressure composite operation, not one syscall.

Report per-role operation counts, elapsed time, cold cycle, P50/P95/P99/max,
foreground self/child CPU, context switches and maxRSS. A pair/solo comparison
uses matching role, scenario, mode and round; it never divides dissimilar
workflows. Fixed observation time is one second minimum; a composite operation
can extend the target window. Quantiles use all samples, without latency filtering.

Background CPU uses before/after schedstat runtime of matching kernel threads
(PID plus start time), separately for foreground and cleanup windows. Missing
or newly created threads are explicitly counted; matching-thread runtime is a
lower bound, not exact per-instance attribution or all kernel CPU. System IRQ,
softirq and steal ticks are reported separately, not added to thread runtime
because they can overlap. Collection runs outside the operation window.
Output is buffered in a fixed 4 MiB memfd, prefaulted by the controller before
creating the test cgroups. Serial-console output is flushed after measurement
and cleanup, not during the measured windows. Snapshot/query and buffered-log
overhead during cleanup is still part of the observer limitation.

Memory reports raw cgroup current/peak/stat/events at ready, finished and after
drain plus a fixed 250 ms observation tail. These include process and manager
charges, not only inventory. Inventory byte estimates omit slab padding and
some generic metadata; do not replace cgroup accounting with those estimates.
The fixed tail does not prove all shared RCU/workqueue activity has ended.

No perf/eBPF is attached to latency trials. Always-on reason counters and
schedstats still have overhead. New-versus-old results measure the combined
change, not an independently identified benefit of each sub-change. VM results
are not bare-metal NUMA isolation or independent-kernel fault-isolation claims.
