Bounded profile sessions and periodic survey prototype
=====================================================

Scope
-----
Explicit single-shot IP or owner captures and receipt-gated periodic IP surveys.
This is not automatic optimization, CKernel integration or completed S6.
The periodic implementation is experimental: offline tests do not constitute
ARM64 build, VM runtime or performance acceptance. Standard-library Python
controls bounded identity/journal state; C/libbpf owns capture. Both processes
count toward costs. Legacy cisd/cisctl protocol remains unchanged.
Requires the fixed ARM64 observation kernel, 4-KiB pages, cgroup v2, initial
user/cgroup namespaces, host administrator, Python >=3.9 and libbpf.

Interface
---------
Run ``python3 session.py daemon``, then ``python3 session.py request '<JSON>'``.
Version-1 JSON uses bounded Unix SOCK_SEQPACKET messages (8192 bytes)::

  {"version":1,"op":"register","path":"/sys/fs/cgroup/example"}
  {"version":1,"op":"start","nonce":"request42","collector":"ip",
   "targets":["ID:GEN"],"window_ms":2000}
  {"version":1,"op":"status","session":"SESSION"}
  {"version":1,"op":"cancel","session":"SESSION"}
  {"version":1,"op":"report","session":"SESSION"}
  {"version":1,"op":"unregister","target":"ID:GEN"}
  {"version":1,"op":"stop"}

The independent ``owner`` collector creates no IP sampler. IDLE holds identity
FDs only, with no periodic root scan or PSI thresholds. One host-wide session
including drain; one or two targets; 256 registered roots. Fresh maps/buffers
per session, never pinned. Distinct session and stable registration generations.
Unknown fields/versions, stale identities, overlapping roots, and nonce-content
collisions are rejected. Idempotency history is bounded at 256 persistent records.
Without a periodic plan, reaching this bound rejects new sessions. With a plan,
only expired, cleanup-verified, retention-managed records from this boot can be
retired. Old P1 evidence and faulted records are not deleted. A new durable nonce
epoch precedes deletion; expired-epoch requests are rejected, never replayed.

Lifecycle
---------
ADMIT -> PREPARE -> ARMED -> CAPTURING -> DRAIN -> VERIFY -> IDLE.
Uncertain cleanup yields FAULTED. COMPLETE/PARTIAL/CANCELLED/FAILED are separate
results: safe cleanup does not imply complete evidence.
Only a record with ``finalized=true`` is terminal. During durable publication,
status remains VERIFY; the next session cannot start. Status omits large boundary
snapshots and survey payloads, which remain in the local administrator-only JSON.

Before enabling a producer the worker sends map/program IDs; the controller
durably journals ownership and then acknowledges ARM. Perf is disabled during
preparation. BPF event windows reject out-of-window records, but this alone does
not remove entry cost. Stop disables perf and detaches links, drains records,
exports terminal and incomplete events, removes targets/watches, destroys
objects, then closes FDs. Identity remains valid until the final buffered event.

Parent-death handling and a controller watchdog cover independent failures.
A host-global journal prevents bypassing unresolved cleanup by choosing another
output directory. ``recover`` verifies the recorded PID and all enumerated
objects absent; it does not kill recycled PIDs or delete other tools' objects.
Object-ID ENOENT proves no enumerable capture object remains, not completion of
all deferred kernel memory/CPU reclamation. Two suspended processes, kernel
uninterruptible waits or a frozen host have no unconditional shutdown guarantee.

Budgets and evidence
--------------------
Initial defaults: 2-s window; prepare 10 s; cleanup 5 s; residue verification
2 s; nominal IP 1000/s; detailed entry 200000/s; output 16 MiB; worker steady
CPU guard 20 ms/s; combined RSS guard 64 MiB. A controller-side cooperative guard
also checks process CPU including reaped helpers and live-child process clocks.
Default limits are 250 ms preparation, 20 ms per capture second, 250 ms drain
and 600 ms whole-session process CPU. These are prototype stop policies,
not kernel worst-case latency guarantees. Controller+worker CPU and kernel
allocations remain acceptance measurements: RSS and worker guards alone do not
prove the inclusive 64-MiB/20-ms contract. Preparation and drain are not hidden
outside cost accounting. PMU fallback, multiplexing, losses, incomplete owner
boundaries and output failures must remain visible.

Collector and residue-helper reaping share a controller-local registry with CPU
snapshots. A child moves from its Linux process CPU clock to cumulative
``RUSAGE_CHILDREN`` under the same lock, so exit cannot omit or double-count its
CPU in a snapshot. Waiting polls outside this lock; it does not hold a lock while
waiting for a child to terminate. Live sampling uses the fixed Linux
``make_process_cpuclock(pid, CPUCLOCK_SCHED)`` ABI and fails closed if unavailable;
it does not round to ticks or silently omit a failed counter. Stage guards close
at worker transitions before verification helpers start. Reports retain per-phase
peaks, unchanged limits and the first violation. These counters still exclude
asynchronous kernel work. Unit regressions for
this handoff do not replace ARM64 budget enforcement or background-cost tests.

No business interference percentage without an aligned business denominator
and comparable baseline. Protocol-2 ABORT, task-start identity, object epoch and
preempted holder handling remain intact. Empty-root lifecycle stress is not
real-workload attribution. Fixture coverage does not imply all kernel locks.

Validation
----------
``test_session_report.py`` checks the request contract. ``session_vm.py`` uses
the disposable-initramfs marker and real namespace containers. It exercises
1/128/256 idle registrations, IP/owner, private/reused/preempted fixture paths,
cancellation, prepare failure, fixed repeat cycles and optional n=5 paired
costs. Preserve old analysis/owner/profile regressions; zero discovered tests
is not PASS. See the external validation record for actual pass/fail/blocked
gates. A COMPLETE session receipt does not mean the development phase passed.

Periodic control (P2)
--------------------
The same controller admits manual and periodic work. There is one active or
draining session per host and at most two targets per session. A configured plan
also limits manual requests, even when periodic scheduling is paused. Automatic
owner escalation is deliberately absent.

Configure and inspect without starting collection::

  {"version":1,"op":"schedule_configure","plan":{"interval_s":60,"window_ms":2000}}
  {"version":1,"op":"schedule_status","offset":0}
  {"version":1,"op":"status"}

``schedule_status`` paginates 16 roots, using ``next_offset``. Manual starts after
configuration must include the ``nonce_epoch`` returned by status. Changes to
configuration, history rotation and controller restart invalidate old epochs.
Persisted plans restart PAUSED and require explicit root registration; they do
not guess surviving container identities or replay missed slots.

Enable is a separate request::

  {"version":1,"op":"schedule_enable"}
  {"version":1,"op":"schedule_pause"}
  {"version":1,"op":"survey_report","target":"ID:GEN"}
  {"version":1,"op":"survey_epoch"}

Enabling requires ``--p1-acceptance FILE``. The private root-owned receipt uses
schema ``cis-p1-admission-v1``, has ``phase_complete=true``, matches the running
controller/worker/BPF/support-module hashes and kernel notes/release, and has
PASS for every key in ``periodic_plan.P1_CHECKS``. It must reference the raw
evidence index SHA256. This is a trusted administrator admission assertion,
not a replacement for auditing the actual evidence. Never create an all-PASS
receipt to get around failed or absent measurements. Old P1 blocked reports do
not qualify. There is no test flag to bypass this runtime gate.

At each due slot the least-recently-attempted root gets priority. Every fourth
slot may revisit a candidate using the second position. Missed slots are skipped,
not caught up. Jitter uses a recorded seed; it only extends the base interval.
No timer reads all roots' metrics every second. Waiting periods have no sampling
probes or PSI triggers. Manual diagnostics consume the same host interval.

The ideal round time is ``ceil(N/k)*interval``; the conservative fairness bound
is ``N*(interval+jitter)`` when roots are stable and every slot succeeds. Neither
is a valid-sample or discovery guarantee. A 60-second interval for 256 roots and
two targets takes at least 128 minutes per ideal round. Failures, manual work or
sample scarcity extend this. Plans cannot promise an infeasible sample-age SLO.

Survey semantics
----------------
Read only selected roots at session boundaries. Every counter file has its own
read timestamps. The snapshots enclose preparation/cleanup gaps, not an atomic
snapshot aligned to the exact perf window. Missing counters remain missing;
deletion, generation mismatch, counter reset and configuration change invalidate
comparison rather than creating zero deltas.

IP records carry session, root generation, CPU and sample weight. ``ip_event``
describes each CPU's sampling unit. Mixed/unknown PMU units are not summed or
ranked as a common cost and do not qualify as comparable surveys. Top IPs can
include interrupt context; this is not object-holder or causal evidence.

The first valid sample establishes a reference, not a healthy baseline. That
reference is frozen until the epoch changes, rather than learning persistent
anomalies as normal. A 1.5x rate increase AND an absolute increase of 10000
microseconds/second in CPU use or PSI wait is an experimental candidate rule,
not a validated interference detector. No business denominator means no business
interference percentage or cycles per successful operation.

Identity, CPU/memory configuration, collector and explicit administrative epoch
bind comparisons. Image, credentials, mounts and workload phases are not all
automatically visible; administrators must notify relevant changes. Reports
distinguish last service from last valid sample. Unobserved does not mean normal.

Budget and failure boundaries
-----------------------------
Slow ARM journaling, residue verification and final reporting use a single
bounded IO slot; no ARM before durable inventory and no next session before
publication. Initial admission persistence, registration and explicit recovery
still perform synchronous IO and need further fault/runtime validation. An
uninterruptible filesystem operation has no unconditional shutdown bound.

CPU guards use coarse child ticks and are cooperative, not instantaneous quotas.
Safe cleanup may exceed a budget; the result is downgraded, not reported as a
successful measurement. Management processes do not account for all BPF/PMU
entry work or asynchronous kernel reclaim. Per-session pre-write CPU is persisted;
post-publication CPU is available in live status, not recursively included in
the same write. Whole-cycle acceptance must measure the complete external window.

RSS includes sampled controller, worker and helper processes, can double-count
shared pages, and excludes kernel allocations. Default disk admission reserves
20 MiB per next session and requires 32 MiB free; total owned-session storage is
capped. Retention TTL may prevent reclamation, so storage exhaustion can suspend
service even with bounded memory. This is reported, not resolved by deleting
historical evidence or shortening TTL silently.

P2 validation
-------------
``test_periodic.py`` and ``test_periodic_controller.py`` exercise the model,
admission, budgets, identity/PMU boundaries, fairness, idempotency and asynchronous
publication. They are offline tests, not Linux resource or latency evidence.
``periodic_vm.py`` defaults to a negative missing-receipt test; positive mode
requires real P1 admission and runs two or three actual 60-second cycles with
namespace containers. It is functional, not n=5 cost/coverage acceptance.

All P1 runtime gaps and cycle-level P99/CPU/memory/coverage gates remain required.
Do not translate IMPLEMENTED, model PASS, missing hardware, or a gate refusal into
completed periodic runtime acceptance. Preserve original failed measurements.
Admission I/O and failure visibility
-----------------------------------

The first session journal and output-file creation use the same single bounded
I/O slot as the inventory and final journal. No worker exists during this first
step. Status, cancel, and stop remain available; a cancelled or timed-out
admission never launches its worker when the write eventually completes.
Metadata mutations are rejected while admission, capture, or journal work is
pending. The worker PID and inventory become durable before ARM, not by a
synchronous write on the event-loop thread immediately after spawning.

A crash between the initial journal and durable worker identity is deliberately
not recovered by guessing that no worker exists. Recovery requires an offline
process/object audit. A filesystem error may prevent the failure record itself
from being persisted; live status marks ``durable_result=false`` and FAULTED.
Bounded threads do not make a blocked filesystem operation interruptible.
Startup, history rotation and inactive administrative operations still need
separate storage-backpressure coverage; this change is not full P1 admission.

Worker receipts distinguish ``ENTRY_RATE_LIMIT`` from ``CAPTURE_ERROR`` and
retain the negative capture return code. Neither entry limits nor CPU limits
have been increased. A prefix stopped by an entry limit is PARTIAL, not a valid
full-window performance or attribution result.
