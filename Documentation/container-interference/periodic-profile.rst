Single-shot profile foundation (P0/P1)
====================================

Scope
-----
Explicit single-shot IP or owner captures, not periodic scheduling, automatic
optimization, CKernel integration or completed S6. Standard-library Python
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
collisions are rejected. Idempotency history is bounded at 256 persistent records;
archive explicitly when idle rather than silently reusing an evicted nonce.

Lifecycle
---------
ADMIT -> PREPARE -> ARMED -> CAPTURING -> DRAIN -> VERIFY -> IDLE.
Uncertain cleanup yields FAULTED. COMPLETE/PARTIAL/CANCELLED/FAILED are separate
results: safe cleanup does not imply complete evidence.

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
CPU guard 20 ms/s; combined RSS guard 64 MiB. These are watchdog thresholds,
not kernel worst-case latency guarantees. Controller+worker CPU and kernel
allocations remain acceptance measurements: RSS and worker guards alone do not
prove the inclusive 64-MiB/20-ms contract. Preparation and drain are not hidden
outside cost accounting. PMU fallback, multiplexing, losses, incomplete owner
boundaries and output failures must remain visible.

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
