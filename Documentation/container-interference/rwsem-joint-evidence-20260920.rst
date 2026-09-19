Selected rwsem source filtering and joint evidence, 2026-09-20
============================================================

Scope and frozen sources
------------------------

This is exclusive ARM64 VM evidence, not a host deployment or production
certification. The host boot ID remains
``20bf4ee1-355a-4c77-a494-0c265b05c8d5`` and its kernel was not replaced.
Kernel and joint producer commit: ``ee63990ca``. Image SHA256:
``d340a090e7317ac6b8b59a9a430f125684277475d92262788a8c27631a2f74e3``.
Complete Image and modules builds succeeded without a configuration change.

Raw evidence is retained beneath
``/root/cis-20260916-232524/evidence/``. Joint serial:
``rwsem-filter-joint-20260920/x7-rwsem-joint-20260920-003927.log``, SHA256
``35abca9f5810d6e460185f6e0110908432061423a191507239bc07d4725ccaf2``.
Reproduce the independent check with ``rwsem_vm_check.py SERIAL OUTPUT --joint``.
Its result is PASS_SCOPED, with no errors; it does not set X7 complete.

Failure retained, not threshold relaxation
-----------------------------------------

The earlier producer ``efafc74a7`` on kernel ``63df60de9`` aborted the first
ON state at ENTRY_RATE_LIMIT: 735326 BPF entries, eight emitted rows. The
failed serial SHA256 is
``67bf6c1027f21494f1c98aff718c42b1b1af75658fa0165561c4c2651865f564``
under ``rwsem-joint-runtime-20260920``. It is not reused as a complete cohort.

Moving address selection before BPF removes unrelated callbacks, rather
than hiding them after entry or raising the protection threshold. Fifteen
native lease checks verify rejected malformed input, exclusive and immutable
selection, readback, close, killed owner and subsequent reopen. The new
contract requires corresponding source-selection receipts. Historical
receipts remain explicitly historical and cannot satisfy joint plan v2.

Observed result
---------------

* Ten native rwsem cases, three alternating OFF/ON pairs: 60 states and
  30 complete captures. Four ordinary container workloads per state produce
  360000 successful operations, no errors and no timeouts.
* All 24 predeclared eligible native hold/attempt relationships were
  recovered. Private objects and unsupported attribution cases produced no
  false E2 promotion. This denominator is the controlled fixture population,
  not all ordinary rwsems or real application contention.
* Per ON-state bookend native entries: 1502729--1535124; rejected before BPF:
  1502725--1535108. Only 4--16 selected entries reached BPF. These are event
  counts, not CPU-time savings; native equality checks still cost CPU.
* CAPTURING combined-process CPU median 9.912275ms, maximum 10.772220ms,
  against the unchanged 40ms policy. Combined process RSS maximum
  35209216 bytes. Neither metric includes all native hook/RCU/kernel costs.
* Arrival-relative P99 worst increase: target 1.257780ms, bystander
  0.682040ms. These are recorded fluctuations, not an accepted low-tail gate.
  Fixed-arrival throughput is demand-limited; its stability does not prove
  unchanged saturated capacity.

Background and memory boundary
------------------------------

Same-case, same-round ON minus OFF management-cgroup bookend CPU ranges
96.844--164.938ms, median 116.738ms. It includes initialization, verifier,
controller, worker, snapshots and result handling; it is not CAPTURING-only.
Do not add it to the process CPU metric as an independent cost.

Matched kernel-thread bookend CPU difference ranges -40--20ms, median zero,
at 10ms tick resolution. There were no capped scans or scan races, but 11
new/gone thread keys across the state bookends. Their lifetime CPU and
softirq in business context are not recovered by this measurement.

Management cgroup cumulative peak reaches 68558848 bytes (includes the
harness and retained results); this is not a per-capture observer-only peak.
Whole-VM Slab increases in ON bookends range 487424--2060288 bytes, also not
exclusive attribution. Full background CPU and kernel memory remain
incomplete. Neither zero tick differences nor zero memcg kernel subfields
prove zero cost or compliance with a total resident-memory target.

Recovery regression
-------------------

Control producer ``8f21f9534`` on the same Image completed 16 crash/recovery
checks. ``rwsem-filter-crashes-20260920/x0-crashes-20260920-004753.log``
shows rwsem source and filter active before SIGKILL, both inactive after
verified cleanup, followed by a successful new filter lease. Interrupted
sessions have incomplete terminal scope counters by design: cleanup PASS
does not certify their diagnostic evidence. Crash serial SHA256:
``91e3d6ec2e380cfb9620fd585e279c8c5f0403748683ba0110c163a6b9618ba8``.

``rwsem-filter-fault-20260920/x0-fault-20260920-010510.log`` also passes the
independent failure-injection check: a deliberately failed cleanup verifier
keeps admission FAULTED even when a separate real verifier confirms objects
absent. This is one case/session, not a successful diagnostic capture.
SHA256 ``e62a4f42882b295ca74f37ad018158ac2cb395a8a04048b59761c8f444f14099``.

The same producer/kernel also completed the following independently replayed
cohorts. Ordinary application runs do not add a forced positive truth
denominator for quiet resource collectors.

* ``rwsem-filter-control-20260920/x0-control-20260920-004949.log``:
  16 control checks, 14 sessions, complete terminal scope audits. Includes
  selective source activation, stop/restart budget preservation and real
  missed-slot handling. SHA256
  ``89317d757da8edd10077542a396cb0b006b256307d33a1ca34218bd1117a5b38``.
* ``rwsem-filter-common-joint-20260920/x7-joint-20260920-005424.log``:
  33 states, 198000 operations, no errors/timeouts. Maximum CAPTURING
  process CPU 30.481180ms; RSS 38576128 bytes. Worst P99 increase 0.443090ms
  (net, round 1, bystander). SHA256
  ``94b02ba046619a8ca44a29f0e5afa59ab1da153b7cd0f8ec4d9f6ab9961b7bcc``.
* ``rwsem-filter-slub-joint-20260920/x7-joint-20260920-010307.log``:
  six states, 36000 operations, no errors/timeouts. Maximum CAPTURING
  process CPU 11.533910ms; RSS 32182272 bytes. Worst P99 increase 0.346830ms.
  SHA256 ``4fb6abe1642c65dc61e07e3c3e499b8d3c463f1531148abcfb561395c672b962``.

These new tail observations do not erase the previous batch's unexplained
6.938470ms increase and are not proof of its cause or repair. All process CPU
policies remain unchanged. Whole-kernel/async cost is still incomplete.

Remaining work
--------------

The 32 historical cohorts independently replay with no new failures. They
remain pinned to their own kernels and producers. Current-kernel ordinary
joint and control regressions above are separate evidence. Mixed-resource
independent truth, complete asynchronous cost, Maple tree ownership, broader
skb provenance and block multi-source boundaries are not solved by this
rwsem-specific fix. X7 remains incomplete.
