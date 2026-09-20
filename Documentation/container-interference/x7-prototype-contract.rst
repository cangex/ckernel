Bounded X0--X7 prototype acceptance
==================================

This is the minimum prototype contract from the 2026-09-18 development
plan, not a replacement for strict P1/production acceptance.  A periodic
profile is intended to explain observed contention on supported paths.
It cannot prove all-container interference isolation, full Linux coverage,
or sub-second detection between periodic windows.

``coverage_matrix.py`` still independently checks pinned raw serial files.
``prototype_contract.py`` now derives stage status from those results rather
than returning the old, unconditional ``x7_complete=false`` placeholder.
An empty/partial matrix, a failed cohort, guard-only Socket evidence, an old
base-summary timestamp or missing current-kernel joint regression cannot
close the prototype.  PASS_SCOPED always carries its scope and explicit
``production_accepted=false`` and ``full_linux_coverage=false`` fields.

Minimum stage evidence
----------------------

* X0: selective loading for all twelve collectors; shared manual/periodic
  budget; pause, restart, stale request, unregister and missed-slot handling;
  actual twenty-minute permit expiry; faulted refusal, worker termination
  and controller crash recovery.  Interrupted captures remain rejected.
* X1: generic slow-lock discovery, selected FD ownership and independent
  overlap denominator, rwsem write/read modes and bounded reader sets,
  lifecycle negatives, overflow degradation and dense FD guard rejection.
  Generic spinlocks do not acquire invented holders.  FD overlap recall is
  not pure-spin or causal-blocking recall.
* X2: native leaf/ancestor counter participants, initialization generations,
  limits, rollback, frequency/migration/private controls.  Common updates
  are not mutex ownership or hardware cache-line contention proof.
* X3: sampled allocation phases, releases, placement, native failure and
  partial rollback; Maple request/destination-tree association; selected
  SLUB node-lock ownership.  Full tree lifetime and other allocator locks
  remain outside the implemented relationship contract.
* X4: native logical Socket ownership, transfer/accept and netns identity;
  CPU quota and actual address-reuse negatives; backlog residence;
  original TCP header allocation, native refusal/recovery and release
  backend versus retained-clone references; capacity/rate guard rejection.
  A transformed child skb or payload is not assigned the original owner.
* X5: direct requests, tag waits, merge/source snapshots, requeue and partial
  completion, split/error/driver termination negatives, native writeback
  billing and bounded synchronous inode context.  Device-internal blocker,
  arbitrary cancellation interfaces and complete dirty-data ownership are
  not inferred.
* X6: actual sixty-second slots, two automatic specialists, one manual
  specialist, fairness/interleave and source/epoch checks; separately
  recorded pressure-to-candidate, queue and full-explanation clocks.
* X7: four rotating container roles, ordinary native file/VMA operations,
  independent mixed TCP/block truth and positive/negative specialist tests.
  Common, SLUB, rwsem, mixed, control and final routing cohorts must share
  the same built-kernel notes hash.  All raw cohorts keep their own tools,
  kernel and observation scope; historical measurements are never relabelled
  as new runs or as certification of future source revisions.

Evidence strength and remaining boundaries
------------------------------------------

Native runtime tests establish their own supported paths.  Deterministic
unit tests additionally reject malformed/lost/recursive/truncated records,
wrong identities, unsupported generations and incomplete source maps.
Those tests are not represented as new hardware ring-overflow experiments.
Historical failures, rejected high-rate captures and the development-only
fixture panic remain in their original artifacts.  A guard PASS only means
that rejection, detachment and continuing business work were verified.

CPU, RSS, map inventory, management cgroup and kernel-thread bookends remain
separate measurements.  They cannot be added into a complete monitor cost.
Source callbacks, asynchronous work and total kernel memory are still
incompletely measured.  The 40 ms combined-process CAPTURING guard is
unchanged; the old 40.600240 ms exception is not a general waiver.  Cooperative
guard overshoot is retained, not accepted as a complete profile.

P99 is record-only as authorized.  Ordinary application results lack a full
independent attribution population and do not certify precision/recall.
Positive fixture relations and negative controls cannot be replaced with
quiet ordinary windows.  No all-lock, hardware-SPE, bare-metal NUMA or
production low-overhead claim follows from prototype completion.

Timing correction
-----------------

The base summary is produced before specialist interpretation.  Previously
its timestamp was reused as full explanation latency.  The unified report
now timestamps the completed in-memory analysis, before serialization and
delivery.  The raw saved guest report is checked against the capture's
boot ID, monotonic clock, source window and raw hash.  Offline replay time
is retained separately and cannot substitute for live latency.  Older raw
reports are labelled ``legacy_base_summary_only`` rather than upgraded.

At tools ``6f83712af0cd05b1dcd2980c7029c778ca78642c`` and unchanged kernel
``55795f96b``, a new ten-session real routing run passed.  Full explanation
lag was 59.803900--292.964350 ms, excluding serialization/delivery.  The
controlled CPU-pressure onset to candidate took 59.958357--59.990065 s,
including the actual periodic slot wait.  Specialist queue delays were
57.891016, 177.728638 and 180.280246 s.  These are distinct measurements,
not a claim of detecting a general incident within 293 ms.

The original serial is
``x7-timing-6f83712af-20260920/routing/x6-diagnosis-20260920-111434.log``
below host14 ``/dev/shm/cis-x-20260919/evidence``.  SHA256:
``24f2b7fd8ffae1370cbe1ee0a538b6ccfd122b72a41882fb954ea65bbc9a2854``.
ARM64 preparation passed 660 Python, 21 owner and seven profile tests.
This timing cohort does not by itself complete the remaining joint audit.
