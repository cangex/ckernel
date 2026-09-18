Measurement and bounded failure evidence, 2026-09-18
===================================================

Status
------

P1 remains BLOCKED; no positive periodic P2 run or acceptance receipt was
generated. These results extend ``closure-pilot-results.rst`` rather than
replacing its historical measurements. They do not establish a new observer
performance improvement.

Only the dedicated 8-vCPU, 4-GiB ARM64 KVM environment was used. Host CPU
affinity is not exclusive ownership. The host kernel was not replaced; the
guest Image was reused only after checking that the kernel-side sources did
not change. Userspace and BPF binaries were rebuilt for the functional runs.

Frozen calibration
------------------

``repeatability_vm.py`` executes the predeclared two-boot, five-pair-per-boot
OFF/OFF protocol. Both roles rotate CPUs; A/B order alternates. Throughput and
open-loop latency are separate tests. The window is 2 seconds, arrival rate
2000/s, and 4096 warmup operations finish before the scheduled boundary.
There are no collectors, tracing, or per-request timeline exports in this
calibration. All pairs and both boot blocks are retained.

The pooled paired 95% intervals, in percent, were:

.. list-table:: Pooled paired differences
   :header-rows: 1

   * - Metric
     - Mean
     - 95% interval
   * - Target throughput
     - +0.14424
     - [-0.01243, +0.30090]
   * - Bystander throughput
     - +0.17580
     - [-0.07049, +0.42209]
   * - Target P99
     - +4.84424
     - [-9.89992, +19.58840]
   * - Bystander P99
     - +4.50725
     - [-10.49792, +19.51242]

The throughput boot blocks also satisfy the +/-1% calibration band. The
latency blocks do not satisfy +/-2%. This is uncertainty in OFF/OFF, not a
measurement of monitoring overhead. The paired-t intervals are conditional
on their sampling assumptions; ten pairs are not ten independent boots.
Timeouts remain in raw output, and any timeout now prevents latency
calibration PASS even if A and B have identical P99 values.

The separate clock diagnostic produced 45 exchanges. Host schedstats was
disabled: host runnable-wait and timeslice deltas are UNKNOWN, not zero.
The 0/10 ppm drift hypotheses were inconsistent with the samples. Under an
explicit 100 ppm hypothesis the midpoint alignment interval was 148935 ns
wide. The observed P99 values were 89820 and 88420 ns, whose 2% changes are
about 1.8 us. This transport-based alignment cannot support event-level
host-preemption attribution at the required scale. A channel-reset error
after the guest service closed is retained in the diagnostic output.
No host setting was changed and the diagnostic CPU cost is not included
as a production observer-cost estimate.

Bounded raw evidence
--------------------

``runtime_evidence.py`` and ``lifecycle_evidence.py`` now cross-check:

* Three cancellation phases and eight explicit fault boundaries.
* The complete RLIMIT_NOFILE 4..24 sweep, including actual getrlimit readback.
* Before/after enumerable BPF inventories for all 29 resource-fault cases.
* Worker kill, worker stop, controller stop/resume, controller kill, and
  combined worker/controller kill. Raw signal results, PID/start-tick
  lifetime, armed-window observations, FAULTED barriers, recovery requests,
  and durable records are required rather than test-output PASS labels.

These subclaims passed in a new isolated VM run. Enumerable object absence
does not prove completion of deferred memory or CPU reclamation. The five
crash cases do not cover every publication/storage/concurrent-restart path.
Subclaim failures propagate to broad P1 FAIL, while passing subclaims alone
cannot upgrade a broad gate to PASS.

``identity_evidence.py`` separately checked the controlled migration test:
61 pre-boundary samples attributed to A, 110 post-boundary samples to B,
2 boundary-ambiguous samples retained, and zero wrong attributions. This is
not a proof of all registration races or short-lived descendant coverage.

``kernel_resource_audit.py`` binds program/map IDs to session ownership and
records fdinfo and program metadata. The latest functional run reported
1120 IP and 6720 owner JIT code bytes. These are payload lengths, not memory
allocations or total residency; JIT layouts may differ between loads. Total
allocation upper bounds and background CPU remain unknown. Do not add
worker CPU to reaped-child CPU, or perf mmap to RSS without deduplication.

P1 evidence contracts
---------------------

``p1_admission_check.REQUIRED_EVIDENCE`` gives each of the 15 gates an explicit
required-evidence description. Missing coverage is not a generic PASS/SKIP.

* Identity: controlled migration is implemented; races, short-lived
  descendants and non-target owner truth still need complete raw readers.
* Lifecycle: bounded cancellation and crash recovery are implemented;
  concurrent restart, publication failures and their admission barriers
  remain incomplete.
* Resource failure: boundary and real FD failures are implemented;
  allocator-internal loading/memory failures remain incomplete.
* Storage: initial real ENOSPC alone does not cover ARM/DRAIN/publication,
  blocked storage or bounded recovery.
* Combined CPU: live/reaped-child tests do not replace runtime stop-handoff
  and post-stop residual measurements.
* Kernel background and total memory: JIT/BTF/verifier transients, perf
  metadata, static monitoring structures, page deduplication, business-path
  observer CPU, kworker/RCU attribution and deferred retention are missing.
* Owner truth: historical fixture/model results do not substitute for a
  complete source-bound mutex and real lockref truth reader.
* IDLE throughput/P99, IP/owner capture quality and window throughput,
  and the window-latency contract require a complete frozen performance
  batch. This functional batch intentionally grants none of these checks.

No new OFF/ON batch was run after calibration failed. Collector metadata
export changed during this phase, so historical observer costs cannot be
assigned to the new binaries. N4 performance optimization, N5 acceptance
and N6 positive periodic validation are not complete.

Evidence index
--------------

Raw evidence is administrator-only and is not committed to this repository.
Remote directories below are relative to
``/root/cis-20260916-232524/evidence``. Archive SHA256 values bind the evidence:

* ``p4-calibration-20260918-1/evidence-v1.tar.gz``:
  ``1cabcf1c4a119b3110a2e28e576fd31e9a9ce6fb8de0489024aaccfaeeb51863``.
  Workload/protocol source: ``3e428fd0f``.
* ``p4-runtime-20260918-1/evidence-v1.tar.gz``:
  ``64aac5f8c574edf15d8feac8c56f72deba56a21e1639d6f2c686b56b2d8e2637``.
  Runtime source: ``da4717fcd``. Use the corrected
  ``clock-analysis-v2.json``; the earlier analyzer did not guard disabled
  host schedstats and is retained only as historical output.
* ``p4-fault-audit-20260918-1/evidence-v1.tar.gz``:
  ``7daea986be440db810d8e99f73a9f81e4481ee3b878d797474ab89d22c98527a``.
  Runtime source: ``34180f07865b98531b84294037717477f8c04671``.
* Final reader re-evaluation and regressions:
  ``p4-final-20260918-1``, analyzer source
  ``ea2ac9ab9ec799951ac72988026c55b8bf95f155``. Changes after the fault run
  affect analysis/tests only, not its runtime binaries.

The final ARM64 run passed 181 discovered unit tests, the separate 19-case
owner suite, the separate 7-case profile suite, and the native recursion
snapshot check. These suite counts are not a count of independent performance
observations. Local macOS discovery passed 180 with one Linux-only skip.

Next executable work
--------------------

Continue the independent storage/CPU/failure readers and resource accounting
without relaxing the P1 contract. For latency, declare a revised diagnostic
protocol before running it; do not retry the identical calibration until
it passes, alter timer slack silently, or dilute a 2-second sampling impact
in a longer cycle average. Host isolation or finer host tracking that
changes the protected environment requires separate authorization. Do not
start positive periodic acceptance before all applicable P1 gates pass.
