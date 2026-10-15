Verification checkpoint, 2026-10-15
===================================

This is an incomplete engineering prototype, not T0-T7 acceptance or a
performance claim. The original four comparison conditions are retained.
No physical disk was initialized, no host reboot or global security/propagation
policy change was performed. Native tests used exclusively created, allocated
regular-file pools. The installed kernel is the observation-modified
6.6.0-wb-mmuobs-20261011, not an unmodified OLK kernel.

Executed evidence
-----------------

* 38 local unit/model tests pass. They are not power-loss/concurrency proofs.
* Native normal integration r2 passes: two snapshots and one freshly formatted
  branch have different ext4 devices/journal interfaces; same-path writes,
  hardlinks, rename/unlink, xattrs, fsync sentinel, FD refusal, immutable
  template verification, sealed readback, inactive thin_check and full cleanup.
* Container integration r2 passes: actual container device/inode matches,
  SELinux Enforcing/container_t, write/fsync, stopped-container reference
  refusal, template verification and normal full cleanup.
* Go admission: S/G/F/B each have three independent solo runs, all 12 official
  evaluations pass. Every task/batch uses new thin IDs. All 16 recorded ext4
  geometry observations match their requested bytes/inodes/journal budgets.
* All 12 final cost snapshots occur after every business end and before scoring.
  Actual final snapshot lag is 310.885-448.543 milliseconds. There is also a
  startup-barrier interval. This is ordered coverage, not exact business-only
  CPU or physical memory attribution.
* Admission concludes with every branch/template DELETED and the pool removed.
  Deletion during service retained backing reservation until final pool removal.

Preserved failures and repairs
-----------------------------

Native r1 refused a propagated mount reference. The owned mount was removed
normally after checking same-device/root/path propagation mirrors and no open
references. No foreign namespace was entered. A losetup empty-output parsing
failure after successful detach was reconciled from actual loop state, not
by repeating deletion. Original failures are retained.

Container r1 could not use a proc-root alias into a private namespace: Docker
resolved it to a host path where the mount was not visible. The bounded revision
uses a host-visible owned mount. Its propagation mirrors are audited; unmount
and remaining-reference checks must both succeed. An exited namespace number
was observed reused by an unrelated process with no branch mount; recovery
therefore relies on actual device/reference identity, not the old namespace
number. That unrelated process was not modified.

The failed container branch was reconciled only after no mounts/FDs/container
references remained, zero DM open count, and clean filesystem validation.
Results were sealed before explicit discard of this failed test's own data.

Observed solo admission means, seconds
--------------------------------------

.. csv-table:: Descriptive admission means only
   :header: "Arm", "Preparation", "Business", "Cleanup", "Observed turnover"

   S, 1.961955, 2.263960, 3.994058, 12.942941
   G, 2.328968, 2.302001, 6.872356, 16.238624
   F, 0.362843, 2.303639, 3.994442, 11.496514
   B, 0.296325, 2.297617, 3.988282, 11.207481

These are correctness-admission observations, not an independent pilot or
formal effect estimate. Turnover includes container setup, fixed start gate,
official scoring retention and cleanup. It is not immediate production deletion
latency. Preparation excludes separately measured one-time pool/template setup.
S/G prepare their full grouped geometry even for solo; F/B preserve the target
task's 768MiB geometry. All arms reserve the same 24GiB pool infrastructure.
No loaded denominator exists, so no interference rate or net benefit is given.

Acceptance still missing
------------------------

T1/T2 are implemented prototypes with normal-path validation. T3 remains
incomplete: create_snap/delete/format intent ambiguities are quarantined rather
than fully reconciled. Control-crash points, data/metadata no-space, guest crash
and recovery have NOT_RUN in a qualified isolated VM. Existing old guest images
lack Python/dmsetup and require a separately prepared test environment; their
presence does not satisfy VM readiness.

T4 admission and completion ordering pass, but late observation and unique
physical/background cost attribution remain unresolved. T5 pilot, formal paired
blocks, 24-way comparison and five fresh waves are NOT_RUN. T6 resource cost
diagnostics are NOT_RUN. T7 final net-benefit verdict is NOT_ESTABLISHED.
run_matrix.py deliberately exposes admission-only mode until these gates are
implemented and validated. No automatic continuation service is installed.

Reproduce local logic tests
--------------------------

From the source checkout::

    make -C tools/ckernel_taskfs test

Native integration requires explicit root authorization, a new private output
directory and the documented capacity protection. Never substitute a physical
disk or existing LV. The Go runner verifies the frozen replay SHA, seven input
hashes, boot/kernel, ARM64 image, topology and SELinux before executing.
