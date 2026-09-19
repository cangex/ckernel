Inode writeback bridge: isolated development evidence
====================================================

Scope and source
----------------

Kernel commit: ``2d449ba81``. Tool capture commit: ``dae385c88``.
No host kernel replacement, reboot, Docker restart or host block-device test.
The existing ARM64 config and the 40 ms CAPTURING process-CPU limit are unchanged.
P99 remains a recording item, not an acceptance waiver for identity or cleanup.

Full ARM64 Image and modules built successfully. Immutable artifact SHA256:

* Image: ``dea56d66ef0acf90ca3b6ce041122fdf18d08228701772a21f74967d7b0e3728``
* vmlinux: ``193ee9e8b7879dc4de9a5635bb9e6f03cb96c999fa49b006e9fdbe962b6b1594``
* config: ``678424d65838341018da716b6eb7f4e13d7213e56201ec97744d92708f156a65``

Native ext4 bridge
-----------------

``wb-bridge-loader-20260920/x5-writeback-20260920-031818.log`` contains the
frozen private/shared x OFF/block x three-round matrix: 12 states, six captures.
Its SHA256 is
``919add652a5fb467cf574b1a5ce5afa6f6135514dc3e3a29b89eced6a111f7fe``.
Independent container logs record inode number/device, byte ranges and write
intervals; post-sync content is reread and checked. Each capture observes 256 KiB
of completed data I/O, without turning server/worker activity into the writer.

All nine background data requests have a closed native inode context: two per
private-file capture, one per shared-inode capture. Each capture contains 64
dirty-folio transitions, including both registered actors. There are respectively
4/3/4 private and 2/3/2 shared native writeback contexts; metadata-only contexts
are not invented as data requests. No private inode is assigned to the other
container. The shared inode is not assigned an exclusive writer or blocker.

The bridge is request *submission context*, not a claim that every merged bio
belongs to that inode. Dirty-transition observations remain separate because
inode address/number/generation do not prove lifetime until a later writeback.
The native I_SYNC call supplies the narrower lifetime used for request bridging.

CAPTURING process CPU peaks at 11.660060 ms across these six captures; combined
RSS peaks at 38,731,776 bytes. Preparation/report costs are not zero: recorded
process CPU through reporting peaks at 214.192220 ms. The first private capture
records 1,345,136 bytes of map fdinfo, 61,440 program-page bytes and 557,056 perf
mapping bytes. These inventories overlap RSS and exclude auxiliary/JIT/perf and
asynchronous costs; do not sum them into a complete memory or CPU claim.

Preserved failure
-----------------

``wb-bridge-runtime-20260920/x5-writeback-20260920-031316.log`` is the earlier
failed development run at tools ``83e8a1110``. The C loader whitelist omitted
``wb_pending`` and the new programs, so the verifier rejected block_start before
sampling. This is not a successful capture. Commit ``dae385c88`` fixes the
whitelist and adds a compiled exhaustive C-versus-Python contract test. No budget
or data-quality rule was weakened to pass.
Failure log SHA256:
``26ad8f448b0e2d8601e670ddd5eaac55e83e47c760ec56c7ea7e497413d9d821``.

Readers and boundaries
----------------------

All 44 previous pinned evidence cohorts and the five new cohorts replay without
failure with the new reader (49 total). New inode-context coverage is a separate
category; old billing-only cohorts cannot satisfy it. At this checkpoint X7 remains incomplete: this cohort
does not validate all networking/allocator paths, production incidence, complete
background costs, high-rate behavior or a unique blocking tenant.

New-kernel regression
---------------------

All following runs use kernel ``2d449ba81`` and capture tools ``dae385c88``.
The Linux build/prepare tests pass 573 tests; the same local macOS run has one
Linux-only CPU ABI test skipped, not counted as a local PASS.

* Control: 16 checks, 14 sessions, PASS with complete scope audit.
  ``wb-bridge-x0-control-20260920/x0-control-20260920-032108.log``
  SHA256 ``fda5bb135e15bd69a1dba02be32de62779970616bda35eb279d4c71c7cc2f425``.
* Crash/cleanup: 16 checks, 16 sessions, PASS for the intended failure/cleanup
  outcomes. Interrupted capture scope is incomplete, not accepted data.
  ``wb-bridge-x0-crashes-20260920/x0-crashes-20260920-032416.log``
  SHA256 ``33cb7f69deb2d87e70913a581ea36537f571db6cd4bfb12710aa2b5fed0f05d5``.
* Native request merge: 12 states, six captures, PASS; CAPTURING maximum
  10.596020 ms. ``wb-bridge-merge-scheduler-20260920/x5-fixture-20260920-032458.log``
  SHA256 ``60a6d95cb877fff37d33540a160ddec5436fec4081bd14b484d31bb7582594a0``.
* Four-container application: 33 states, 30 captures, PASS_SCOPED, 198,000
  completed operations with zero errors or timeouts.
  ``wb-bridge-x7-joint-20260920/x7-joint-20260920-032535.log``
  SHA256 ``e293b05dbe832d9dc6a6329b1a5fc8456299d3df97f3c5af0b9bccf3a9f1a2a9``.

The joint CAPTURING maximum is 27.668060 ms; combined RSS maximum 38,502,400 bytes;
process CPU through reporting maximum 186.851320 ms. Target/bystander maximum
absolute P99 changes are +0.493340/+0.483400 ms and minimum throughput changes
are -0.037436%/-0.010786%. These are fixed-offered-load VM comparisons, not
saturated throughput or production low-latency acceptance. Complete kernel,
business-thread probe, asynchronous CPU and memory totals remain unproven.

The deliberately SIGSTOP'ed worker triggers the unchanged CPU limit at
40.019750 ms, ends FAILED, and is rejected. Its final CAPTURING accounting
reaches 113.090730 ms while cooperative stop/cleanup completes. Cleanup PASS is
not capture PASS, a new budget waiver, or proof of a hard-realtime 40 ms cutoff.
