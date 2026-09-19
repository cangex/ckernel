Buffered writeback and regression evidence, 2026-09-20
====================================================

Scope and frozen inputs
-----------------------

X7 remains INCOMPLETE. These are scoped ARM64 KVM results on the dedicated
development VM, not a host-kernel deployment or production acceptance.

* Frozen kernel source: 9c96024e4 (unchanged from the previous complete build).
* Image SHA256: e06cd9c713551caa31b864f3a06acf4dd4ebfd14744286d7f0add3c45483a294.
* Config SHA256: 678424d65838341018da716b6eb7f4e13d7213e56201ec97744d92708f156a65.
* Runtime tool source: 4720d5f4f; later verifier changes add stricter byte
  conservation and clearer unknown-epoch reporting, not changed raw evidence.
* Host root: /root/cis-20260916-232524/evidence. Local evidence is in
  .codex-tmp/container-interference-20260916 beneath the development workspace.

Results
-------

Buffered ext4: 12 OFF/block private/shared states, three preordered rounds,
six captures. All data verifies after syncfs and eviction of the tested range.
The captures contain nine completed background requests: two per private
case and one per shared case. Exactly 256KiB of test data completes per
capture, with 128KiB from each billing root in private cases. Each shared case
has two real writers, but its observed bio billing is one root, including a
different root in the last round. The report retains unknown dirtier/inode
ownership, rather than interpreting the billing root as the only writer.

* Buffered serial: x5-writeback-20260920-023324.log
  (writeback-epoch-20260920 remote cohort).
  SHA256 fffde51a05b5620e241fbfd310b228e08762c4da46296ddd3d811ee8854f609c.
* Request merge regression: 12 states, six captures, PASS.
  x5-fixture-20260920-023958.log;
  SHA256 0fdb7461c6d5c7bdbdea439c9e967388b3255e2d36a39044210f14676f5637a2.
* Source/control regression: 16 checks, 14 sessions, complete scope audit PASS.
  x0-control-20260920-023607.log;
  SHA256 38bf4fcca256cf655e832c8082fd810d6b7866d6e60fcd7251bc38723d7a1a93.
* Crash regression: 16 checks, 16 sessions, cleanup PASS. Interrupted captures
  remain incomplete; they are not accepted interference evidence.
  x0-crashes-20260920-023915.log;
  SHA256 6e480f9d1f3415060dcdaf4b3ce80ee4b0bae182c6ec41f1e6606ba070b71cc9.
* Four-container ordinary joint regression: 33 states, 198000 completed
  operations, zero errors/timeouts, PASS_SCOPED.
  x7-joint-20260920-024035.log;
  SHA256 c3484845c9f8f51ba1365af90512fac03019ee39c0eb2c9069d5d5b445f8e0d6.

The four regressions reside under writeback-x0-control-20260920,
writeback-x0-crashes-20260920, writeback-merge-scheduler-20260920 and
writeback-x7-joint-20260920. Local copies share the parent
writeback-regression-evidence-20260920. All were replayed from raw serial.
The cumulative x-coverage-writeback-input-20260920.json has 44 accepted scoped
cohorts with zero replay failures; the overall status remains INCOMPLETE.

Cost, warnings and failed development states
-------------------------------------------

Normal capture process CPU maxima: buffered 10.019850ms, request merge
10.130660ms, ordinary joint 27.052490ms. Buffered combined RSS peak is
36831232 bytes; ordinary joint is 35352576. Buffered process CPU through
report generation reaches 170.442230ms, so the 10ms capture value is not an
end-to-end overhead claim. Native probe execution in worker/business context,
asynchronous residuals and all kernel memory are not fully accounted.

The intentionally stopped-worker crash case trips the unchanged 40ms
CAPTURING budget at 40.182820ms and ends at a recorded peak of 113.523000ms.
Its result is FAILED and its data is rejected. Cleanup passed; this does not
mean the CPU limit was met or that cooperative stopping is hard realtime.
No new budget exception was granted.

Ordinary joint maximum P99 increases: target +0.307320ms, bystander
+0.715580ms. Minimum observed throughput changes at fixed offered load are
-0.027862% and -0.023285%, respectively. P99 is record-only and this is not a
saturated-throughput acceptance. Earlier worse tails remain in older evidence.

Two failed development cohorts remain preserved:

* writeback-admission-20260920: BPF verifier rejected a 544-byte combined
  stack before capture. Fixed by reusing unused event fields, not by raising
  a verifier limit or adding an unbounded scratch map.
* writeback-stack-20260920: valid background requests had an early kernel
  thread start epoch of zero; the previous reader rejected them. The corrected
  reader preserves unknown thread lifetime and passes the available first
  case, but the old incomplete matrix is NOT relabelled as a complete run.

The new full buffered cohort was run only after both corrections. Local
563-test discovery has 562 PASS and one Linux CPU-clock ABI SKIP on macOS;
runtime preparation independently passed its then-frozen Linux tests.

Remaining work
--------------

The new admission fixes previously invisible background bio submissions.
It does not yet join initial dirtying events to inode writeback episodes and
then to requests, prove unique device blockers, or finish split/cancel and
high-rate coverage. Sampled skb allocation/backend provenance, explicit Maple
tree identity, mixed-source independent truth and full background-cost
accounting remain open. None becomes PASS merely because the ordinary joint
workload is quiet for that adapter.
