Block provenance runtime evidence, 2026-09-20
============================================

Scope and frozen inputs
-----------------------

All runs used the dedicated ARM64 KVM guest on host 14, not a replacement host
kernel.  The host boot ID remained 20bf4ee1-355a-4c77-a494-0c265b05c8d5.
Kernel source was 9c96024e4, configuration SHA256
678424d65838341018da716b6eb7f4e13d7213e56201ec97744d92708f156a65.
Full Image and module builds returned zero.  Image SHA256 is
e06cd9c713551caa31b864f3a06acf4dd4ebfd14744286d7f0add3c45483a294;
vmlinux SHA256 is
82b376355cec32521eeaaee042cd358e164d147651511416f30bd2d3f5e96cd2.
Tools/fixture revisions were 10e65b72c (bio merges), a421fd7e9 (partial,
requeue and control), and 64d7c474e (mq-deadline request merges).

Native transitions, independently checked
-----------------------------------------

* Bio merging: 24 fixed states, 12 captures.  The driver dispatched 30 observed
  requests and the collector observed 60 native bio appends.  Front/back merges
  and nonadjacent controls passed.  Six nine-bio snapshots retained exactly
  4096 unknown bytes each out of 36864 remaining bytes, rather than attributing
  the unwalked ninth bio to the submitter.
* Request merging: 12 states, six captures.  The two-container mq-deadline
  bridge/control cohort observed 24 request episodes, 18 dispatched requests,
  six bio appends and six request-to-request transfers.  Victim merge terminals,
  survivor generations, byte ledgers and driver dispatch/data truth matched.
* Partial completions: 12 states, six captures, 96 observed requests.  Each
  4096-byte request completed in two 2048-byte pieces, without double counting.
* Requeue: 12 states, six captures, 96 requests and 192 issue snapshots.  A
  retry snapshot did not become an additional submitted request or byte total.
* Control: 16 checks and 14 sessions passed, including source switches and
  object cleanup.  Crash cohort: 16 checks and 16 sessions passed recovery.
  Interrupted captures deliberately lack complete terminal scope counters;
  this is a recovery pass, not acceptance of those interrupted samples.

The merge fixture never emits Profile trace events itself.  It invokes native
submit_bio, plugging, scheduler, dispatch and endio APIs.  Native cgroup merge
rules are retained.  These are controlled transitions, not a production
device-contention frequency or a full causal blocking graph.

Measured process costs
----------------------

Maximum combined process CPU during CAPTURING was 10.299730 ms for bio merges,
9.866110 ms for request merges, 9.126230 ms for partial completion and 9.455410 ms
for requeue.  The 40 ms cap was unchanged.  Peak combined RSS in those four
cohorts was respectively 36175872, 34545664, 34553856 and 35278848 bytes.
For the bio-merge cohort, process CPU through reporting reached 194.689840 ms:
the capture-phase number is not an end-to-end observer CPU claim.  Native
probe work charged to business tasks, asynchronous backend work and complete
kernel memory remain outside a total-cost certification.

Raw evidence
------------

Remote evidence base: /root/cis-20260916-232524/evidence/.
Each directory contains status, source/kernel inputs, build and execution
logs.  Replayers read the raw serial export rather than trusting guest PASS.

=============================== =========================================
Directory suffix                Serial file
=============================== =========================================
block-provenance-merge-20260920   x5-fixture-20260920-013941.log
block-request-merge-20260920      x5-fixture-20260920-015537.log
block-provenance-partial-20260920 x5-fixture-20260920-014419.log
block-provenance-requeue-20260920 x5-fixture-20260920-014541.log
block-provenance-control-20260920 x0-control-20260920-014738.log
block-provenance-crashes-20260920 x0-crashes-20260920-015216.log
=============================== =========================================

Serial SHA256 values in the same order::

  4d5f44c5d79d5c0e7a6038d28483fc0cbb11960ca9340b022c6b88935a4cf7e8
  870f229a787c115fb8f27242002f4276655637ee52ae4d32109fde3117b461f3
  9c1f05aeca0afd4e6782ddc8eea48fb158411f0cffac455668a4d456169b290e
  f4fe3f8e2b78e5fb6a9d62d7ac4e28cd40d07d5ad00647b71e9f0d456641b731
  dfeedc4e44b1bbb505a113b6bcd807fea6f702bbc0ecd6795a53a98a5f2e8cd6
  b59ece9d48efb60b78f18c2a024ccee2d27641720092cf206fbbf448d216bcb8

Control and crash hashes, verifier hashes and per-cohort outcomes are also
recorded in the external content-bound coverage index.  Reports expose bio
blkcg weights separately from the submitter and never label device peers as
unique blockers.  The offline evidence index capacity is 64; live admission
limits did not increase.

Remaining scope
---------------

This closes the tested native bio/request merge gap, not all X5 or X7 work.
Buffered writeback dirtying provenance, split/cancel runtime negatives,
high-rate overload, skb allocation/backend provenance, Maple tree identity,
and the remaining joint truth/complete background-cost gaps remain explicit.
No production, bare-metal NUMA, E3 causal, or total-memory acceptance follows.
