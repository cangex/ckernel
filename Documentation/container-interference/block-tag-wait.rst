Block tag slowpath observations
==============================

The optional CIS source in ``blk_mq_get_tag`` records the first failed
allocation, each real ``io_schedule`` entry/return, a tag found by the retry,
and immediate NOWAIT rejection. Immediate successes are not traced. With
CONFIG_CIS_OBSERVE disabled there is no source call; otherwise the native
tracepoint static key is disabled unless a collector is attached. There is
no source clock, global owner table, allocation, or new blocking operation.

The block bundle adds one raw tracepoint program and a hash with at most 256
pending calls keyed by TID and task start. Targets and the existing 2-second
session/entry/output budgets still apply. A stale or nested pending call
cannot silently replace another episode. Buffer loss, map capacity,
expiration and missing pairs remain audit facts. Stack collection occurs
at call start, not each wakeup. Source switches use version 9; version 8
historical block bundles are read-only and cannot be admitted for live use.

An allocation can enter this path because of tag availability or fairness
rules. The complete slow call includes queue kicking and retries; only
explicit sleep pairs identify time inside ``io_schedule``. Neither metric
is pure device delay or spin cycles. A returned tag can still be discarded
for an inactive hardware context. It is not request completion or even a
guarantee that the enclosing allocation succeeds.

CPU/hardware-queue migration may change the bitmap between wakeups. A pair
retains its original bitmap; different episodes do not establish that an
address has a durable object lifetime. The starting container and later
identity changes remain distinct. A queue or bitmap shared by two waiting
containers does not reveal which outstanding request occupies a slot or
which container causes the wait. These records provide E1 wait facts, not
unique-holder or E3 causal claims. Merged bios, writeback provenance and
unobserved device internals remain outside this extension.

Implementation and parser regression do not constitute isolated runtime
or overhead acceptance. A new kernel build and dedicated exhaustion,
private-queue, no-exhaustion and NOWAIT fixtures are required. Existing
requeue/partial-completion cohorts retain their original contract and
must not be upgraded to tag-wait coverage on replay.

Dedicated VM receipt
--------------------

``block-tag-protocol-runtime-20260920/x5-fixture-20260919-232248.log`` has
SHA256 ``ab91d6583ae6f5d75006cbe52180620f954323dd0725e89a32fc7795d66a4a9e``.
Kernel source is ``63df60de9``; tools and fixture are ``65f602039``.
The full ARM64 Image and modules built. The VM's two unexposed four-slot
blk-mq queues execute real allocation/free APIs from registered container
tasks. This is a kernel API fixture, not a filesystem or real device test.
No request is submitted for I/O. A per-file context owns its allocated
requests and releases them on close; it is not production ownership code.

Four cases, three alternating OFF/ON pairs each, produced 24 states and
12 captures. All were replayed by ``tag_vm_check.py``. Each exhausted
capture had exactly one observed sleep, respectively 50.12547, 50.12755
and 50.12638 ms, bracketing independently controlled tag release. These
are intentionally induced waits, not observer overhead. Each NOWAIT
capture had one rejection with no sleep. All three private-queue and
all three available-slot captures had zero tag episodes. Request-submit
episodes were absent as required. No unique blocking-container relation
was emitted, even though the fixture knows which actor retained slots.

Maximum combined CAPTURING process CPU was 10.39307 ms; maximum enclosing
process CPU through reporting was 191.71417 ms. Combined peak RSS was
37,711,872 bytes. These are different scopes, not total observer kernel,
background or asynchronous memory costs. New-kernel joint and teardown
regressions must be recorded separately, and are not inherited from this
fixture. Multi-hardware-queue migration, reserved tags, production I/O
coverage, merged requests and writeback provenance remain unverified.

The first cohort, ``block-tag-runtime-20260920``, failed before collecting
because the harness tried to decode the launcher's host-PID line as JSON.
Its failure log remains unchanged. The fix explicitly recognizes and
records that one launcher line, rejects duplicates or unknown text, and
compares the module's host task ID with the launcher. It does not discard
arbitrary errors or reclassify the failed cohort as successful.

New-kernel joint and cleanup receipt
------------------------------------

``block-tag-joint-runtime-20260920/x7-joint-20260919-233153.log`` has
SHA256 ``80437b464199742ddab7679883034cfdcd93731aa8d7415f57038f1a49bbb45c``.
It pins the same kernel/tools as the tag fixture. Four container actors
completed 198,000 operations over 33 OFF/specialist states, with zero
errors or timeouts. All 30 captures replayed with accepted evidence
quality. Maximum CAPTURING process CPU was 35.22407 ms, below the current
40 ms policy without using the older one-off 40.60 ms exception. Maximum
combined process RSS was 37,011,456 bytes. This is PASS_SCOPED, not X7
completion or full observer-memory accounting.

Largest descriptive P99 increase was 6.938470 ms, in round 1, owner
collector, bystander actor 2. P99 remains record-only by authorization;
the cause of this increase is NOT established. Do not label it hardware
noise, claim tail-latency acceptance, or rerun until it disappears.
The enclosing management cgroup used 11.685--930.491 ms per benchmark;
this includes preparation, harness, snapshots and reporting, not only
capture. Snapshot reads reached 48.73327 ms outside the capture interval.
Whole-VM Slab, KernelStack and PageTables gauge deltas respectively range
from -335872 to 2596864, -77824 to 81920, and -229376 to 245760 bytes.
They include business and unrelated background effects and must not be
summed with process RSS as if they were exclusive observer allocations.
Full asynchronous kernel CPU/memory attribution remains unknown.

New-kernel control checks passed 16 cases / 14 sessions, a forced-failure
case / one session, and 16 crash-cleanup cases / 16 sessions. Their serial
SHA256 values, in that order, are::

  948a2c44c1fe5ee7c13d8d2914702e6ee9569ed842a0324dd14e3652dc776c4a
  9c3d1cbfd1faea63465b07594dda37b3f42ce7132234e46a19fb403f186947a9
  58d72354384ce6fd4a0a48e0809387338f1591b1aabddccea9a8691a07066c24

The interrupted crash captures explicitly lack complete scope audits;
they demonstrate cleanup, not complete diagnostic observations. No host
kernel was replaced and no older evidence was deleted.

The same new kernel also reran both real block lifecycle fixtures: 12
OFF/ON states each for requeue and partial completion. Both replayed
PASS, with 96 captured request episodes per fixture and unchanged byte,
head-bio provenance and independent device-counter checks. Serial hashes::

  aa16e0dbf4f41995c836cd104e8e5c7d0326822d761ba0a8e480a534671c4a42
  0880b52fb05bf4543ee21ee79050f676274afedb19ecdecb705e874d1d21d04f

The separate SLUB-selected-cache joint cohort passed six OFF/ON states,
36,000 operations, zero errors/timeouts, and all three capture replays.
Serial ``block-tag-slub-joint-runtime-20260920/x7-joint-20260919-234822.log``
has SHA256
``cd62a3e1c3a8e713a1aaf63c466a0eb2a96eb184af5306c41994029e21ce7190``.
Maximum CAPTURING process CPU was 10.99435 ms and RSS was 31,399,936 bytes.
Largest descriptive P99 increase was 0.25319 ms. This remains a scoped
ordinary-operation cost check, not positive competition population truth,
complete background attribution, or production tail-latency acceptance.
