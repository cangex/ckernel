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
