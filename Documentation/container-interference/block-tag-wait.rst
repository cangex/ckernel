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
