Block request requeue and partial-completion fixture
==================================================

The external selftest module creates two 16MiB RAM block devices only in the
dedicated VM. It requires explicit ``disposable_vm=1`` and immutable mode
``test_mode=1`` (one actual blk_mq_requeue_request per request) or ``2`` (an
actual 2048-byte blk_update_request followed by the remaining completion).
No production block algorithm or host device is changed. Merges are disabled
only on these test devices; all requests are 4096-byte reads/writes.

The existing independent container workload writes and verifies disjoint
sectors, sharing a device or using two devices. Three alternating OFF/ON rounds
yield 12 states per mode, 16 successful operations per state. Frozen device
counters must increase by exactly 16 requests and final completions, zero
errors, and the selected 16 requeues or partial completions, also with the
observer OFF. The counters are fixture-only, not production observer overhead.
For ON windows every client syscall must join exactly one request episode with
the right container and head-bio blkcg, native queue/issue/requeue/completion
sequence, total bytes and successful data validation. Missing events cannot be
replaced by the expected sequence. Native observer records are not synthesized
by the fixture. The other mode is a negative for the absent event type.

This closes request-lifecycle runtime examples only after those runs pass.
It does not establish device saturation causality, a unique blocking container,
tag exhaustion, merged bio origins, buffered writeback, storage hardware delay
or production performance. Both device addresses remain VM-local RAM; shared
device membership alone never identifies a blocker. Module teardown occurs
after all actor FDs close and captured source objects are removed.

Scoped runtime evidence
-----------------------

Both use kernel 6864117ae, Image SHA256
``fbe205ea89fa9b80ed96f424fdf87f2edafb503f217d88b95c21196318ee0501``.

* Requeue: tools 67904958b; ``x5-fixture-20260919-222108.log``; SHA256
  ``88187cbe0278f88f6cf4174df7bc9ffae27e6d42eca6285b9af77093958742b6``.
  All 12 states / 6 captures passed, 192 client operations including OFF,
  96/96 ON request episodes with one requeue and two issue intervals each.
  Process CAPTURING CPU maximum 9.16769ms; RSS 34,861,056 bytes.
* Partial completion: tools 5eb288879; ``x5-fixture-20260919-222555.log``;
  SHA256 ``969ebbd993e0d53ef78c5104770f40b558d1babcd4108503bb4316d36d7f3fa5``.
  All 12 states / 6 captures passed, 192 client operations including OFF,
  96/96 ON request episodes and 192 2048-byte completion records. No requeue
  was invented. Process CAPTURING CPU maximum 8.95865ms; RSS 34,594,816 bytes.

The single-bio truth contract checks its current byte count against request
remaining bytes, not the initial size after a partial completion. Native bio
iteration advances after completion; preserving the old 4096-only test would
incorrectly reject the final 2048-byte event. Tools 5eb288879 also replayed the
frozen requeue and original direct-I/O cohorts successfully. No raw evidence
or module behavior was changed by that offline report refinement.

Every workload completed with correct contents, both devices unloaded, source
switches returned OFF and capture objects were removed. These bounded fixture
results do not cover tag wait, merging, writeback or whole-system overhead.
