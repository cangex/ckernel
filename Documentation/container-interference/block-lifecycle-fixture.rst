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
