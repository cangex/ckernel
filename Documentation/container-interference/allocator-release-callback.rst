Allocator release callback serialization
=======================================

The 20260919 joint-source-audit cohort rejected allocator round zero with
404 source release recursion skips. The other two rounds had no such skips.
Bulk truncation and NMI skips were zero. This is a failed joint cohort, not
a reason to suppress the source quality check or retry until it passes.

The old release guard spanned every object in a bulk release, including the
intervals between raw tracepoint callbacks. A preempting interrupt release
could therefore be rejected even outside the callback. The revised guard
spans one callback, with local IRQ save/restore around that callback only.
Interrupts are restored between objects if the caller had them enabled.
NMI and actual recursion still count as gaps and invalidate attribution.
No SLUB algorithm, object lifetime, sampling weight or quality gate changes.

This is a diagnostic-source cost, not a free correctness fix. Version 4 of
cis_alloc_audit adds per-CPU callback count, accumulated callback body time
and boot high-water callback body time. The latter is never subtracted as
if it were a counter or reported as a per-window maximum. The timer excludes
some save/restore and bookkeeping work; it is not a full IRQ-off latency
bound. NMI, virtual CPU descheduling and clock costs can also affect it.
Source time covers all admitted cache releases, not only selected targets;
it must not be added to sampled CPU cost without checking overlap.

The handler remains inactive unless its tracepoint is attached. No global
hot-path counter is added. Fresh Image/modules builds and isolated tests
must establish runtime behavior and cost before any completion claim.
