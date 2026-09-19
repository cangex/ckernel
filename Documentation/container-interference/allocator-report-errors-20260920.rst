Allocation report acceptance corrections
=======================================

The guarded SLUB kernel (06c07b5de) common joint cohort used tools 79c6131ca.
Its frozen serial SHA256 is
``e5bb479e75bb10861f10c5451957ac7aed8b2613cbaffe2aeeed19da7260b144``.
The original offline verification failed allocator0. It is retained, not
overwritten and not replaced with a selected runtime retry.

The 902 rejected stage rows contained ``stack_id=-17`` (stack-map helper
collision), not invalid node IDs. Stack helper errors in [-4095,-1] now retain
typed allocation stages while explicitly reporting an unavailable calling
path. Counts are per accepted call, not per repeated stage. Positive IDs
without exported symbols also remain unavailable. Bad nodes, inconsistent
per-call IDs, invalid protocol, loss and bad identity still reject evidence.

Replaying exposed a second offline defect: the lifetime join applied the
1024 live-sample bound to all allocations accumulated over a window. It now
processes allocation/release timestamps in order and retires matched samples.
The same simultaneous 1024 limit remains enforced; no source sampling limit
or memory budget is raised. Observation keys still include requester, task
start, call, object and allocation ordinal, not merely address. Sorting fixes
cross-CPU delivery order, not missing timestamps or missing identity.

A third acceptance gap was corrected: an invalid allocation lifetime
subreport now fails unified quality instead of emitting apparently accepted
release relationships. Typed stage and object-lifetime validation are not
interchangeable. Unit negatives cover invalid errno, changed stack IDs,
invalid node, duplicate release, address/ordinal mismatch and true simultaneous
capacity overflow; a 1100 sequential sample case must not overflow.

The second corrected replay is PASS_SCOPED for 33 ordinary application
states / 30 capture windows. The intervening replay is also retained: although
its old joint checker said PASS_SCOPED, allocator0's lifetime subreport failed,
so that intermediate result is NOT accepted. This is ordinary workload
regression, not allocator-holder positive recall or full X7 completion.
Missing stack paths are not filled from neighboring calls or timestamps.

The guarded kernel's separate x0-control serial
``x0-control-20260919-205609.log`` passes 16 control cases / 14 sessions.
Fault/crash cleanup and unimplemented X3-X7 cases are not inferred from this.
No host kernel, workload, raw evidence or prior failure record was changed.
