FD-only bounded prefix revision
===============================

Design and predeclared validation, 2026-09-20
--------------------------------------------

The prefix-64 fixture population measured 42/64 complete shared-table calls,
21/32 cross-container CLONE_FILES calls and 150/256 address-reuse calls. Missing
calls remain in the denominator. This is insufficient evidence of full call
coverage and is not a measurement of true blocking-relationship recall.

Only FD resource kind 3 now admits 128 state events per watched lifetime,
followed by the existing phase-11 truncation marker. Lockref and SLUB stay at
64. Atomic admission, retirement, initialization and scheduler cut-off retain
the same semantics. A bounded prefix may still terminate inside a call; no
reader is allowed to manufacture its missing end or exclude the call.

No map capacity changes: 64 watched objects, 128 holder records and task
records, 1024 pending attempts. For one lifetime at each of 64 watched slots,
the new bound admits at most 8192 ordinary state events plus 64 truncation
markers. It is not a session event bound: retirement/reuse, scheduler events
and repeated watches need the unchanged 200,000/s source-entry guard, 16MiB
output limit and 40ms CAPTURING combined-process CPU guard. The 64MiB memory
policy is unchanged; this does not certify total kernel memory. Retirement
and source-entry costs still occur after prefix exhaustion.

The live collector contract explicitly declares prefix-128. Historical
prefix-64 receipts are accepted only by their exact contract digest in the
offline reader, never reused as new-bundle admission evidence.

Validation is frozen before execution: basic threads/private/native n=3,
cross-container CLONE_FILES/address-reuse n=3, and high-rate FD guard n=3.
Use the same 16 operations/thread, full-call denominator and independent
truth brackets as before. Guard sessions must be rejected PARTIAL with source
detached and business continuing; they are not successful dense profiles.
Rebuild BPF/userspace, run unit tests, replay old receipts, and repeat control
cleanup with the new bundle. Kernel algorithms and fixture workload do not
change. Runtime evidence will be recorded separately, including failures.

This revision targets a concrete coverage loss, not complete X1/X7 acceptance.
In particular all-call coverage is not causal recall or continuous spin time,
and finite selected-object records are not coverage of arbitrary spinlocks.
