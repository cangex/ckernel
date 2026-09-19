TCP send allocation failure validation
=====================================

This cohort tests native ``alloc_skb_fclone`` failure, not injected trace
records, and does not alter TCP algorithms.  It requires a disposable VM
kernel built with FAULT_INJECTION, FAILSLAB and FAULT_INJECTION_DEBUG_FS.
Absence of the native controls is a capability failure, never a pass.
This OLK normally merges the fclone cache and refuses changing its failslab
flag when aliases exist.  The VM therefore boots with the native
``slub_debug=A,skbuff_fclone_cache`` parameter to select only that cache before
merging.  Its zero alias count, boot command and initial flag are recorded;
global injection probability must still be zero.  Restoring the original
flag to one in this case does not leave injection enabled.  OFF and NET use
the same narrowly unmerged test layout, not the production cache geometry.

Frozen cases are ``txfailure`` and ``txunmarked``, OFF/NET, three alternating
rounds: twelve states and six captures, each bounded to two seconds.  Both
containers own distinct inherited loopback TCP pairs.  Each executes eight
128-byte sends, spaced 100ms apart.  Native failslab is limited to the
``skbuff_fclone_cache`` and explicitly marked tasks.  Actor zero alternates
marked failures and unmarked sends on the same socket.  Actor one either
does the same or stays entirely unmarked.  No allocation failure is enabled
on the host.

The task fault flag is set only around send and read back on every change.
The independent workload records the syscall time bracket, return value,
errno, socket cookie and bytes actually received.  Failed nonblocking sends
must return EAGAIN and no data; unmarked sends must deliver all bytes with
correct content.  MSG_EOR prevents unrelated sends sharing a header.  The
checker requires a distinct allocation episode per send, correct requester
and cookie, no invented skb or release for a failed allocation, and observed
original-header release for successful recovery.  It does not infer a
blocking container, allocator lock holder or packet-payload owner.

The guest records and restores every native fault-control setting and the
cache flag.  Standard source-switch, CPU, memory, quality and cleanup guards
remain unchanged.  Quality gaps or missing recovery lifetimes fail the
cohort, rather than reducing its eligible denominator.  Kernel warnings and
failed setup attempts are retained.

The protocol-2 send adapter admits allocation beginnings in process context
only. Source-audit version 4 counts IRQ-only beginnings as
``tx_irq_filtered``; they never created an admitted requester or pending
allocation lifetime. Real nested tracing still increments both
``tx_nested_skipped`` and the rejecting recursion counters. Gaps in selected
steps or releases remain rejecting. This is an explicit coverage boundary,
not evidence that IRQ allocations have been attributed. Version-3 failed
captures are retained with their original recursion failure, not relabelled
using the new counters. Historical contract replay is hash-bound.

The independent failure and admission checkers are also tested through the
actual raw-event report parser, including its ``sockets[].waits`` schema.
Earlier failed VM runs exposed a checker field mismatch; those incomplete
cohorts cannot count as validation of the corrected checker.

This is not coverage of the separate ``sk_wmem_schedule`` admission-reject
branch, realistic memory pressure, receiving allocation or clone/GSO/GRO
lineage.  Backend elapsed time includes scheduling and interrupt time;
original-header release entry does not prove final shared-data reclamation.
The dedicated coverage key prevents this cohort being relabelled as Socket
holder validation or the successful-send-only backlog cohort.
