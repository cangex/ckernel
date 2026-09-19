TCP send allocation failure validation
=====================================

This cohort tests native ``alloc_skb_fclone`` failure, not injected trace
records, and does not alter TCP algorithms.  It requires a disposable VM
kernel built with FAULT_INJECTION, FAILSLAB and FAULT_INJECTION_DEBUG_FS.
Absence of the native controls is a capability failure, never a pass.

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

This is not coverage of the separate ``sk_wmem_schedule`` admission-reject
branch, realistic memory pressure, receiving allocation or clone/GSO/GRO
lineage.  Backend elapsed time includes scheduling and interrupt time;
original-header release entry does not prove final shared-data reclamation.
The dedicated coverage key prevents this cohort being relabelled as Socket
holder validation or the successful-send-only backlog cohort.
