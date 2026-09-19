Native TCP memory admission rejection
====================================

This is a bounded disposable-VM fixture, not normal network throughput or
wire-delivery certification.  It uses native TCP_REPAIR send queues to keep
original skb headers live, without changing a socket's private kernel fields
or substituting a trace producer for the real allocation path.

Before capture, an unregistered management task queues exactly 4MiB on a
repair-mode TCP connection with sufficient SO_SNDBUFFORCE.  This exceeds
native per-CPU accounting reserve; /proc/net/sockstat must show positive TCP
memory accounting.  The retained seed is explicit test pressure, not charged
to a measured container or hidden as observer memory.  After each test has
finished, its sockets and the seed are closed.  The original tcp_mem values
are restored and read back even after failure.

Two registered containers each use a distinct already-connected repair-mode
socket.  Sixteen fixed nonblocking 128-byte MSG_EOR sends occur under either
the original TCP budget or a VM-only zero budget; the workload does not retry
until it obtains a favourable result.  Parent/child barriers prove that the
budget was restored before eight further same-socket sends.  Those eight
must be accepted by TCP.  Data is intentionally not put on the wire, and
closing the socket purges its retained native queue within the capture.

OFF and NET modes each run three alternating rounds for both cases.  Every
send has independent syscall return/error, cookie and monotonic brackets.
The verifier requires correct requester identity, one header-allocation
episode per call, at least one observed native memory-admission rejection
per pressure actor, release before the rejection terminal, and accepted
recovery.  Successful header admission followed by a failed data-copy memory
check remains distinguishable: EAGAIN alone does not certify which allocation
stage failed.  All accepted headers need an observed release entry.  The
normal-budget case must have neither failed sends nor admission rejections.

This does not prove a competing container caused a real-world shortage,
identify an allocator lock holder, track clone/receive lineage or establish
data delivery.  It supplies failure-path and cleanup evidence only.  Same
kernel OFF/NET, source quieting, identity and process-CPU guards remain in
force; neither the old 40.60ms exception nor production acceptance transfers
to this fixture.
