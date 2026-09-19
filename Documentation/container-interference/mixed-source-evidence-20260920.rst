Mixed-source independent truth, 2026-09-20
========================================

Tools b1c008764b4ebbe6d41bfe912bb8f916e41f95b7, immutable kernel
7897796a3cf1668c0f27d79a36c5ae0296bfbc40, ran the fixed 24-state matrix in
the dedicated eight-vCPU ARM64 KVM guest. Host boot and kernel were unchanged.
The Image SHA256 remains
da9d838f343a6ca138bf74d72cdd77fea4a187fc91552e48c8afec08e883858b.

Independent replay passed all 24 states, including 18 captures. There were
96 ordinary container runs, each with 1500 arrival-timed file/VMA operations,
zero errors and zero timeouts. Ordinary work covered each full capture.
All 384 direct-I/O calls across the matrix actually overlapped independently
bracketed native TCP logical holding intervals; simultaneous process presence
alone was not the criterion.

Each of the three shared-socket NET windows captured exactly 4/4 eligible
holder/waiter relations. Each private-socket NET window had zero cross-container
relations. Six BLOCK windows matched all 16 direct-I/O request episodes each:
96/96, with the correct actual submitter, bio billing identity, operation,
device, timing bracket, completion status and byte count. No unique blocking
container was inferred from shared-device participation. Other simultaneous
resource activity did not become the socket's holder or the request's source.

The 64-item network source guard was not exercised by this small mixed cohort.
Network native callback counters stayed unchanged in OFF/IP/BLOCK windows;
source switches and actual object removal passed after all captures. This
does not measure all inactive entry-instruction cost or all generic tracepoints.

Maximum combined-process CAPTURING CPU was 10043640ns; the unchanged guard is
40000000ns. Maximum process CPU through reporting was 172389120ns, and peak
combined RSS was 37703680 bytes. These exclude incompletely measured callback
and asynchronous kernel costs. Per-container and management CPU/memory,
whole-VM gauges and matched kernel-thread ticks remain in the replay output.
Management bookends were 15705--215544us and matched kernel-thread CPU 0--2
ticks per state; both include non-observer work and are not exclusive costs.

Paired target arrival-relative P99 differences were -344150..396280ns;
bystander differences were -400560..384920ns. P99 remains record-only. This
fixed offered-rate experiment is not a saturated-throughput benchmark or
production latency certification. Guest perf automatically lowered its maximum
sample rate as far as 30500; the retained warning is not proof of zero
monitoring disturbance. Captures still met their actual quality and CPU guards.

The guest rebuilt tools and passed 614 tests (586+21+7). Independent replay of
the serial, not the guest's summary string, determines the scoped result.
Serial SHA256:
5d2736f215b0192ffdfe26c674399c32550d558cd94d3c9681db7b626a9b2ce4.

Remote evidence:
/dev/shm/cis-x-20260919/evidence/mixed-b1c008764-20260920.

This closes the specified mixed TCP/direct-I/O truth cohort, not X7 as a whole.
High-rate/capacity/failure coverage remains separately tracked; receive packet
transformations and complete background accounting are not inferred from this
test. Use a separate bounded coverage index rather than increasing the existing
64-cohort reader limit or hiding previously failed evidence.
