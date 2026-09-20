Y7 joint acceptance protocol (implementation, not acceptance)
============================================================

The scoped execution receipt is y7-validation-20260920.rst. This protocol
describes the frozen test design; its presence alone is not a runtime result.

The first cohort uses four active containers with four private directories,
private files, FD tables and anonymous address spaces. A fixed open-loop
arrival sequence performs file write/read/verification, private rename/unlink,
periodic fdatasync and VMA activity. No two containers modify the same file or
directory. There are 6000 arrivals per actor at 3 ms, including queueing delay
and the 100 ms timeout count in latency reporting.

Within each frozen placement, three alternating rounds compare idle OFF,
one reduced IP/boundary survey, and that survey followed by counter, page
backend, filesystem, block and selected-CPU windows. Windows are two seconds
at predetermined three-second slots. This is a reproducible profile cost
schedule, not proof of automatic anomaly-trigger efficacy. Each cohort uses
21 sessions, below the existing 32-session permit, and never attaches private
object extensions. Target and bystander roles rotate. Four-container admission
is not enlarged into an untested 48-container deployment.

Two fresh isolated VMs use shared versus two separate disk backends and
different CPU placements. Comparisons are OFF versus modes within a placement;
differences between placements are not a one-variable causal intervention.
Whole-VM, management cgroup, business cgroup, kernel-thread, memory and
per-session costs retain their measurement boundaries. P99 is record-only;
business corruption, wrong identity, sample loss, source budgets and cleanup
remain hard gates. Raw failures must be kept.

This storage cohort alone cannot complete Y7. Independent-connection public
queue integration, final source-OFF checks, enabled/disabled build validation,
and reconciliation of Y0--Y6 coverage and residual unknowns are still required.
SPE unsupported in a VM remains unsupported, not inferred cache-line contention.

The second cohort freezes four accounting roots and eight namespace-isolated
endpoint containers (a private UDP client and echo server per root). Clients
use the shared host network namespace and distinct sockets; servers use two
veth peer namespaces and distinct ports. This directly observable configuration
does not establish forwarded-packet lineage. Shared versus separate egress
placements keep CPUs fixed. Each actor sends 4500 validated 1024-byte echoes at
2 ms scheduled arrivals, with 100 ms timeout reporting. Both endpoints must
confirm the full sequence with no corruption or duplicates. The 100 Mbit TBF
does not intentionally cause loss; sustained backlog is not presumed.

OFF, IP survey and sequential IP/qdisc/CPU profile modes alternate over three
rounds in each fresh VM. Target/bystander roles rotate; only one egress queue
is selected. A nonselected connection must not appear as its participant.
Three two-second profile windows fit within the nine-second client sequence.
Queue participation remains E1, never a unique holder or blocking container.
The selected queue may also carry registered bystander traffic. Its validated
identity universe includes these roots, not only the two active diagnostic
targets. Participants must match the actual queue placement of all four roots.
Combined client/server CPU and memory belong to their accounting root; the
measurement includes endpoint startup/shutdown and first unified analysis.
