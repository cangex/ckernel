Y7 joint acceptance protocol (implementation, not acceptance)
============================================================

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
