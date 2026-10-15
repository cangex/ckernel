Measurement gates
=================

The previous Go grouping experiment rejected four cost windows whose end read
preceded the actual business end. Fixed sleeps are not a completion handshake.
timing.py rejects reversed lifecycle boundaries. costs.py now waits for every
published done event, validates the replay clock, acknowledges completion and
then captures its final snapshot before official grading. There is no fixed
sleep claiming completion. The actual publication/observer lag is retained;
ordered snapshots are not proof of exclusive business-cost attribution.

Required distinct clocks are request, ready, business_start/end, completion_ack,
cost_end, detached, seal/delete request and mapping_reclaimed. Report business,
arrival-to-result and complete resource-turnover times. Lifecycle management,
backlog waiting, CoW, export/scoring retention, pool work and final drain cannot
be erased from the appropriate totals. Do not add overlapping parent waits and
child CPU times into wall time. Per-copy peaks are not unique physical memory.

Future matched configurations are S (one fresh shared filesystem), G (two fresh
filesystems), F (fresh per-task thin/ext4 formatting), B (fresh snapshots of an
inactive immutable template). All run on the same thin/loop/host-device path.
The previous loop-only performance numbers are context, not new controls.

After three independent correctness admissions per final configuration, an
independent n=3 pilot must precede freezing formal blocks (at least eight),
pairing, multiplicity handling and thresholds. B/F lifecycle and B/S loaded
business are separate primary comparisons. At least five waves use fresh IDs
and cannot be counted as independent formal blocks. No formal matrix or net
benefit is currently claimed. No P99 is generated from sparse whole-task runs.

run_matrix.py currently permits only the 12-state solo correctness-admission
sequence. It does not implement or silently start a formal performance matrix.
The observer includes the startup-barrier interval and final publication lag.
System counters contain unrelated background work. Unique physical memory,
steady-state/CoW attribution and production-like immediate deletion latency
remain unqualified. Official scoring retention is measured separately but is
still part of the observed end-to-end turnover. These gaps prohibit net-benefit
acceptance even when every official correctness check passes.
