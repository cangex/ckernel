Y6: selected-CPU execution and background intervals
==================================================

Implementation contract (runtime acceptance pending)
----------------------------------------------------

An explicitly selected set of at most eight online CPUs, disjoint from the
observer's management affinity, is observed for at most the existing bounded
specialist window. Native scheduler, IRQ, softirq
and workqueue tracepoints are used; no scheduling or locking algorithm is
changed. Callback entries on unselected CPUs are counted before filtering and
the existing entry/output/memory guards detach producers on exhaustion.
No stacks, packet/object lifetime maps or every-container CPU arrays are added.

Scheduler switches identify both event tasks by PID/TGID and start_boottime,
with registered cgroup ancestry resolved separately. Runnable switch-out to
switch-in brackets are admitted only on the same CPU without a migration
event. These are off-CPU wall intervals, not pure contention time. Quota,
priority, IRQ, vCPU steal and unobserved scheduling eligibility can coexist.
Native sched_stat_wait observations remain separate and are never added to
the switch brackets. cpu.stat/PSI boundary snapshots describe quota and
pressure over their own timestamped read intervals, not per-event causes.

Execution intervals have matching switch endpoints. Protocol 2 IRQ/softirq
intervals are stack-paired and accumulated per CPU, never exported as perf
records from IRQ callbacks. The first VM prototype exposed an irq_work
notification feedback loop; its failed/lossy evidence is retained. Counting
callbacks without per-IRQ output breaks that feedback rather than hiding the
source cost or increasing limits. Valid cumulative snapshots at ordinary
points subtract the nested union once; racing/partial snapshots stay unknown.
Terminal per-CPU totals include unfinished depth and errors. Missing totals
reject the report. This loses per-vector timing distribution by design, not
as an undocumented sampling change. All callback entry costs remain budgeted.

Workqueue execute brackets identify the worker and work function, not the
submitting container. Work addresses are scoped to one completed execution,
not joined across reuse. Pre-window, nested, migrated or incomplete episodes
are retained as unknown. NMI and hypervisor time are outside this first scope.

Same-CPU overlap supports an execution association, not a unique blocking
container or E3 cause. Background CPU is reconstructed only inside validated
scheduler slices, excluding observed interrupt union; wall duration alone is
not CPU cost. A separate fixture ground truth may identify a submitter for
validation but is never silently substituted for production attribution.

Positive and negative tests must cover same/separate CPU, target quota,
migration, task identity reuse, private work, background execution and IRQ
overlap. Hardware SPE needs a real supported PMU and validated decoder; an
event name or LLC miss count is insufficient. Y7 joint cost acceptance is a
separate stage and remains pending.
