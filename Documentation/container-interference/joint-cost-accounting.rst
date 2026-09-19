Joint resource-accounting boundary
=================================

``cis-x7-cost-v1`` adds bounded benchmark-bookend observations to the existing
four-container joint fixture. It does not install extra live probes or change
the 40ms CAPTURING process-CPU gate. Historical cohorts without the cost schema
remain replayable, but acquire no credit for data they never recorded.

The management cgroup records CPU usage/user/system, memory.current,
memory.peak, memory.stat and memory.events alongside the four business roots.
Management includes the harness, launch preparation, controller and workers,
not exclusively the observer. memory.peak is cumulative since cgroup creation;
it is never called the peak of an individual state. Overlapping memory.stat
subfields are preserved rather than added together.

Before/after scans visit at most 4096 /proc process entries, retaining only
PF_KTHREAD records. PID and start-time ticks identify surviving threads. New,
exited, unreadable and capped entries are reported explicitly. Surviving kernel
thread user/system tick deltas describe their aggregate work during the
benchmark, not which tenant or observer caused it. Business-context callbacks
and softirq cannot be recovered from these counters. Tick resolution is
reported; a zero tick delta is not proof of zero work.

Global memory gauges retain units and may increase or decrease. Their deltas
are not an exclusive observer charge, and gauge overlap prevents a fabricated
total. Snapshots expose read start/end times because reads are sequential,
not atomic. The enclosing benchmark differs from the shorter capture window.
CPU iowait may decrease and is kept as a raw observation rather than rejected
or reinterpreted as additive lock-wait time.

Existing process CPU/RSS and actual BPF object inventories remain separate.
These additions improve background and memory visibility but do not certify
complete source-callback CPU, asynchronous memory ownership, production tails
or an all-inclusive observer cost. OFF comparisons are descriptive and retain
business throughput, arrival-relative latency, timeouts and unknown causes.
