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

Scoped runtime, kernel 6864117ae / tools 619897476
------------------------------------------------

Image SHA256 is
``fbe205ea89fa9b80ed96f424fdf87f2edafb503f217d88b95c21196318ee0501``.
Independent raw replays passed:

* Common group: ``x7-joint-20260919-223842.log``, SHA256
  ``5f0cce68e10956df850ad24acc7fc352f1758fef66cb0fda8215d36c8b065adc``.
  33 states / 30 captures, 198,000 completed operations, no errors/timeouts.
  Maximum process CAPTURING CPU 31.81849ms; combined RSS 38,420,480 bytes.
* SLUB group: ``x7-joint-20260919-224707.log``, SHA256
  ``d0288ac5781509e213360a85402396229da6ab6527d4d4e220248db555e17542``.
  6 states / 3 captures, 36,000 completed operations, no errors/timeouts.
  Maximum process CAPTURING CPU 11.55319ms; combined RSS 33,464,320 bytes.

Both retained the unmodified 40ms capture gate and P99 record-only policy.
No kthread scan hit the cap or lost a stat read. The common group saw 14
new/gone thread keys across bookends, not fabricated zero CPU for those
threads. Surviving thread CPU deltas ranged from 0 to 4 ticks (100Hz); these
are VM-wide kernel-thread activity, not exclusive observer cost. Management
cgroup usage ranged from 11.413 to 1,014.389ms per enclosing benchmark; it
includes preparation, harness and post-capture analysis, so the capture CPU
number is not a claim that total work cost only 31.82ms.

The longest sequential snapshot took 53.82783ms wall time in the common group
and 42.92568ms in the SLUB group. This bookend measurement cost is outside the
capture, retained visibly, and is not called application lock wait or folded
into the 40ms capture limit. Memory gauges increased and decreased; no total
observer memory was inferred. These cohorts still provide no independent
ordinary-application attribution recall and do not complete X7's remaining
mixed-source truth, tag/merge/writeback, skb transformation or Maple ownership
requirements.
