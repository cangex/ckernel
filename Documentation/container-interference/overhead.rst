======================
Observer cost protocol
======================

Initial engineering limits
==========================

* Populated roots: one full resource update per second, staggered. Empty roots:
  presence and memory counters each second, full CPU/PSI every five seconds.
* Nominal machine-wide 1000 kernel IP samples/second, split across CPUs, not
  multiplied by the number of containers. Fixed cycle period uses a 4 GHz
  engineering frequency bound; achieved rates must be measured, not assumed.
* Two-second diagnostic window, two concurrent targets, 30-second cooldown.
* 256 roots, 512 configured CPUs, 1024 pairs, 128 work records, 256 stacks.
* At most 32 administrator requests/second; bulk registration completion time
  and its CPU/memory are reported separately from active-window costs.
* Two data pages plus metadata per CPU output; independent perf quality pages.
* 64 MiB initial resident-memory limit and 20 ms daemon CPU/second guard.
* Above 200000 probe entries/second the collectors detach on the next audit.

The one-second audit has reaction latency and is not a hard CPU-time guarantee.
Perf quality reads are staggered across CPUs rather than issued as one global
burst. The report includes unread CPU count and maximum counter age. These are
asynchronous cumulative snapshots, not simultaneously sampled counters. The IP
sample period and nominal coverage budget are unchanged by staggering.
Tracepoint entry/filtering costs on non-target tasks count even if no records
are emitted. Map/kernel-memory reserves are engineering estimates; validate
with the observer cgroup charge, process RSS and system memory, especially for
different page sizes. Output page cache and background work are not free.

An unpopulated cgroup can retain charged memory and asynchronous work. Empty
roots therefore retain memory.current/events polling and IP registration;
they are not declared cost-free. Deferred CPU/PSI fields are omitted and their
age is explicit in metric_idle. They do not train a business baseline. On the
first one-second presence check that sees a task, full counters resume and a
new warmup starts. A short-lived unsampled task wholly between presence checks
may only appear in the next five-second cumulative refresh. This limitation
is explicit, not a claim of continuous short-task coverage. No active-root
sampling cadence or global IP budget is reduced by the idle policy.

Modes and statistical gate
==========================

Compare OFF (no daemon/probes), metrics and IP on the same kernel and layout.
Alternate a predeclared order with n=5 paired rounds and swap target/bystander.
Measure closed-loop completed operations and fixed-arrival-rate response P99.
Latency starts at planned arrival, includes backlog and counts timeouts. Never
discard failed or slow rounds or replace them with the best run.

The initial acceptance targets are throughput degradation <=1% and P99
increase <=2% for both target and bystander. The two-sided paired 95% t interval
must support the bound. A mean inside the limit with a wide interval is
BLOCKED/confidence_insufficient, not PASS. Detailed diagnosis has a separate
<=3% throughput target; its local CPU and tail cost are still reported.

Every measurement also requires useful coverage. No IP records, decode errors,
budget shutdown or unexplained record loss invalidates an ambient coverage
claim even when its timing numbers look good. PERF_SAMPLE_RAW has trailing
alignment bytes; reject malformed records, not legitimate alignment padding.

Open-loop response starts at the planned arrival, including wakeup delay,
queueing and timeouts. The harness additionally records waiting and execution
segments; their separate P99 values cannot be added. Execution includes any
blocking or preemption, and is not pure CPU time. Tail-conditional means are
reported separately. Result arrays are faulted in before the common barrier.
Timer slack is reported, not changed to make a result pass.

An extended screen fixes n=20 in advance, with a paired t interval using 19
degrees of freedom. It does not pool old pilots or extend the cohort until a
passing interval appears. OFF/OFF variation is a diagnostic of measurement
noise, not permission to subtract that noise from the reported effect.

The S6 runner refuses admission without a numerical and coverage-valid S2
report. All two-second diagnostic targets must be armed before the common
workload start. A final benchmark batch may cross the deadline; scale_report.py
uses a conservative bound, charging that entire batch against the monitored
configuration. Attachment/startup costs are still reported outside the active
window and are not free. A missing/late interval cannot pass based on average
cost over a longer test.

Pilot screens are not formal S6 scale acceptance. Record implementation/source
hashes and retain all earlier failed screens. Hardware/VM scheduling variance
must not be explained away as hardware without evidence. The dedicated VM has
pinned vCPU threads but no exclusive reservation of all host cache, memory or
interrupt resources; report this uncertainty without changing host policies.

Formal S6 must cover 1/12/24/48 active containers and 128/256 registered or idle
roots, after the ambient gate. If a prior gate fails, prepare the later matrix
but do not label it completed. User authorization to proceed does not establish
that observation is nonperturbing.
