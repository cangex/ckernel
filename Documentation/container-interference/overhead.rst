======================
Observer cost protocol
======================

Initial engineering limits
==========================

* Approximately one resource update per second/root, staggered.
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
Tracepoint entry/filtering costs on non-target tasks count even if no records
are emitted. Map/kernel-memory reserves are engineering estimates; validate
with the observer cgroup charge, process RSS and system memory, especially for
different page sizes. Output page cache and background work are not free.

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

Pilot screens are not formal S6 scale acceptance. Record implementation/source
hashes and retain all earlier failed screens. Hardware/VM scheduling variance
must not be explained away as hardware without evidence. The dedicated VM has
pinned vCPU threads but no exclusive reservation of all host cache, memory or
interrupt resources; report this uncertainty without changing host policies.

Formal S6 must cover 1/12/24/48 active containers and 128/256 registered or idle
roots, after the ambient gate. If a prior gate fails, prepare the later matrix
but do not label it completed. User authorization to proceed does not establish
that observation is nonperturbing.
