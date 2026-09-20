Y7 public-resource prototype validation, 2026-09-20
=================================================

Status: PASS_SCOPED for the frozen private-object VM cohorts and source
guards. Production low-overhead certification is NOT_ACCEPTED. This receipt
closes the bounded Y0--Y7 prototype, not arbitrary workloads, all blocking
relationships, automatic governance or a bare-metal deployment.

Source and independent evidence
-------------------------------

The final VM harness, C worker and BPF bundle were frozen at
c090b7ad0e40d853d50cd6742a9fab165c96c623. The ARM64 Image/vmlinux remain
native-source-equivalent to 50a202e65; the subsequent changes are tools and
documentation only. Image SHA256:
8d19768285e08059c36a887116c49e4ad173ecd864143e0409c88fe9b65e228d.

Remote immutable evidence root:
/dev/shm/cis-x-20260919/evidence/y7-batch-c090b7ad0-20260920.

* cpu/regression/y6-cpu-20260920-231545.log: 30 regression states, 15 captures.
* network/shared/y7-network-20260920-231745.log: nine states, 12 captures.
* network/separate/y7-network-20260920-232241.log: nine states, 12 captures.
* storage/shared/y7-private-20260920-232733.log: nine states, 21 captures.
* storage/separate/y7-private-20260920-233308.log: nine states, 21 captures.

Y7 therefore has 36 joint states and 66 captures. The CPU regression is
additional, not counted as another Y7 workload. Every cohort has three
preordered OFF/survey/profile rounds. No failed trial or favorable subset
was substituted. All payload/sequence checks, successful exits, identities,
window coverage, accepted source budgets and post-window detachment pass.
All offered operations complete and all 100-ms timeout counters are zero.
Raw records were independently replayed on host 14 and on the local machine,
not accepted merely from a guest PASS string.

The local download is under
.codex-tmp/container-interference-20260916/y7-final-evidence-20260920.
Its 281 files total 156880413 bytes; the archive SHA256 is
e9991a4570425630b79ac4f3b8dcd130f04addf494745d7fe0180f28999e1191.
Local independent results are y7-independent-final-20260920 and
y6-batch-independent-20260920. The y0-y7-index-20260920.json file links
stage-specific accepted evidence, rather than pooling different kernels,
fixtures or historical cohorts. Final first-guest-analysis clock checks
were added in 42b6ea99a; this does not change the measured capture binaries.

Workload and observed coverage
-----------------------------

Four registered roots, at most two active targets, run in an 8-vCPU, 4-GiB
ARM64 KVM guest. Storage actors have separate directories, files, FD tables
and address spaces. They perform 6000 validated arrivals each at 3 ms.
Network actors use private UDP connections, four client/server pairs in eight
PID/mount-isolated endpoints, with 4500 arrivals each at 2 ms. Host-network
clients and peer-network servers do not prove general forwarding lineage.

Shared and separate filesystem/queue selections remain distinct. Roles rotate
between target and bystander. A selected public queue legitimately contains
registered bystander traffic. Conversely, another queue's participants do not
appear in the selected queue. Different private directories do not require
sharing a writable file to reach a common journal or block backend.

Accepted joint observations include native counter updates, journal commit
waiting, orphan operations, block episodes, selected-CPU overlap and public
queue admission/service/backlog. Network shared-queue windows retain roughly
500 admission/service samples each; the split selection retains roughly 250,
with exactly the expected participating roots. This is participation, not
exclusive lock ownership or wire completion.

All six physical-page specialist windows have NO_ACCEPTED_SAMPLES. They do not
establish absence of allocator interference. The separate Y2 positive and
negative adapter tests remain the physical-page runtime evidence. The final
Y7 cohort also does not observe transaction-switch waits; three such events
occurred in an earlier retained compact storage cohort. These populations
are not merged. IP samples are execution observations, not accepted resource
relations. Bounded report truncation is retained and is not sample loss.

Measured costs
--------------

Values below are min/max observations, not confidence intervals. Each row
includes a complete scheduled profile set and first guest analysis, not just
one two-second capture. Management includes harness/controller/workers and
preparation; final archive/export/independent replay are excluded.

==================== ==================== =================== ===============
Cohort / placement   Profile manager CPU   OFF manager CPU     Manager peak
==================== ==================== =================== ===============
Storage / shared     1661.25--1682.06 ms   31.68--32.88 ms      69.63 MiB
Storage / separate   1694.99--1791.29 ms   32.78--33.31 ms      71.80 MiB
Network / shared     1564.25--1690.60 ms   59.31--84.92 ms     103.25 MiB
Network / separate   1603.05--1716.38 ms   59.52--89.40 ms      99.75 MiB
==================== ==================== =================== ===============

Survey manager CPU is 161.03--163.86 ms for storage and 190.65--223.75 ms
for network. Per-capture combined process CAPTURING CPU is 15.08--37.04 ms;
the existing 40-ms guard is not enlarged. Measured per-capture process RSS
is 30.52--39.59 MiB. Harness/analysis cumulative RSS peaks are 47.34--50.65 MiB
for storage and 77.09--77.45 MiB for network. Management cgroup peaks include
file cache and are cumulative across states, not independent per-state peaks.
Neither the 64-MiB capture-process policy nor these partial measurements prove
a 64-MiB whole-system bound. The network analysis process exceeds 64 MiB.

Storage profile P99 paired changes are -0.096 to +0.197 ms for targets and
-0.092 to +0.194 ms for bystanders. Network changes are -0.031 to +0.009 ms
and -0.031 to +0.007 ms respectively. P99 is record-only. Fixed offered-rate
throughput stays close to its programmed rate; this is not saturated capacity
or proof of <=1% observer overhead. Business aggregate CPU changes include
up to +8.70% in a storage pair; they cannot be hidden behind fixed throughput
or uniquely attributed to the observer from three pairs.

Matched background kernel-thread ticks in profile are 50--130 ms for storage
and 20--30 ms for network; OFF values are 30--140 ms and zero reported ticks.
The tick resolution is 10 ms; zero ticks does not mean no work. These are not
observer-exclusive background costs, omit unmatched short-lived threads and
do not recover all interrupt execution in business context. Whole-VM CPU,
per-actor CPU, softirq and memory gauges remain in the raw reports. Native
kernel-memory fields reported as zero are not proof of zero kernel overhead.

Latency accounting
------------------

Request-to-window time is 189.35--304.27 ms; each capture is two seconds.
The harness deliberately performs its first analysis after business completion.
Window-end-to-first-explanation is therefore 1.387--15.661 seconds in storage
and 3.734--8.769 seconds in network. Analysis-boundary wall time after business
is 0.803--0.929 seconds for storage profile and 1.152--1.249 seconds for network
profile, including bookkeeping. This is not automatic detection latency.

The retained guest boot ID and monotonic timestamps validate these boundaries.
An independent replay's host clock must not replace them. Periodic waiting
and anomaly-trigger discovery delay are NOT_MEASURED in this frozen schedule.
This run does not demonstrate the earlier fast-warning target end to end.

Failures, fixes and regression
-----------------------------

The initial storage run rejected missing filesystem parser provenance. Full
report retention was then reduced between sessions without discarding raw
captures. The first network run hit the real CPU worker guard. Overlapping
native wait events now use eight bounded per-CPU/root aggregate slots, with
unknown/overflow audits, while switch/migration/work events remain intact.
The next network run hit the unchanged 40-ms combined process limit and an
incorrect assertion excluding valid bystander queue participants. The checker
now compares all registered roots against actual queue placement. A bounded
16-KiB CPU JSON write buffer preserves every record and flushes inside the
charged capture phase. Byte-equivalence and write-failure tests pass.

All failed and intermediate cohorts remain in their original directories;
they are not relabelled PASS or silently mixed into final statistics. The
repeated 30-state CPU matrix retains shared/private/quota/migration/background
negatives. Preparation passed C/BPF builds and 758 Linux Python tests plus
21 owner and seven profile tests. The final analysis-only regression suite
has 759 tests (two Linux-only tests skipped locally), plus the same 28 tests.

Build and protection closure
----------------------------

Enabled and CONFIG_CIS_OBSERVE-disabled complete ARM64 Image/modules builds
pass. OFF Image SHA256 is
9e2d60b304d2faca21cb68a2282dbd8e8256e9f4ea3a7afe3bf32b38c985836a.
The final disabled vmlinux, ext4, jbd2 and sch_tbf checks contain no tested
CIS observer/tracepoint symbols. This is build/link evidence, not an OFF-image
booted performance comparison. Same-kernel OFF mode supplies the runtime
source-detachment evidence. Closure files are in y7-closure-20260920 remotely
and y7-closure-evidence-20260920 locally. Host kernel and boot ID are unchanged.

Reproduce raw replay with PYTHONPATH=tools/container_interference::

  python3 tools/container_interference/y7_acceptance.py \
      E/storage E/network NEW_OUTPUT
  python3 tools/container_interference/y6_cpu_check.py \
      E/cpu/regression/y6-cpu-20260920-231545.log NEW_CPU_OUTPUT

Residual scope
--------------

The prototype cannot universally identify the unique blocking tenant for
shared counters, journals, tags, qdiscs, all allocator locks or asynchronous
work. It does not establish hardware cache-line contention, device-internal
causes or complete forwarded traffic lineage. SPE is UNSUPPORTED. Shared
read-only image/cache contention and some in-flight revocation races remain
unverified. No 48/256-active-container, bare-metal NUMA, saturated-load or
production low-overhead acceptance is claimed. See y-coverage-guide.rst for
the exact default versus optional collector scope and evidence levels.
