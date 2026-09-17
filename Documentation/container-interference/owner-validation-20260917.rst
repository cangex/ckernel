Fast warning and ownership validation, 2026-09-17
================================================

Scope
-----

Development extends 31df84d26053830666f8a1ec0eaeba3e15172ca4 on
codex/container-interference. Tests used disposable ARM64 KVM guests,
8 vCPUs / 4 GiB, containerized target and peer. No host kernel replacement,
host restart, Docker restart or modification to CKernel/CKernel-M occurred.
CONFIG_CIS_OBSERVE and --fast-alert are opt-in, not accepted defaults.

Build and mechanism checks
--------------------------

The non-preempt build completed a full Image and modules. PREEMPT=y
completed an Image and the matching fixture module. CONFIG_CIS_OBSERVE=n
compiled the three modified call-site objects; this was not a separate
full disabled-kernel boot. Builds used GCC 10.3.1 / binutils 2.37. The native
hooks are the same across the final guest runs; later iterations changed
userspace/BPF tests and report export, not the native lock implementation.

The final recorded suite is owner-20260917-114401.log. Its SHA256 is
1cce772479ccabc1b23ed8876797ee805313d7ac7c738194a2bf2517f74f0055.
The environment JSON next to it records image/initramfs and source hashes,
host CPU assignments and commands. The bounded-evidence checker passes:

* Shared mutex: 395 E2 intersections, both holder directions observed.
* Private mutex: two different objects, zero cross-object edges.
* Address reuse: two reset boundaries, 391 E2 intersections, zero edges
  crossing a reset or contradicting the fixture holder intersection.
* Busy-holder preemption: 75 E2 intersections with observed preempted
  holder segments, no cond_resched in the busy hold, PREEMPT=y.
* Real shared dentry: 8192 induced fallback operations, 15 E2 intersections
  in the exported prefix; both directions observed.
* Private dentries: two objects, zero slowpaths and zero merged edges.
* Automatic dentry diagnosis: first candidate 147.50766 ms after the
  workload barrier, 13 E2 intersections, both directions observed.

No wrong holder intersection, cross-reset edge or export loss was found
in these selected mechanism cases. These numbers count intersecting
intervals, not unique blocked requests. They do not establish complete
recall or a production zero-false-positive rate. Dentry tests use actual
dget/dput/lockref fallback, with explicit test-only delays in the fixture.
They are not unmodified HTTPD performance results.

The same suite passed the 31 identity checks, 13 state-machine checks,
RSS-failure and metric regressions. Eleven owner-parser unit tests and
14 positive/negative symbol cases pass on the build machine. Serial logs
have no observed BUG/Oops/warning; this is not KASAN/lockdep certification.
Raw stack IPs and bounded symbolized leaf-to-root stacks are exported;
unknown module/BPF symbols remain unknown rather than guessed.

The final CPU-competition candidate arrived at 60.13470 ms; the quota
scenario at 64.01385 ms. Earlier CPU-warning trials ranged approximately
60--564 ms, and quota trials sometimes had no PSI warning or took about
2.09 s. These are not a universal detection bound or detection-P99 study.
The generic bench control produced no candidate in the final suite.

Failures retained and corrected
-------------------------------

* Initial native trace header instantiated CREATE_TRACE_POINTS twice;
  compilation failed and was corrected before guest execution.
* An older OLK BPF verifier rejected a modified raw-tracepoint context
  pointer. The skipped argument is now captured as a scalar at entry.
* Initial slow-lock export overflowed buffers. Diagnostic epoll draining,
  bounded lockref prefixes and explicit terminal loss audit replaced an
  implicit incomplete stream. Old lossy logs are not E2 success evidence.
* A PREEMPT_NONE/cond_resched run was not accepted as involuntary-preempt
  truth. A real PREEMPT=y busy holder without cond_resched was added.
* A manual dentry trial produced no closed E2 edge despite valid workload
  exit. It remains a coverage failure; process exit is not proof of closure.
* owner-20260917-114026.log hit the entry budget after three ordinary
  _raw_spin_lock samples incorrectly started an owner window. The final
  trigger admits explicit supported slowpath symbols only. The budget was
  not raised, the failed log remains preserved, and the full fixed suite
  was rerun rather than deleting the bench case.

Exploratory cost, not S6 acceptance
---------------------------------

owner-cost-20260917-112351.log contains five fixed alternating OFF versus
IP+fast-alert pairs for each of closed-loop throughput and equal-arrival
open-loop latency, two containers, four-second measurement windows. Every
round is retained. It predates the final symbol-filter and report-only
changes; no owner diagnosis was triggered in that cost matrix. A host
kernel build overlapped part of the run, so this cannot separate observer
cost from host resource interference or serve as formal final-version S6.

Mean paired throughput degradation was 0.1736% / 0.2300% (target / peer),
with 95% paired-t intervals [-3.3782, 3.7255]% / [-3.4540, 3.9140]%.
This does not establish the <=1% gate.

Mean paired P99 increase was 18.3040% / 17.8583%, or 11.494 / 11.310 us;
95% intervals were [-2.2561, 38.8642]% / [-5.4330, 41.1496]%.
The <=2% P99 gate is not passed. Startup process CPU was about 86.6--107.1
ms; steady monitor-cgroup CPU averaged 0.5371 ms/s. Daemon RSS ranged
10,395,648--12,328,960 bytes. These process numbers exclude separately
scheduled kernel PSI work and PMU interruption; they are not total observer
cost. Kernel/system snapshots remain in the raw logs.

No new formal <=3% owner-diagnostic overhead result or 12/24/48-container
S6 acceptance is claimed. Previous S6 failures remain outstanding. The
next cost study must isolate PSI, IP, and owner collectors, stop concurrent
host builds, preserve pair ordering, and account for target/peer tails,
kernel monitor work and all CPU/memory costs.

Evidence location and limits
----------------------------

On the authorized development host, raw build/runtime evidence is under
/root/cis-20260916-232524/evidence. Source tools, documentation, tests and
the evidence checker are committed; multi-megabyte raw traces remain out
of Git. The local delivery includes hashes, summaries and publication
readback. Incomplete intervals, unknown identities and uninstrumented
direct d_lock owners remain unknown. An E2 ownership overlap is not an E3
claim that a container caused the whole application's throughput loss.
