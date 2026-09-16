M6 validation and combined-domain record
=======================================

Implementation and source boundary
----------------------------------

This stage starts at M5 commit 603b67189cb35e72542b6fecf5ee86f14e906c38.
CONFIG_CKERNEL_M_NET is default disabled, and Maple remains disabled in all
new domain tests. The existing host kernel was not replaced. Builds use the
recorded ARM64 GCC 10.3.1 external O= tree; runtime is in isolated ARM64 KVM
guests. Guest CPU placements and configuration hashes accompany each run.
These are not bare-metal NUMA-isolation acceptance results.

Native reference and retained failures
-------------------------------------

The first network-policy fixture using AppArmor parser 2.13.6 failed the native
deny/audit expectations on an unchanged kernel. The guest-only fixture was
recalibrated with Debian AppArmor 3.0.8-3, explicit policy ABI 3.0 and its matching
libc/loader; no host packages or network settings were changed. Real TCP/UDP
allow, deny and audit were required before testing the new fast path. Native
reference ``m6-final-native-20260916_124726.log`` has SHA256
09b2f2086485dcef39c91a36b598ceef4fe9af4dc311e54cb91f8f133564185e.

An incomplete transport package stopped the initial source preflight after
two headers; it never reached compilation. The preflight now verifies all
inputs before applying any, and permits only byte-identical owned partial
application. Its original failure is retained separately.

The first complete diagnostic kernel built successfully, but
``m6-ordinary-20260916_135338.log`` failed the fork/exec test's expected hit
count (SHA256 8fe0506782767fcc34de02ad9b973cd774a39720524c95e3ef5dad2172ca1e71).
The fixture incorrectly assumed ordinary fork retained the same cred pointer.
Native ``copy_creds`` uses ``prepare_creds`` unless the eligible CLONE_THREAD
sharing branch applies. The fixture now requires native fallback after fork
and again after exec, while preserving successful socket use. No kernel
eligibility check was relaxed. ``m6-final-userspace.sha256`` distinguishes the
corrected fixture from the initial build archive.

Correctness evidence
--------------------

The corrected ordinary and pressure runs each passed 16 managed cases plus
eight TCP/UDP permission assertions and two legacy-policy characterizations.
The latter describe the calibrated unmediated policy, not extra independent
loads. Cases cover confined creation, actual qualification hits, inventory
overflow/reuse, credential change, fork/exec, SCM_RIGHTS, concurrent policy
replacement, accepted TCP clone/revoke, revoke races, batch exit, ABI errors,
allocation faults, CPU/cgroup migration, stacked denial, abandoned original
owners and network-namespace change. Audit delivery was enabled, lost=0.

Pressure log ``m6-pressure-20260916_135555.log`` SHA256:
a30994c80c61f8807c9029682c2a28f1cec79840de46ab4d8204c4c5f209cc17.
Its immutable Image SHA256:
c47bf19487b46259fdd1d58754b3b6529bc14139dfc1d63d6781ec487b9d1091.
Fault injection attempted 64 creates: eight rejected and 56 completed, then
all 64 uninjected recovery creates succeeded. Under a 48 MiB cgroup limit,
the deliberate 24 MiB touch yielded memory.current=25427968 bytes;
post-tests=25948160 and post-unmap/500ms=782336, with zero OOM/OOM-kill.
These snapshots are not proof of complete deferred release or zero overhead.

The cumulative image also passed M4 security/open/KUnit regressions and both
ordinary and pressure M5 FD regressions. The four-domain diagnostic workflow
ran statx/open/read/dup/close/self-signal/UDP, with Maple disabled: 48 distinct
states, 64 workers and 2000 operations each. Every all-domain worker recorded
real activity in all four domains, with file and security reference loans
balanced; Core workers recorded no domain hits. Raw log
``m6-combined-diagnostic-20260916_135608.log`` SHA256:
2d46464137e091153a7427e4bf7bf471efb5443d8d50a78c92fc05913b2e3683.
This short instrumented matrix is a functional gate, not performance evidence.

Configuration and performance completion
---------------------------------------

The configuration matrix exited zero. Cumulative, NET-only minimum, VFS-only,
Core-only and fully disabled configurations completed full Image and module
links. NET-only repeated the managed cases under pressure. Core/off repeated
native allow/deny/audit and legacy characterizations without exercising an
absent feature ABI. VFS-only ran private-tree, lease-contract, query-lease,
fault/pressure stress and 12 open-lease regressions with native denial; it did
not count the earlier generic lsm.c reload SKIP as a success. This supplies
the previously missing file-domain minimum-configuration gate on cumulative
source with other domains disabled. Its raw log is
``m6-vfs-minimum-20260916_142140.log`` SHA256
c734f9d8d3c53a937588be4666e7d4beabb234604c7053baab48f06f8b07e5c7;
Image SHA256 3127861e2cccbda15ed4945a4171707647f7a40e714bbe584a60ca05c03262c9.

The separate full performance Image/modules build also exited zero, with
KASAN, lock debugging and allocation fault injection disabled. The fixed
Image SHA256 is de5ec04d34a3c3db972fa8ae5bad8f95a36f8a400db097e0f551fa95b61ea003;
config SHA256 is 1a7348334ce43fd91cdbdc6f2ee7cfb31c1e53c8856d707106896ea5f23d0d92.
Final source verification matched every M6 kernel integration file to the
original diagnostic-build source archive; only the documented fork fixture
and result documentation changed afterwards. The fixed
network matrix completed 360 states / 480 workers, n=3, alternating roles and
Core/NET order. Its log ``m6-perf-20260916_145815.log`` SHA256 is
0f8e103dd08279b6cad7bda38f3de72a078015f42de897a35290dea01d5cb39d.
Strict parsing checked every planned state, operation count, native fallback,
inventory bounds and zero OOM. Paired execution overlap was at least 93.79%
of each worker's timed interval, not complete overlap in every sample.

An operation is one one-byte loopback UDP send plus receive, not an HTTP
transaction or a TCP connection. Closed-loop workers perform 200000 operations;
the 20 us equal-arrival experiment performs 20000. The ranges below are the
four target/bystander and placement group means of three runs, not confidence
intervals. All raw quantiles, maxima and CVs are retained in analysis-net.

NET versus Core, paired steady closed-loop:

* Unconfined: throughput -2.88..-0.96%, service P99 +0.78..+2.90%, foreground
  CPU/op +1.30..+3.18%. First-operation cost ranges -1.41..+4.98%, and maxima
  +4.29..+65.43%. Native unconfined checks are already cheap; local lookup is
  not presumed to be a benefit.
* Mediated: throughput -4.08..-3.07%, service P99 +2.67..+4.32%, CPU/op
  +3.97..+5.14%. The eligibility lookup precedes the unchanged native policy
  path; it must not bypass that path to manufacture a gain.
* Equal-arrival operation P99: unconfined -0.76..+1.12%, mediated
  +1.22..+5.68%. Arrival-to-completion P99 instead changes -0.09..+3.00%
  and -0.53..+0.11%, respectively. These are different latency definitions.
* Exhaustion retains native success, but unconfined throughput changes
  -4.92..-4.08%, P99 +4.18..+21.20% and CPU/op +4.99..+6.54%.
  Mediated exhaustion throughput changes -3.95..-3.11% and P99 +3.62..+4.39%.
* Migration, invalidation and their first/max latency records remain separate
  in the full table. For example, mediated migration P99 increases
  +3.39..+15.40%, and one group-mean maximum increases 588.27%. These samples
  are not discarded or interpreted as a stable maximum-latency guarantee.

For paired steady runs across both policy workloads, matched-kthread CPU
averages 55.53 us foreground / 35.89 us cleanup in Core, versus 66.72 / 47.00 us
in NET. This is partial attribution, not total background CPU. Supervisor
preparation averages 9.04 versus 10.38 ms; worker preparation 0.650 versus
0.654 ms. Preparation includes setup/scheduling and is not solely CKM init.
Observed final drain waits span about 20.1..40.3 ms in Core and 21.2..58.8 ms
in NET and include the polling interval. No strict reclaim-latency bound follows.

The six-vCPU NET state reports 5408 logical management bytes per instance,
excluding Core, allocator rounding and retained credential/policy graphs.
Paired steady ready/finished memory.current is 4718592 bytes in both modes;
post-drain observations range 413696..540672 bytes (Core) and 417792..540672
(NET). Coarse cgroup snapshots do not mean the extra state is free or establish
leak freedom.

Nonparticipating socket create/close
----------------------------------

Nine separately recorded states requested 0/16/128 idle NET instances, n=3,
and timed 20000 socket-create/close pairs in a task not bound to any instance.
The native clone/free hook still scans the RCU owner registry. With 128 idle
instances, mean P99 is 4243.33 ns versus 3490 ns at zero (+21.59%), CPU/op
2.737 us versus 2.094 us (+30.73%), and total wall time +32.25%. All three
rounds show increases, but this is not an isolated causal lock-cost measure.
Logical management for 128 states is 692224 bytes, excluding retained graphs.

The 16-instance mean is worse (+70.68% P99), dominated by the retained second
round (10790 ns, compared with 3450/3630 ns in the other rounds). Do not claim
monotonic scaling or delete that round. Requested instance counts and a fixed
cleanup gap are not a proof that no deferred registry entry remains. This
test exposes a nonparticipant cost; the domain remains performance-unaccepted
and default disabled.

Combined-domain performance
---------------------------

The same non-debug Image completed the fixed Maple-off combination matrix:
144 states / 192 workers, n=3. Every enabled worker exercised all four domains;
file/security loans balanced and post-drain FD/socket conservation passed.
Log ``m6-combined-performance-20260916_150352.log`` SHA256:
1fcbbeb7c43c5fe0891833d426640c19335dc6ef99eb0b9e5712e5bd359f5b5f.
Minimum paired execution overlap was 90.16%. The operation is statx, open,
read, dup, close, self-signal and UDP send/receive on independent instances'
identically prepared private read-only tmpfs. Do not compare its unit with
the network-only operation or call this a production Agent workflow.

All-domain versus Core paired steady closed-loop throughput increases
7.03..14.31%, service P99 decreases 6.40..12.69%, and foreground CPU/op
decreases 7.47..13.71%. Pair-versus-solo P99 in Core grows 13.27..20.38%;
the all-domain change ranges -2.46..+2.00%. These observations do not assign
independent gains to each component, and specifically do not overturn NET's
independent regression. The whole-window invalidation result includes the
first half before target revocation; it is not a post-revoke-only result.

The equal-arrival result does NOT establish tail isolation. Operation P99
changes -10.82..+18.29%, while arrival-to-completion group-mean P99 changes
-5.81..+1509.27%. The largest group is the swapped bystander: Core's three
response P99 values are 62070/66910/66790 ns; all-domain values are
67440/66660/3016370 ns. Keep all three rounds. The third enabled run has
service P99=10150 ns, so response queuing/deadline delay is materially larger
than one operation's service time. Scheduling, backlog, shared software and
host disturbance have not been causally separated. No follow-up selective
rerun replaced this result, and no hardware-only explanation is claimed.

Matched-kthread CPU averages 4.294 ms during Core foreground / 94.81 us
cleanup, versus 4.408 ms / 116.17 us all-domain. These costs do not improve
alongside foreground CPU and remain only partial background accounting.
Supervisor setup averages 12.56 versus 10.92 ms and worker preparation
0.877 versus 0.880 ms, including scheduling/setup rather than isolated init.
Observed drain spans 20.1..30.2 ms (Core) and 28.6..50.9 ms (all-domain),
including polling. These do not bound deferred cleanup or batch-exit tails.

The combined domain queries report 7400 logical payload/management bytes per
instance at six vCPUs, excluding Core, slab rounding, private tmpfs contents
and retained policy graphs. Ready/finished memory.current remains 4718592
bytes in both modes; post-drain snapshots range 323584..466944 (Core) and
323584..462848 (all-domain). Small state costs cannot be inferred to vanish
from those coarse readings. Complete CSVs and definitions are retained in
analysis-combined. Combination correctness and bounded mechanism measurements
are complete; blanket performance/isolation acceptance is not.

Background and acceptance limits
-------------------------------

Inventory bounds do not bound scheduling, lock, RCU or workqueue delays.
Foreground CPU, matched-kthread CPU and global CPU ticks overlap and cannot
be added. Matched identities miss some short-lived work; the 250 ms observation
tail is not complete reclamation. Owner-cost runs retain a one-second cleanup
gap, not proof that every deferred registry removal finished before the next
requested idle-instance count. Exact cold enrollment/setup timings and first
operation timings are different fields. Three run quantiles and maxima are
not stable tail guarantees or confidence intervals.

Functional pressure and batch exits do not replace their unmeasured detailed
tail-performance matrices. M3 and M4 documented performance regressions and
M5 revoke/cold/max-tail regressions remain, and M2 is still paused/unaccepted.
See ``lifecycle-and-reentry.rst`` for local versus shared operations, mandatory
coordination and the separate-review requirement for strong-budget semantics.
