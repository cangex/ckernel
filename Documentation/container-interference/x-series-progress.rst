X-series development and evidence ledger
========================================

Baseline: 7d073e111d8d6a2ec4d75a50fd99b3e23e969c70 on
codex/ckernel-periodic-profile. X0--X7 are development stages, not the
E0--E3 evidence levels or the production P1 acceptance gates.

X0 changes
----------

* Independent IP, owner, scheduler and reclaim BPF objects are compiled
  from the existing implementation. A session selects one object; the
  controller checks its exact program/map names and IDs before ARM.
* The source identity binds the entire collector bundle. ``bpf_sha256``
  now denotes that versioned bundle digest, not one ELF file. Individual
  ELF digests remain in ``collector_bundle.objects``. Old receipts cannot
  authorize this source; historical evidence is not rewritten.
* The relations-v3 contract separates holder/waiter, shared updates and
  queue/service. A counter contributor cannot be represented as a lock
  holder. A session ID is not an object lifetime. Wall intervals cannot
  be renamed as measured CPU time or cycles.
* Terminal scope includes unresolved identity, ancestor depth, unmatched
  events, nesting, expiry and IRQ filtering. Missing counters stay unknown.
  These overlapping counters are not added into a population denominator.
* The X0 VM suite tests actual pause/drain, shared manual interval budget,
  restart into PAUSED, nonce rotation, unregister, missed-slot suppression
  and failed-verifier FAULTED handling. A separate case waits the actual
  twenty-minute permit lifetime. Unit-clock tests are not expiry evidence.

Implementation and runtime validation are reported separately. The
independent ELF refactor has fresh ARM64 build and runtime checks below;
the earlier selective-autoload cohort is not used to certify the new bundle.
Total kernel memory/background CPU and production P1 remain NOT_ACCEPTED.

X0 runtime cohorts, 2026-09-18
-----------------------------

Evidence root on 14: /root/cis-20260916-232524/evidence. Tests use dedicated
ARM64 VMs, not the host kernel. No host reboot or Docker restart occurred.
The fixed Image source is fe4afbc31; its SHA256 is
4f11956a64c706d378fc2b0730f59d3f08efa4fec8430173282f0fe38a21d625.

* x0-final-runtime-20260918-2, tool source 4579e7a3d: control, injected
  verifier failure, owner plus six actual periodic slots, scheduler/reclaim,
  dentry/ordinary-file bridge and real 1200-second expiry all passed. Exact
  terminal inventory and scope checks passed for the completed captures.
  Archive SHA256: aba6382dcdc147a4181e1b4a7e58a0129cdfc0fcbdd63bc278e10273fd73c6ca.
* x0-crashes-runtime-20260918-1, source 304c8236b: failed after five worker
  crash cases because the recovery response exceeded the 8KiB packet bound.
  Recovery had succeeded; the wire result failed. Full evidence is now kept
  on disk and the response uses the same compact record as status.
* x0-crash-packet-20260918-1, source 2395b0239: failed at an invalid test nonce
  before controller crash injection. Fixed fixture nonces do not relax the
  production alphanumeric nonce requirement.
* x0-crash-nonce-20260918-1, source 440917236: all nine worker/controller
  SIGKILL/SIGSTOP cases passed, including verified cleanup after FAULTED.
  Offline checking initially misread the final QMP shutdown as signal JSON;
  d86968808 adds an artifact end boundary and verifies the same retained raw
  evidence. Archive SHA256:
  a123cc372185c56ba5a7c8525d80977b77b3673592afba46d21c2b471578dcfc.

Interrupted captures remain FAILED, with incomplete terminal scope. Their
PASS means verified lifecycle recovery, not valid profiling evidence. A
recovered record cannot become COMPLETE. Earlier failed cohorts are retained.
These cohorts validate the stated tool/kernel combinations, not a future
kernel with new observation hooks.

X1 source audit before implementation
------------------------------------

The fixed OLK ``kernel/locking/qspinlock.c`` emits contention_begin only
after entering its MCS queue path. The optimistic pending-bit path returns
without that pair. End marks completion of that observed interval, not
the later unlock. These tracepoints can supply an E1 slow-path interval,
not complete spinlock acquisition or holder history.

``files_struct->file_lock`` uses are not confined to ``fs/file.c``.
Additional direct operations occur in ``fs/legacy-filescontrol.c``,
``fs/misc-filescontrol.c``, ``fs/locks.c``, ``fs/proc/fd.c`` and
``io_uring/openclose.c``. Driver fields also named file_lock are different
objects and must not be included merely by field-name matching. An adapter
that only instruments alloc_fd/close_fd_get_file must not claim complete
FD lock ownership. It must either include those uses in its supported
configuration or explicitly downgrade incomplete history.

The rwsem reader owner field is not a full reader set. Reader-list overflow,
pre-window readers and non-owner APIs need explicit incompleteness. Waiting
end alone does not identify the blocker. No additional X1 owner resource
is activated or accepted by this source-audit document.

In this fixed tree, include/linux/rwsem.h aliases down_read_non_owner and
up_read_non_owner to ordinary read operations when DEBUG_LOCK_ALLOC is off.
Instrumenting only kernel/locking/rwsem.c's separately named non-owner
functions would therefore miss that semantic distinction in a normal build.
The later reader-set adapter must cover that configuration or refuse a
complete-reader-set claim. A writer acquisition can establish a new drained
boundary, but cannot reconstruct earlier unobserved readers. Killable,
trylock, nested and downgrade paths also need explicit outcomes; an E1
contention_end event is not an ownership release.

X1 first-layer implementation
-----------------------------

``sync.bpf.o`` loads only contention_begin/end and their bounded maps.
It supplies source-bound E1 candidates, not holders or full rwsem reader
sets. ``sync_report.py`` never infers a holder from repeated addresses.
The existing producer recursion barrier does not prove that generic
contention tracepoint recursion losses are zero; that coverage is explicitly
UNVERIFIED. Full entry and background costs remain unaccepted.

``sync_vm.py`` freezes three rounds of shared/private spinlocks, mixed
rwsem access, independent rwsems, reader-only and try-write cases. Fixture
ioctl truth brackets acquisition and release; ``sync_check.py`` validates
candidate object, task, cgroup and interval. It does not insert ground-truth
holders into the measured report, or use missing qspinlock events to claim
a population recall rate. Spin holds are bounded to 100 microseconds,
rwsem holds to 2 milliseconds, only inside a disposable VM. Kernel locking
algorithms are unchanged. Runtime results are recorded separately below.

X1 first-layer runtime, 2026-09-18
---------------------------------

x1-candidates-runtime-20260918-1 used tool source f389ada8d and the same
fe4afbc31 Image. All 18 fixed cases passed, with independent raw verification
by sync_vm_check.py. Shared spin observed 62/62/62 matching object/task/wait
intervals; mixed rwsem observed 34/30/31. Private spin/rwsem and reader-only
controls had zero matched wait intervals. Each try-write case exercised
actual failed attempts (31/32/32); no holder is inferred from their absence.
Archive SHA256:
8e392bfc1f0b0de7998aba201606cd0ff551f84fcd42f462004e9afd9bd0d2e7.

This is E1 discovery of object, actor and interval, not E2 ownership closure
and not population recall. Generic source recursion completeness remains
UNVERIFIED. The selected FD adapter is implemented at 181479d70, with bridge
fixtures at 432289a37. Its new kernel build and VM acceptance are separate
from these earlier E1 results; see fd-adapter.rst for pending cases.

FD ownership cohorts and source regression
------------------------------------------

The first full FD Image, source 181479d70, has SHA256
7873de76e80f5dc979a25722bd44637a70f0cb019acb465616a233e886e086ff.
The complete ARM64 Image and required fixture module linked; the earlier
all-driver-module build was interrupted and is NOT_ACCEPTED. Runtime cohorts
do not claim all configured modules were rebuilt.

* x1-fd-runtime-20260918-2 refused a fixture with stale fput symbol CRC. The
  fixture was rebuilt against new vmlinux.symvers without bypassing MODVERSIONS.
* Cohort 3 exposed missing device nodes in the container rootfs. Cohort 4
  then exposed concurrent BPF_NOEXIST watch creation. Only EEXIST followed
  by a live watch is now benign; capacity and other map errors remain fatal.
  Holder/scheduler records are also tied to the watch epoch.
* Cohort 5, tool source 527801cae: nine basic windows passed independent
  verification. Shared-table thread truth matched 40/40/40 relationships;
  independent tables matched zero. Real open/dup/fcntl/close produced
  40/40/39 observed relationships, without an invented population denominator.
  Archive: 1e9f4efc38b3354739a519b8aeb75a58e95a620a6ecf99ce3a9c7f313e459114.
* Cohort 6 exercised the explicit CLONE_FILES control but produced no actual
  reused FD-table addresses. It remains FAIL for its reuse requirement.
* Cohort 7, tool source edc946c76: explicit two-container CLONE_FILES matched
  20/20/20 truth relationships. Real table reuse matched 93/90/100 relationships
  and six reuse boundaries per round. The allocator helper runs on the worker
  CPU only for allocation, then restores management affinity. This controlled
  allocation locality is not a cost result. Raw archive:
  e53b9d7f3a16bc30215115c82d4bbe69c11e23283b3a18ffa8a7c1e069618b7d.
  c76fd3fb0 corrects the offline checker to distinguish container preparation
  from actual operations inside the sampling window. The original failed
  check remains. fc90add6a additionally requires real RETIRE events and a new
  watch epoch for every reused address; all 18 boundaries pass on that raw data.
* x1-fd-regressions-20260918-1: control passed but the ordinary shared-file
  bridge exceeded the unchanged 200000 entries/s protection, observing
  4429893 entries over about 1.0066 seconds. Capture stopped and cleaned up;
  its data remains FAILED. The combined tracepoint had activated FD events
  unnecessarily in a mutex/lockref session.

fc90add6a fixes this last regression by splitting the source static key,
membership bitmap, raw tracepoint and BPF ELF. Exact inventory and exclusive
source-switch checks are required. The new kernel/runtime cohort is recorded
separately after completion, not inferred from historical FD passes. Local
validation at this revision: 235 tests pass with one platform-specific skip,
21 owner tests pass and seven profile tests pass. Runtime and cost acceptance
remain separate from these unit results.

Independent FD source runtime, 2026-09-18
----------------------------------------

x1-fd-split-build-20260918-1 built the full ARM64 Image and required fixture
module at fc90add6a. Image SHA256:
421558bd8d5173d4098e92e3c02578433ce9e82bc2f5f110b5f3fdac7a8f01a8.
All-driver modules were not rebuilt. The host retained its original kernel.

x1-fd-split-runtime-20260918-1 froze seven distinct VM modes before execution.
Control (ten checks, eight sessions), basic FD (nine windows), lifecycle FD
(six), file bridge (five), specialists (six), and owner plus actual periodic
slots (eleven sessions) passed independent raw verification. Only FD was
enabled in FD windows; owner loaded no FD source, and idle checks observed
both switches off. The bridge emitted no FD resource records. The formerly
failing shared-file case recorded 4266 total entries over the two-second
window instead of hitting the source guard. These are different observation
durations, not a throughput or interference reduction percentage.

Shared FD-table thread truth matched 40/40/40 relationships, private tables
zero, and explicit cross-container CLONE_FILES matched 20/20/20. Reuse matched
128/128/128 relationships plus six retired/new-watch boundaries per round.
No wrong actor or cross-lifetime join was found among reported relationships;
the fixed eligible-event population recall test remains unimplemented.
Native open/dup/fcntl/close observed 39/38/39 relationships without fixture
truth. No population accuracy is inferred for the native-operation bridge.

The final cost mode stopped at openloop0sched after fourteen complete captures.
Its combined-process CAPTURING CPU was 40600240ns versus the unchanged
40000000ns limit. Although worker capture finished without record loss, the
controller correctly retained PARTIAL and the cost protocol remains FAIL,
with subsequent measurements not run. No threshold relaxation or identical
retry was used to certify it. Full runtime archive:
e0ff8195a8823c34c1ef1792ace28569e76b2447e41b93fdd421e04486cc772b.
An immutable first-five export has SHA256
e9d9b78a70c1b02243f1beee4b4c9910b2996b740bab805a087bb05e71d9edba.

For the fifteen sparse FD windows, worker CPU was 81.71--101.00ms including
preparation, with 1.00--2.01ms in the armed capture phase. Combined-process
CPU was 97.03--126.17ms and peak combined RSS 29.73--34.20MiB. These exclude
incompletely accounted business-context callbacks and kernel background or
memory costs; they cannot certify total low overhead.

The dedicated high-rate guard cohort at 5108b811e first failed its tester's
incorrect expectation of FAILED. The existing worker contract emitted PARTIAL
on ENTRY_RATE_LIMIT, safely unloaded, and the two containers completed another
1642240/1652224 operations in buckets beginning after source detach. The
original failed cohort is retained as x1-fd-guard-runtime-20260918-1, archive
34e0f132250ac3ee0c25bf816f31cb8162f2fe3825200f7fff34e3ddbe8b4b5d.
a7c332eb6 corrects only the test expectation, not the production result,
threshold, workload or refusal to attribute incomplete captures.

x1-fd-guard-runtime-20260918-2 ran the new fixed three-round cohort and ten
crash/recovery cases at a7c332eb6 with the same fc90add6a Image. Independent
fd_guard_check and x0_check verification both passed. Each dense FD capture
remained PARTIAL with ENTRY_RATE_LIMIT, no admitted attribution, verified
unload and subsequent successful operations from both containers. Observed
entries were 4444746, 4407371 and 4452351 in approximately 1.00--1.01 seconds;
the unchanged policy was 200000/s. The periodic check is reactive, not a hard
per-event ceiling: these overshoots and the pre-detach observer cost remain
limitations. After detach, each container completed between 1648640 and
1661440 operations in the retained post-detach buckets. No throughput or
tail-latency acceptance is inferred from continued progress.

The ten crash cases include the newly independent FD worker. Their PASS is
cleanup/recovery acceptance only; interrupted captures lack complete terminal
scope (scope_audit_complete=false) and cannot be accepted as observations.
Archive SHA256:
59b9c5175fb67fee865f25e21514ffab2545b8577423eb23aa7ffba56adcfa1d.
Local tool tests at a7c332eb6: 237 passed, one platform-specific skip; owner
tests 21 passed and profile tests seven passed. Total source/background cost,
dense FD profiling and the stopped cost matrix remain NOT_ACCEPTED.

Remaining stages
----------------

X1 owner adapters and full counterexamples; X2 page_counter updates; X3 allocator stages;
X4 Socket/backlog/skb; X5 block I/O; X6 specialist routing; X7 integration
remain unaccepted until their own code, runtime truth and quality results
are available. Schema availability is not resource coverage.
