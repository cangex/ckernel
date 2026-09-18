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

Remaining stages
----------------

X1 owner adapters and full counterexamples; X2 page_counter updates; X3 allocator stages;
X4 Socket/backlog/skb; X5 block I/O; X6 specialist routing; X7 integration
remain unaccepted until their own code, runtime truth and quality results
are available. Schema availability is not resource coverage.
