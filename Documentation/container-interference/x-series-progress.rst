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

Implementation and runtime validation must be reported separately. The
independent ELF refactor requires fresh ARM64 build and runtime checks;
the earlier selective-autoload cohort cannot certify the new ELF bundle.
Total kernel memory/background CPU and production P1 remain NOT_ACCEPTED.

X1 source audit before implementation
------------------------------------

The fixed OLK ``kernel/locking/qspinlock.c`` emits contention_begin only
after entering its MCS queue path. The optimistic pending-bit path returns
without that pair. End marks completion of that observed interval, not
the later unlock. These tracepoints can supply an E1 slow-path interval,
not complete spinlock acquisition or holder history.

``files_struct->file_lock`` uses are not confined to ``fs/file.c``.
Additional direct operations occur in ``fs/legacy-filescontrol.c``,
``fs/misc-filescontrol.c``, ``fs/locks.c`` and ``fs/proc/fd.c``. An adapter
that only instruments alloc_fd/close_fd_get_file must not claim complete
FD lock ownership. It must either include those uses in its supported
configuration or explicitly downgrade incomplete history.

The rwsem reader owner field is not a full reader set. Reader-list overflow,
pre-window readers and non-owner APIs need explicit incompleteness. Waiting
end alone does not identify the blocker. No additional X1 owner resource
is activated or accepted by this source-audit document.

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
algorithms are unchanged. Runtime results must be collected separately.

Remaining stages
----------------

X1 owner adapters and full counterexamples; X2 page_counter updates; X3 allocator stages;
X4 Socket/backlog/skb; X5 block I/O; X6 specialist routing; X7 integration
remain unaccepted until their own code, runtime truth and quality results
are available. Schema availability is not resource coverage.
