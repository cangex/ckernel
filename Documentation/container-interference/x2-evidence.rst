X2 counter evidence ledger
==========================

The 2026-09-18 user exception is recorded in x2-authorization.rst. It does
not change the general 40ms CAPTURING process budget or erase old failures.

Fixed hierarchy fixture
-----------------------

Kernel source e1cc144b7 includes the native page-counter observation calls;
userspace and fixture runner source 336fc52c4. The ARM64 Image SHA256 is
ebbab2092c6e81376b5bf5d5e016b551dd5da3ee685837120a68064a17377891.
The complete Image builds and boots in the dedicated VM. A complete module
build for this revision has not run. This is not host-kernel deployment.

Evidence directory on 14::

  /root/cis-20260916-232524/evidence/x2-counter-runtime-20260918-2

Serial x2-counter-20260918-225238.log contains the raw records and fixture
truth. counter_vm_check.py independently replays them: 18/18 windows PASS,
1008/1008 eligible complete calls matched across two container identities.
The fixed cases are same leaf, same ancestor with different leaves, private
objects, ancestor limit failure with rollback, frequency change and CPU
migration. Each case has three rounds; the VM uses source shift=0 only for
this declared truth population. This is not production sampling recall.

Combined controller/worker CAPTURING CPU is 9.01324--11.08130ms per 2s window;
maximum measured combined process RSS is 34.19140625MiB. These are process
accounting figures, not total observer CPU or total kernel/BPF memory.
Asynchronous kernel cost is still unresolved. The seven-collector control
cohort x0-control-20260918-225420.log passes the independent x0_check.py:
11 checks, 9 sessions, all recorded scope audits PASS. Source-off snapshots
and object absence are verified, not inferred from stopping output.

Retained failures
-----------------

The first ARM64 build used a struct trace field rejected by this OLK trace
generator. e1cc144b7 uses supported scalar trace fields; the raw tracepoint
payload still carries the full bounded sample. The failed log is retained.

The first fixture runtime stopped in sameLeaf0 because its independent
checker joined overlapping intervals before selecting the actor. Commit
336fc52c4 checks actor identity before call multiplicity. Replaying that
unchanged raw window matches 64/64 eligible calls. Its original failed
cohort remains a failed, incomplete run, not a new 18-case success.

Meaning and remaining gaps
--------------------------

The production report exposes real sampled updates, protection propagation,
ancestor failures and rollback. It never supplies a fictitious mutex owner.
Across-call address candidates remain E1 until native object lifetime is
proven. Fixture-known stable lifetime is external truth, not production
evidence. Call elapsed time includes observation and preemption; it is not
atomic cycles or cache-line contention. Stages within a call are not summed
as independent call costs, and sampled counts are not scaled to a total.

X2 is INCOMPLETE: ordinary memcg bridge, selected-ancestor bounded aggregate,
native lifetime/address reuse, no-shared-counter CPU competition, high-rate
source audit and total cost remain open. SPE/PMU cache-line proof requires
separate supported hardware. X1 rwsem/recall/cost gaps remain open as well.
X3--X7 have no runtime acceptance from this cohort.

The ordinary bridge added after this cohort runs mmap/touch/munmap in two
containers with default shift=6, fixed OFF/counter order, no fixture ioctl,
and per-container resource snapshots. It must be tested separately; its
operation count is not ground truth for the number of native counter calls.
