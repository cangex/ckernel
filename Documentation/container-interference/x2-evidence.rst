X2 counter evidence ledger
==========================

The 2026-09-18 user exception is recorded in x2-authorization.rst. It does
not change the general 40ms CAPTURING process budget or erase old failures.

Fixed hierarchy fixture
-----------------------

Kernel source e1cc144b7 includes the native page-counter observation calls;
userspace and fixture runner source 336fc52c4. The ARM64 Image SHA256 is
ebbab2092c6e81376b5bf5d5e016b551dd5da3ee685837120a68064a17377891.
The complete Image builds and boots in the dedicated VM. The same frozen
configuration's full modules target subsequently passes (1702 .ko files
hashed); Image and configuration hashes are unchanged. This is not a build
of every possible Kconfig combination or host-kernel deployment. Module
evidence is x2-counter-modules-20260918 under the same evidence root.

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

X2 is INCOMPLETE: selected-ancestor bounded aggregate,
native lifetime/address reuse, no-shared-counter CPU competition, high-rate
source audit and total cost remain open. SPE/PMU cache-line proof requires
separate supported hardware. X1 rwsem/recall/cost gaps remain open as well.
X3--X7 have no runtime acceptance from this cohort.

Ordinary memory bridge
----------------------

Source 8f9540252 runs mmap/touch/munmap in two containers with default shift=6,
fixed OFF/counter order, no fixture ioctl, and per-container resource
snapshots. Each actor has 16 operations, touching 8MiB each, with a 2ms gap.
The memory limit is 64MiB per root. This is not a saturation benchmark.

Evidence directory on 14::

  /root/cis-20260916-232524/evidence/x2-memcg-runtime-20260918-1

Serial x2-memcg-20260918-230703.log passes counter_mem_check.py's independent
replay: six OFF/counter states, 192/192 completed memory operations, three
clean capture sessions. The native stacks include try_charge_memcg and
uncharge_batch under real anonymous allocation/unmap, plus FD accounting
outside the operation boundary. The latter is retained but is not passed
off as memory-workload charge attribution.

There is exactly one selected complete native memory-counter call per
actor per capture in this workload. THP appears in the actual allocation
stack. This is enough to establish the bridge, not to estimate frequency,
contention strength or per-operation total counter cost. The business
operation count is not counter-event ground truth, so recall is UNAVAILABLE.
Same-address candidates still have unknown native lifetime.

Combined CAPTURING process CPU is 8.51601--9.55027ms, maximum combined process
RSS 32133120 bytes. The recorded paired whole-loop rates change by +0.61%
to +2.62%; operation medians and CPU also vary. These short n=3 measurements
with pacing and warm-state variation do not establish zero perturbation or
performance acceptance. All 16 operation latencies per actor are retained;
they are not a reliable response-P99 estimate. proc/stat snapshots retain
VM-wide CPU, not identified background observer cost. Kernel/BPF memory
and asynchronous CPU remain incomplete.

Local exported archives (SHA256)::

  fixture: 3e5a4e27607cbfd8cfe6ccf4eb2659351125ca3520ff1b06eea8df081e8a15fc
  bridge: fc2b7ab5bfb80bd23549a5485f934b2f26d42cf70d281bb05b5828d537d7033d

Final Linux replay
------------------

Verifier/source 3ea5783fd was checked out with the selected kernel files in
a separate Linux directory. All 253 tool tests, 21 owner tests and 7 profile
tests PASS, with no SKIP. Earlier tools-only exports skipped the selected
FD source audit; the final checkout restores that coverage, not the test's
expectation. The two new operation-boundary tests run here as well.

The Linux fixture, ordinary bridge and control replays all PASS. The two
verification JSON files are byte-identical to the local independent replay.
Logs are in x2-final-audit-20260918 under the evidence root. Dedicated VMs
have exited; root free space remains 6.2GiB. No old evidence was removed.
