Open-reference prototype validation status
==========================================

M3-C is implemented and default off. Functional evidence below permits the
next independent prototype to be developed; it is NOT full M3 acceptance,
a performance improvement, or a proof of bounded cross-instance latency.

Diagnostic evidence
-------------------

The ARM64 full Image/modules build used KASAN, lockdep and task-local failslab.
The isolated guest passed 12 open-reference cases, prior private-tree/query
tests and concurrent pressure/revoke regressions. Open tests include separate
offsets, dup, native fallback, DAC and actual AppArmor denial, O_DIRECT, exec,
remount/unlink, CPU migration and SCM_RIGHTS after the originating task exits.
Open loans balanced at quiescent checkpoints. The initial O_DIRECT assertion
was a test error: native shmem_file_open supports FMODE_CAN_ODIRECT on this
OLK. That failed run was retained; the test was corrected, not the kernel.

64 allocation probes observed 5 rejected and 59 completed creates, followed
by 64 successful uninjected recoveries. The open-specific 32 probes observed
3 rejects and 29 completes. Four batches of 16 independent instances ran
under a 48 MiB memory-cgroup limit with 24 MiB resident pressure and explicit
reclaim. This is diagnostic coverage, not pressure-tail-latency acceptance.

Diagnostic log: m3c-diagnostic-20260916_092858.log.
Diagnostic Image SHA256:
1ab495a081f04451e49fd778e808c0b84382e4be7416483dadf37ba2d84ef9d4.
Legacy lsm.c still reports a policy-reload SKIP. Its zero exit is not a pass
for that subcase. Post-FMODE_OPENED IMA-error cleanup was source-audited, not
fault-injected at runtime.

Performance evidence
--------------------

Two batches are preserved separately. open-perf-20260916_095139.log had
residual mutex/spinlock/list debug options and is preliminary only. The
replacement build removed those options and all active KASAN/lockdep/failslab
instrumentation; it completed full Image/modules linking before measurement.

The clean batch open-perf-clean-20260916_104904.log contains 252 fixed states,
336 worker measurements, three rounds, target-only/bystander-only/pair runs
and role exchange. Every operation is open + fstat(size verification) + close.
Steady-state modes separate native shared layout, native private layout, Core
on the same private layout, and VFS loans on that layout. Maple is disabled.
Cold, exhaust, migration and invalidation observations are retained. The
equal-arrival control uses 20 microseconds between scheduled operations.

Compared with Core on the SAME private layout, paired steady closed-loop
VFS throughput changes by -3.82% to -3.05%; service P99 by +3.67% to +6.07%;
foreground CPU per operation by +3.40% to +4.41%. These are ranges across
role/placement three-round means, not confidence intervals or pooled P99s.
Exhaust, migration and invalidation also show regressions in this batch.
With equal arrival rate, service P99 changes by +3.07% to +7.80%, while
response P99 (including dispatch delay) ranges from -1.03% to +5.77%.
No speedup or isolation acceptance is claimed; keeping only a favorable
response-latency statistic would misrepresent these results.

Clean log SHA256:
1b391ed0b9ead560a3e60fcc4a5cb43eb78c20883f9d1b76b17dff93924cba44.
Raw foreground CPU, matched-kthread runtime, total CPU ticks, inventory and
memory snapshots are retained. These CPU measures overlap and must not be
summed. Kthread matching is not complete IRQ/background attribution. The
250ms post-close observation is not proof that all RCU callbacks drained.

Remaining acceptance work
-------------------------

Complete configuration-matrix builds (off, Core, minimum and cumulative),
pressure/batch-exit performance, stronger background attribution and direct
same-config object-footprint comparisons remain pending. Existing full
diagnostic/performance builds do not silently substitute for those checks.
VM measurements do not establish bare-metal NUMA isolation. The new kernel
has not replaced the development host's running kernel. Correctness failures
would block dependent work; measured regression is recorded with default-off
status while independent domains continue under the approved scope.
