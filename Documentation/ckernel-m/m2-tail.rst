M2 tail-latency measurement and record lifecycle diagnostics
==========================================================

Measurement boundaries
----------------------

``maple_pair`` accepts ``CKM_PAIR_SECONDS`` from 1 to 30 (default 1), subject
to its fixed sample capacity. Exhausting the capacity is an explicit failure,
not permission to drop samples. P99 is not meaningful when a long composite
operation yields too few samples. The bystander acknowledges its start before
the controller releases the target; the recorded monotonic-raw start/end times
must prove coverage of the entire target window. Target-only and bystander-only
runs remain necessary. Compare absolute tails and each role's pair/solo change;
a slower solo baseline can make a relative interference ratio appear better.

Guest CPU affinity is not host physical-core affinity. An isolated-VM launcher
must stop the guest before execution, inspect the VM's vCPU thread IDs, pin them
to verified host cores, save the mapping, and only then run the guest. Otherwise
host scheduler placement can confound an apparent kernel regression. No guest
NUMA result substitutes for a bare-metal NUMA experiment.

``CKM_PAIR_LIVE=1`` enables optional supervisor-side inventory queries every
10 ms and 100 ms workload time blocks. Query timestamps and duration are saved.
These runs are diagnostic only: QUERY scans records under an instance lock and
can itself affect tails. Samples are nontransactional; node reservations may
temporarily exist without linked records. Exit snapshots do not describe the
occupancy distribution throughout the operation window.

Record tracepoint
-----------------

The disabled-by-default ``ckernel_m:ckm_maple_record`` tracepoint records an
instance cookie, diagnostic record identity, and before/after states. It adds
no timestamp or ownership field to a Maple node or tracking record. Tracing is
not an object reference and must never be used to infer ownership at free time.

States 0, 1, 2 and 3 mean borrowed, retired, cached and released respectively.
Trace-only transitions 4->0 and 3->5 denote registration and entry to the
record-release callback. State 5 does not mean all release work has completed.
The human-readable identity uses hashed pointer formatting. Treat a missing,
ambiguous or inconsistent identity as an invalid interval, not as zero delay.

Use a common trace clock (for example mono_raw), preserve per-CPU overrun/loss
statistics and the complete registration-to-release stream, and pair records
by instance and identity across CPUs. Repeated retirement notifications do not
restart an already-retired interval. Address reuse starts a new lifecycle only
after the previous terminal event. A partial or dropped stream cannot establish
residence-time conservation.

Retired-to-cached/released elapsed time includes reader exclusion, callback
scheduling and handling; it is not a measurement of the RCU grace period alone.
Released-to-callback-entry measures another distinct deferred interval. Cached
and borrowed residence are separate. Do not sum overlapping inclusive times
or infer a P99 cause from correlation alone.

Enable trace events only in separate diagnostic trials, outside performance
claims. The trace buffers, producer CPU and later dumping have their own costs.
Disabling tracing removes recording but does not establish zero instrumentation
cost. Keep native fallback, memcg/GFP/locality checks, budget lifetimes and RCU
reader protection unchanged.

The diagnostic launcher may also trace RCU softirq entry/exit (vector 9) and
compare those intervals to recorded P99-or-slower operations. Such overlap is
evidence of where the observed delay occurs, not attribution of every callback
to the current task or instance. Entry/exit elapsed time can include nested
interrupts or host-vCPU descheduling. It is not exclusive CPU time, and must not
be blindly added to task or kthread CPU. This is distinct from node residence
while waiting for safe reuse. Preserve both measurements and their limitations.
