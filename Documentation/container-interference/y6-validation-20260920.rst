Y6 selected CPU and background validation, 2026-09-20
===================================================

Status: PASS_SCOPED for the fixed 8-vCPU, 4-GiB ARM64 KVM experiment. Not Y7
cost certification, hardware attribution or a 14-host-kernel deployment.

Frozen source 164ec3105 follows native Image source 50a202e65; the intermediate
changes are tools and documentation only, with native-source equivalence
checked before each VM. Image SHA256 is
8d19768285e08059c36a887116c49e4ad173ecd864143e0409c88fe9b65e228d.
Full Image/modules and C/BPF builds passed. The final preparation passed 748
Python tests plus the existing owner/profile tests on Linux. Enabled native
source inventory is version 20. Final disabled-config rebuild is separately
required before combined Y7 sign-off.

Evidence directory on development host 14:
/dev/shm/cis-x-20260919/evidence/y6-fixture-164ec3105-20260920.
Serial: y6-cpu-20260920-215005.log. Independent replay: replay/replay.json.
All 30 states are retained: five fixed cases, OFF/ON, three alternating rounds.
The collector observes CPUs 0 and 1; the management process is pinned to CPU 7.

Runtime facts
-------------

* Shared CPU: 249/251/249 execution-overlap associations. These are E1 facts,
  not proof of a unique blocking container or all scheduler eligibility.
* Separate CPUs and private target quota: no false cross-CPU associations.
  Throttling is separately confirmed from the affected cgroup's cpu.stat.
* Migration: ten migration-invalidated pending waits per round are retained
  unknown rather than joined across CPUs. PID/start reuse has a negative unit
  regression, including early zero-timestamp kernel workers.
* Background: each ON state includes 80 independently recorded completed
  fixture operations within 134--142 complete observed work executions.
  Requeued executions are separate. CPU slices are observed; work origin is
  deliberately unknown and never taken from the fixture in production output.
* All 15 captures finish COMPLETE with validated producer detachment. No lost
  or rejected events; terminal nested IRQ/softirq aggregate is checked.
  Boundary-partial scheduler/work intervals remain unknown.
* Native sched_stat_wait produced records with schedstats explicitly enabled
  in both modes. These overlap switch-derived waits and are not added to them.
* SPE is UNSUPPORTED in this VM. Ordinary PMU presence is not cache-line
  contention evidence, and no hardware-sharing cause is claimed.

Measured process capture-phase CPU peaks are 6.46--14.15 ms per session;
whole-worker CPU including preparation/drain is 100.96--146.06 ms. Combined
observed process RSS is 32,272,384--39,272,448 bytes. These are scoped costs,
not all native callback, interrupt, background or system memory costs. Y7
must measure the wider target/bystander and system effects separately.

Retained failures and fixes
--------------------------

The first fixture lacked its explicit isolated-VM enable parameter. The next
collector emitted a perf record from every IRQ callback, provoking perf
irq_work notifications and a feedback stream. Protocol 2 now aggregates IRQ
union and counts per CPU without emitting from IRQ callbacks; the unchanged
entry and output budgets still apply. A subsequent analyzer rejected valid
zero birth timestamps. Checked producer reads now distinguish these from
read failures; task identity reuse still fails closed. Finally a nested device
bind was hidden by the container's nonrecursive root bind; only the dedicated
fixture device node is copied into the test root. No runtime dataset from
these failed attempts is relabelled successful or mixed into the final matrix.

Limits: wakeup-to-run intervals, priority/eligibility causality, NMI and guest
steal, complete background submitter lineage and precise total observer CPU
remain outside the accepted relations. Per-CPU union loses per-vector timing
by design. Y6 is manual bounded specialization, not continuous all-CPU tracing.
