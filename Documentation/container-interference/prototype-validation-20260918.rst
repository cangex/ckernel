Functional prototype evidence, 2026-09-18
=======================================

Status
------

The disposable-VM manual explanation prototype is operational. This is not
completion of every item in the six-step plan, production P1 acceptance,
or a host deployment. Automatic specialist routing remains disabled. The
user's P99 relaxation changes the functional experiment admission only;
identity, CPU, storage, terminal quality and cleanup gates remain active.

The fixed kernel Image SHA256 is
``4f11956a64c706d378fc2b0730f59d3f08efa4fec8430173282f0fe38a21d625``.
It uses the existing quiescence kernel at source
``fe4afbc314b4b01090e6dadddbbea7e5f99b7087``. New production kernel algorithms
were not introduced. The guest is ARM64 KVM, eight vCPUs, four GiB, 4K pages.
All workloads use container namespaces and registered cgroup v2 roots.
These results are not bare-metal NUMA results.

Evidence cohorts
----------------

All archives and raw object addresses are administrator-local, not committed
to this repository. The cohorts below have different userspace sources and
must not be combined into one performance sample.

* ``prototype-functional-20260918-2``, source ``2307c8c66``: five owner
  scenarios and six actual 60-second periodic slots, all eleven sessions
  finalized with quality PASS and resource removal. Both container workloads
  remained active throughout the six slots; each IP window had approximately
  172--175 samples per root. Archive SHA256:
  ``d58189fa1b9b22dd410135d48cae4d76f2cf59c138d6e03735ccb72643e4df37``.
* ``prototype-integrated-20260918-5``, source ``4346051dc``, specialists
  transcript ``p1-smoke-20260918-112325.log``: six PASS sessions. Shared-CPU,
  separate-CPU and idle cases yielded 429, 44 and zero scheduler intervals.
  Separate CPUs are not a guarantee of zero scheduling wait. The bounded
  memory.high case yielded 34 memcg reclaim intervals; its control yielded
  zero. The quota case reported a throttling counter, not a lock owner.
  Archive SHA256:
  ``bb9366e1ba34f6753db808a3c21498f1f126c67a57051bbd397d656fa1e66f51``.
* ``prototype-bridgecost-20260918-6``, source ``75d02bc62``: five bridge
  sessions and 24 cost sessions, all finalized with quality PASS. Archive
  SHA256:
  ``b2e82f3221b7a798f6dcd887030d544913742f06312292e8d97f6f72f7d4e115``.
  The generic runner label ``p1-smoke`` is not a P1 acceptance result.

Known truth and limits
---------------------

The shared, private, address-reuse, preempted-holder and registered
non-target-holder mutex cases yielded 397, 0, 383, 77 and 395 closed
holder/waiter edges. Independent fixture intervals found zero wrong-holder
intersections, zero wrong-waiter intersections and zero cross-reset edges.
The preempted-holder case contained 77 observed holder off-CPU pieces.
These are bounded-fixture consistency results, not full-kernel recall or
business-throughput causal attribution. Total fixture operations are not
the denominator for eligible contended acquisitions.

The shared dentry fixture yielded 15 closed lockref relationships. It uses
a scoped, controlled delay in actual dget/dput/lockref paths. Its private
dentry control yielded no relationship. The shared case retained 24
unknown-identity observations, two unclosed intervals and one bounded-prefix
indicator; these did not become invented edges. This bridge does not supply
an independent per-acquisition truth denominator for all lockref operations.

Unmodified open/stat/close workloads, using shared versus private files,
both yielded no closed relationship in this window. This is NOT evidence
of no interference and is not an HTTPD root-cause result. An unregistered
mutex holder produced unknown identity observations rather than a named
container or a false complete relationship.

Costs, recorded but not certified
--------------------------------

The final cost cohort freezes three pairs and alternating mode order for
OFF, IP, owner, scheduler and reclaim profiles. Target/observer roles rotate.
OFF means an idle controller with no active probes, not absent-CIS. Each
four-second workload encloses a two-second profile. These whole-workload
measurements are not exact-window or steady-state overhead certification.

Mean throughput degradation percentages (negative means an observed increase),
target / observer respectively:

* IP: -0.160 / +0.123.
* Owner: +0.800 / +0.811.
* Scheduler: -0.385 / -0.153.
* Reclaim: -0.885 / -0.442.

Mean open-loop P99 changes, target / observer respectively:

* IP: +2.402 / +2.369 percent.
* Owner: +0.745 / +0.671 percent.
* Scheduler: +3.417 / +1.127 percent.
* Reclaim: -4.102 / -5.563 percent.

All cost comparisons remain RECORD_ONLY. Three-pair t intervals are wide;
no result proves a production one-percent throughput bound. For example,
target IP throughput has interval [-2.425, +2.105] percent and target owner
has [-1.880, +3.480] percent. Open-loop runs recorded zero timeouts.

Known controller/worker process CPU totals range from 88.93 to 139.69 ms per
session, including setup/drain; sampled combined RSS ranges from 26.94 to
31.90 MiB. Probe execution, PMU interrupt cost, all background work and
all kernel memory are not fully accounted. These numbers cannot certify a
total CPU bound or total memory below 64 MiB.

In the final bridge and cost cohorts, same-boot explanation completion lag
after capture end ranged from 35.29 to 415.28 ms. This is NOT anomaly
detection delay: the 60-second schedule and unobserved gaps dominate service
delay. Earlier cohorts did not record this metric and are not backfilled
using an offline machine's clock.

Failures retained
-----------------

The initial guest model check failed because the fixed kernel did not export
OF sysfs. A bounded read-only boot-log fallback was added, without clearing
the log or relaxing the required model. The first pressure test timed out
draining its workload while memory.high remained active; pressure is now
released only after the capture window. A manual quota session lacked survey
boundaries; prototype manual sessions now preserve them.

The first dentry bridge failed because its fixture switch was disabled.
A privileged fixture-only switch scopes its delay callback between source
barriers. No permanent callback bypasses cleanup verification. An earlier
cost cohort hit the 40 ms CAPTURING process budget at 40.427 ms. The session
was cancelled and objects were removed. Test-driver status polling changed
from 20 to 100 ms; no probe budget or coverage threshold was raised. A new
entire frozen cohort was run; the old failure was not dropped or renamed.

Remaining work
--------------

* Automatic specialist queue, cooldown/fairness runtime matrix and complete
  pause/resume/restart fault integration are not validated here. Existing
  unit tests do not substitute for those runtime scenarios.
* Direct reclaim capture is implemented, but this cohort validates a
  positive memcg reclaim case, not global direct reclaim under pressure.
* Async workqueue is not sessionized into this prototype. Generic spinlocks,
  FD table locks, rwsems, atomics, SLUB, TCP, block I/O, cacheline/NUMA hardware
  contention and arbitrary background ownership remain unsupported.
* Scheduler events have no waiting-task stack or identified aggressor.
  Reclaim identifies the executing victim, not the pressure producer.
* Generic tracepoint/BPF entry recursion loss is not proved by custom-owner
  recursion counters. Total resource costs remain incomplete.
* No HTTPD bridge, 48-active-container matrix, production P1, host kernel
  deployment or automatic mitigation was attempted in this prototype.

Reproduction
------------

See ``prototype.rst`` for operator commands and admission boundaries.
``prepare_periodic_guest.sh`` compiles tools and packages the task-owned guest;
``prototype_vm.py`` selects the default, ``--specialists``, ``--bridge`` or
``--costs`` frozen protocol, one per new disposable VM. Never run its init
script on a host. ``prototype_check.py SERIAL.log NEW_OUTPUT_DIRECTORY``
extracts reports, checks protocol completeness, retains unknown evidence and
computes exploratory paired costs. The output directory must not exist.
Analysis module hashes are separate from capture source hashes.
