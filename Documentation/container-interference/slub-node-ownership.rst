SLUB node-lock ownership prototype
=================================

Scope
-----

``slub`` (profile 12) is a separate bounded collector, not an extension that
silently enables global mutex or allocation-stage sampling.  The source emits
native ``kmem_cache_node->list_lock`` attempt/acquire/release boundaries for the
exact boot-selected ``cis_observe.alloc_cache``.  Native node initialization and
retirement clear observation epochs.  All node lock call sites in this OLK SLUB
implementation use the adapter, including allocation, free, partial lists,
shrink, validation and sysfs statistics.  It does not cover slab bit locks,
CPU-local locks, the global slab_mutex or arbitrary allocator contention.

An attempt begins before the lock instruction.  The acquire event is after
acquisition and release-begin before unlock.  Their overlap identifies an
observed inner hold against another task's acquisition attempt, not pure spin
cycles, the whole wait, or independently established causal delay.  An object
address and a shared cache name alone never establish a holder relationship.
Cache identity uses a full 64-bit event field, not the 32-bit flags field.

Identity and bounds
-------------------

Registered target attempts open at most 64 object watches.  Each watches a
prefix of 64 source events; unfinished tails remain unknown.  Other registered
containers can be holders without being targets.  Reset/retire end the watch,
and unknown identities, recursion/IRQ gaps, inconsistent cache identity and
loss prevent promotion of incomplete evidence.  Scheduling records do not
carry cache identity.  Non-RT spinlock ownership is not normally preemptible;
guest scheduling events do not establish host vCPU steal time.

The source performs an enabled check before its cache-name filter.  Enabling
this collector therefore has entry/filter costs beyond emitted events.  The
third membership bitmap consumes another 8KiB of static memory when CIS is
configured.  Per-CPU diagnostic records also expand with the resource enum.
Neither bounded output nor process CPU alone certifies total observer cost.

Validation status
-----------------

``CONFIG_CIS_SLUB_TEST`` defaults off and must only be enabled in a dedicated
disposable VM.  It exports a privileged, explicitly named fixture-cache test
operation on the real node lock.  Its requested busy-hold budget is at most 5ms,
with interrupts disabled, and it records independent timestamps around observation.
This is not a hard wall-time ceiling: callbacks and VM descheduling can extend
the measured interval.  The test is unsuitable for a production kernel.
The fixture never changes list contents or the allocation algorithm and does
not insert delays into production paths.  Controlled contention is not a claim
about how frequently production containers contend on this lock.

``slub_vm.py`` freezes three alternating OFF/ON rounds of shared, private-node,
holder-switch, cache-recreation, unobserved-acquire and ordinary alloc/free/shrink
cases.  The new-object positive first opens a target watch; a separate negative
starts a non-target holder before that watch and must keep it unknown.  The
ordinary native bridge has no independently timed holder oracle, and thus
receives no holder-recall credit.  Actual repeated addresses are reported, not
assumed after recreation.  ``slub_vm_check.py`` independently joins container
identity, object, cache, timestamps and raw observer events.  It requires no
wrong holder and at least 90% of predeclared eligible controlled overlaps.

Implementation and local tests are not runtime or performance acceptance.
Build/runtime receipts, failed cohorts and remaining coverage belong with the
external evidence index; X7 must not be marked complete from this adapter alone.

Recorded scoped validation
--------------------------

Kernel ``ca2cfff3d`` completed ARM64 Image and modules builds.  The Image SHA256
is ``99425518827e5ee6b5153938599093fb0e9822282e41c26de9ec7962243baba9``.
The disposable-VM tools cohort ``e4d71de7a`` completed 36 states/18 captures.
Its serial SHA256 is
``f8ddf5422fe596d1caf7a480a7feaf94963a916a640a8943f1549045047701da``.
The independent checker found 15/15 eligible positive relations with full
observed acquisition intervals, three private-node negatives with no edges,
and actual cache/node address reuse in each of three recreation rounds.
Retirement and distinct observation epochs were required, not just timestamps.

There were also three independently known overlaps whose non-target holder
acquired before a target watch existed.  All three correctly remained unknown.
Thus 15/15 is scoped positive recall, NOT complete recall of the 18 known
overlaps in the combined corpus.  The original unprimed recreation cohort
failed its positive recall test in all three rounds and is retained unchanged
under ``slub-owner-runtime-20260920``.  The second cohort explicitly separates
new-watch positives from missing-acquisition negatives; it does not recover
unobserved acquisition history.

Ordinary allocation/free/shrink records contain ``__kmem_cache_do_shrink``,
``__put_partials`` and ``deactivate_slab`` paths, not the controlled lock helper.
No cross-container holder edge was observed in those bridge windows.  Worker
execution is not relabelled as the originating container.

Maximum combined controller/worker CAPTURING CPU was 11.74818ms, below the
unchanged 40ms gate; maximum combined RSS was 39,178,240 bytes.  These are
process-boundary costs, not total source callback CPU or total kernel memory.
New-source control validation completed 16 checks/14 captures with source
switches and cleanup verified (serial SHA256
``3e2cb5e5aee500cecefd7a503e25603baaa70a303fcdfdaf36dcca8b71db0f60``).
No host kernel was changed.  X7 remains incomplete.

The initial eleven-collector ordinary joint plan requested 33 captures and was
rejected at the existing 32-session prototype-permit limit.  Its unfinished
batch is retained under ``slub-joint-runtime-20260920``; it is not accepted as
a completed matrix.  Joint plan v3 uses separate, freshly booted common
(30 captures) and SLUB (3 captures) cohorts with their own fixed OFF/ON pairs.
It does not raise the permit limit, renew a running permit automatically, or
reuse successful pieces of the failed batch to claim completion.

Interrupt boundaries
--------------------

The first ordinary SLUB joint cohort (Image above, tools ``c20eb001a``) was
rejected in all three captures: the source counted unsupported interrupt
contexts as recursion loss.  Its 36,000 ordinary operations completed without
timeouts, but this is NOT a complete observation result.  Preserve serial
``5cdd91d551cc6dfc4930eb89a70ad1f5aecd06bdd09721621eefad08b120e2e8``.

The updated source emits an explicit object ESCAPE barrier for hardirq or
active softirq operations instead of attributing them to interrupted current.
The BPF event clears actor/task identity and open ownership, while keeping the
same bounded-prefix counter: repeated interrupts cannot reopen unlimited
prefixes.  Offline joins cannot bridge the barrier.  Synchronous intervals
whose acquisition and release are both observed can still be interpreted on
either side.  NMI/reentrant loss still fails closed.  Disabling bottom halves
in task context alone is not labelled interrupt execution.

This changes the representation of observed unsupported context, not a loss
threshold.  It does not identify an IRQ's business owner or certify complete
asynchronous coverage.

IRQ-exit reentry closure
-----------------------

Kernel ``039f34f5c`` and the first IRQ-barrier BPF program were not sufficient.
The OLK verifier rejected a compiler-generated ``ctx+32`` alias; tools
``9e8bc500b`` first copy metadata into volatile scalars and preserve the unknown
actor even if a barrier becomes the prefix-ending record.  The failed ordinary
and fixture logs remain separate; neither reached an accepted capture.

The ordinary workload then passed two captures but rejected the third with
four actual recursion events.  A separate diagnostic boot reproduced four
softirq events on the same node inside an outer WAIT callback (kind 4, phase 2,
preempt count 0x107/0x108).  This is not an irrelevant drop to be excused.
Serials ``83b718547b85a02b1ffec5d41bca822ded4a0ab8b71433325060aca7abd4515e``
and ``2b774f3891ec076c3e3d4bd44160fdc74b3e9265585a136a4d43340857bd0c60``
are retained with FAIL status.

Kernel ``06c07b5de`` protects only the SLUB observation callback with local
IRQ save/restore.  It does not hold IRQs off across the subsequent native lock
attempt or extend protection across the native lock hold.  Existing IRQ state
is restored.  NMI and actual synchronous recursion remain fail-closed.  This
guard can delay local interrupt handling and is an explicit observer cost.
When the dedicated debug option is enabled, per-CPU callback-body time and
boot high-water duration are exported, with another 24 bytes per possible CPU
in the diagnostic structure.  These debug times exclude entry, accounting
updates and restore; they are NOT hard IRQ-off or scheduler-latency bounds.

The ARM64 Image and modules build passed.  Frozen Image SHA256:
``699b82175d47344d59f61bc7e239561ba8bb2bde4f94350bee26c9b17f01cdb6``.
Tools ``2d5dd8b1e`` ran separate debug and normal cohorts, each with three
SLUB captures and three OFF states.  The debug cohort has zero recursion
deltas; per-state callback-body totals were 3.30107, 3.18902 and 3.49654ms,
with observed boot maximum 13.83us.  Its manifest marks performance ineligible.
Debug serial: ``7e523287c39ca951f7d0b546fad116f94511907525bb5cbcc53a305090b14089``.

Normal serial ``ca3011e715dd6e3a1799ba00a36a78f6b8f23439e6c5edbbe9a9b2043aae1be8``
passed all three captures, exact collector scope, source-off and cleanup checks.
The four ordinary container workers completed 36,000 operations with no errors
or timeouts.  Maximum combined-process CAPTURING CPU was 11.57826ms, below the
unchanged 40ms gate, and RSS was 33,660,928 bytes.  This is not full observer
CPU/memory or tail-latency certification; ordinary quiet node locks receive
no synthetic positive ownership credit.

The fresh controlled fixture cohort on the guarded kernel completed all
36 states/18 captures: 15/15 fully observable positive relations, private-node
negatives, holder switches, and actual same-address retirement/recreation in
three rounds.  Three known overlaps with an unobserved acquisition correctly
remain unknown.  Its maximum CAPTURING CPU is 11.84978ms and RSS 38,813,696 bytes.
Serial: ``5464b29147d9b48cc9333f3036cfb2639b7262e4fde6188a5878de9372c72507``.
This remains scoped node-lock validation, not completion of X3 or X7.

Unified ownership explanations now require the same collector inventory and
terminal-scope audit as specialist reports.  Missing scope cannot default to
PASS, and stale or wrong-resource inventory cannot produce an E2 edge.  This
strengthens offline verification without changing or deleting raw cohorts.
