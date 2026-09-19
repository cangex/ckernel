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
operation on the real node lock.  The operation holds the lock with interrupts
disabled for at most 5ms and records independent timestamps around observation.
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
