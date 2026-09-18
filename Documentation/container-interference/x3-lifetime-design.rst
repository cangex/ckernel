X3 bounded allocation-instance and release-entry correlation
============================================================

Scope
-----

This is a selected-cache prototype, not a general object ownership database.
The native SLUB algorithms, memcg accounting, KASAN quarantine and RCU reuse
rules are unchanged.  CONFIG_CIS_OBSERVE_ALLOC remains default-off.  Allocation
sampling stays per CPU with the frozen shift; only the exact boot-selected
cache is eligible.  The short allocator collector enables both allocation
stages and release-entry events.  All other collectors leave these static
tracepoints disabled.  Source-switch ABI 4 reports both keys independently.

Allocation identity
-------------------

For a selected single allocation, the successful return stage provides the
object address.  For a selected bulk allocation, each observed item provides
an address before post-allocation hooks; the complete call must subsequently
prove success or prefix rollback.  The report rejects incomplete calls and
never counts a rolled-back item as a successful business allocation.

A preallocated, bounded BPF hash (1024 entries) retains the requesting
container ID and generation, task ID and start time, cache and object
addresses, allocation-call timestamp and item ordinal.  The report qualifies
these observed lifetimes with boot and capture IDs.  This is an observed
allocation-instance identity, not a persistent generation in the object and
not a claim about Maple tree ownership or the memcg charged for the object.

Release observation
-------------------

The new hook is at entry to slab_free(), before memcg release, quarantine
handling and publication to native free lists.  It covers that function's
single and bulk callers.  The object pointer array is inspected while the
native caller still owns the objects; no released object contents are read.
The source visits at most 64 objects per detached free batch.  A larger batch,
recursive selected-cache observation or unsupported NMI increments the
producer gap count and prevents lifetime certification for the capture.
Ignoring a release could otherwise incorrectly join an address reuse to its
previous allocation.  The gap is not silently treated as zero frees.

Only entries present in the allocation watch map are exported.  Their identity
is removed before returning to the allocator.  Replacing an already watched
address without a matching release is a quality failure, not a new owner
guess.  The map is neither LRU-evicted nor retained across sessions.  Capacity
failure rejects the capture; an incomplete end-of-window lifetime remains
open and is not converted into a zero-age object.

The release executor is recorded separately.  Process-context execution may
have another registered container or an unknown host identity.  Softirq and
hardirq execution record their context and CPU without assigning the
interrupted task as owner.  The allocation requester is retained unchanged.
An RCU callback reaching slab_free() can therefore be related to an observed
allocation, but this does not reveal when the grace period started or ended.

The timestamp denotes release entry, not backend completion or the instant
at which quarantine permits reuse.  Observed object age is not allocator
service time, contention delay or a blocked-container relationship.

Budget and evidence
-------------------

The native source adds three per-CPU audit counters (24 bytes per possible
CPU on this ARM64 build), no per-object native metadata, no central owner
lock, no extra allocation and no sleep in the observation hook.  Source entry
and BPF hash lookup cost still exist for selected-cache frees not exported.
The BPF map's runtime memory inventory and unknown allocator overhead must be
reported, not replaced with the value-payload estimate.

The allocator's per-CPU event buffers can now use the existing 4 MiB global
payload ceiling: at eight possible CPUs, 128 pages each instead of 16.  The
overall RSS and output caps are unchanged.  This follows a preserved failed
VMA capture that lost three records; it is not permission to accept loss.
The same-kernel ordinary VMA bridge subsequently completed all six OFF/ON
states with zero-loss accepted captures using the pre-release collector.

The disposable external fixture exports actual returned object addresses and
callback timestamps independent of the observer.  Fixed cases include cold
and warm allocation, bulk allocation, a different private cache, cross-CPU
release and RCU-deferred release.  It is not loaded on the host.  Fixture
module taint is expected and distinguished from an Oops or kernel warning.
Native runtime evidence for the new release collector is still required;
unit tests, code existence and successful compilation do not complete X3.

Runtime follow-up: stack collision and identity are distinct
-----------------------------------------------------------

The context-separated release build a63f83cc2 completed the 36-state fixture
but the ordinary VMA bridge stopped on release parser validation. Its first
capture recorded zero source gaps and zero perf loss; 43 softirq release
records had ``bpf_get_stackid`` return -EEXIST (-17), not corrupt identity.
The prior parser accepted only -1 and incorrectly called these schema errors.
The failed cohort remains preserved; it is not rewritten as a successful run.

Release correlation now validates the errno range, reports each missing stack
and retains the independently joined allocation/release-entry identity and
caller address. It NEVER substitutes a colliding stack or claims full-stack
coverage for that event. The status explicitly applies to object identity;
release-stack availability and error histogram are separate. Allocation-side
complete-call requirements, dropped-event rejection and ownership validation
are unchanged. Allocator/network stack maps use 2048 fixed slots (1 MiB value
payload at depth 64), rather than 256; this reduces but cannot eliminate hash
collisions. Export reads the actual bounded map capacity. Runtime cost and
coverage of this revision still need fresh verification.

Fresh lifetime cohort
---------------------

Evidence ``/root/cis-20260916-232524/evidence/x34-backlog-lifetime-20260919``
uses the a63f83cc2 kernel and 1298aa7bb tools. Serial logs
``x3-allocator-20260919-024821.log`` and ``x3-fixture-20260919-024911.log``
passed independent six-state ordinary VMA and 36-state fixture verification.
The three ordinary captures joined 840 sampled release entries; the 18 fixture
captures joined 744. All reported program recursion misses were zero, and no
release stack capture errors occurred in this new cohort. Historical failures
are unchanged. The latest source-only same-release nested guard is NOT part of
this kernel build; kernel and tool source hashes are separately recorded.

Peak observer-process CAPTURING CPU: ordinary 15.61661 ms, fixture 13.99556 ms.
Peak combined observer RSS: 32,632,832 and 38,088,704 bytes, respectively.
These remain engineering counters, not total native source/background cost,
production acceptance, complete allocator lock ownership, or arbitrary
pressure/failure/cpuset coverage. X3 broader scope remains explicitly open.
