Maple allocation bridge evidence, 2026-09-20
==========================================

This closes a bounded X3 observation gap, not all X2--X7 acceptance. No allocator
algorithm, tree layout, ownership, allocation policy or host kernel changed.
The target remains ``codex/ckernel-periodic-profile``.

Frozen source and kernel
------------------------

Kernel: ``4a39c37bb``; runtime tools/fixture: ``32a644d41``. Later readable-report
and coverage edits are not relabelled as the capture source. Full ARM64 Image
and modules built with the unchanged configuration and ran in isolated KVM.

* Image SHA256: ``37d2d0c2e73cdb51cdd5ff095a2f0607301c44c513f4d22e04f41eb44572bdaa``.
* vmlinux SHA256: ``04759717aa1edb8e363c34f318d1df14efc168139f7970a629cb38cc4b2f9fb4``.
* Configuration SHA256: ``678424d65838341018da716b6eb7f4e13d7213e56201ec97744d92708f156a65``.

Independent cases
-----------------

``maple-allocator-boot-20260920/x3-allocator-20260920-040643.log``
has SHA256 ``21cc3ab2672dd112541fd7dd660ac9368e1eefd60a1135225ebd2c55825dbd4f``.
Six frozen OFF/allocator states, three captures, two containerized ordinary VMA
split/merge workloads pass. Each capture contains 122 accepted backend calls,
122 closed Maple contexts and 280 sampled node release entries (bulk calls can
return multiple nodes). Distinct live processes do not share the observed mm
tree addresses. Sampling shift is six; this is not a full event-recall study.

``maple-maple-boot-20260920/x3-maple-20260920-040741.log``
has SHA256 ``d5bc951c0b53068a5143a7a940afaa8e176594a2a40d94cf87c876eee2b9dd9c``.
Six frozen OFF/allocator states, three captures, two independently opened test
contexts pass. The fixture uses native Maple APIs, no injected contention:
populate 32 distinct entries; duplicate into a separate destination; verify
all entries; destroy and drain; reinitialize at the same address and repeat.
Destruction is requested from a different CPU. RCU releases keep the allocation
context and actual task/softirq executor, not an inferred owner.

Each captured fixture round validates 80 backend joins and 126 release entries
per participant. The copying path points to the destination tree, not its
source. The report does not merge the reinitialized address into an assumed
permanent tree identity. Module unload succeeds. A successful fixture operation
is not an independent population denominator for every allocator event; recall
is deliberately not reported.

Unit negatives reject mismatched GFP/cache/count/identity, missing or duplicate
brackets, wrong copy destination, malformed evidence and unknown capture
quality. BPF nesting and second-backend checks invalidate the pending join.
Historical records retain their original contract: 49 pinned prior cohorts
replayed without failure before adding the two new cohorts.

Measured and unmeasured cost
---------------------------

The normal CAPTURING process CPU maxima are 14.245840ms (ordinary VMA) and
13.083260ms (fixture), below the unchanged 40ms guard. CPU through report peaks
at 112.931190ms / 112.049180ms; peak observed combined RSS is 39,100,416 /
35,811,328 bytes. These are separate scopes, not interchangeable measurements.

The VMA cohort invokes about 15,692--15,696 Maple callbacks per measured source
interval, including non-target source work. Measured callback bodies consume
4.838650--4.874680ms; free callback bodies consume 2.624130--2.742630ms. They are
not hidden in the sampler process budget. Entry filtering, timer wrappers,
remaining BPF work, IRQs and asynchronous cleanup are not all covered by these
timers. Boot high-water maxima are not window maxima. RSS plus map accounting
must not be added without correcting their overlap.

Preserved development failures
-----------------------------

The initial transfer closed early; the first build attempt stopped before
source checkout because the bundle was absent. The retry used a new evidence
directory. The initial VM launcher invocation supplied an unsupported 600s
timeout and exited before boot; the existing supported 900s timeout was used
with the same immutable Image/initrd in new cohort directories. Neither failed
attempt is counted as successful runtime evidence or as a favourable rerun.

New-kernel regressions
----------------------

Kernel ``4a39c37bb`` and tools ``862190011`` ran three additional cohorts.
All three prepare logs report 586 Linux unit tests passing. Selective loading
passes 16 cases with 14 sessions and complete scope audits. The crash suite
passes 16 cleanup/recovery cases; killed collectors retain incomplete terminal
audits and failed captures. Cleanup PASS does not turn those captures into
usable evidence or waive the CPU guard.

The four-container joint cohort passes 33 frozen states (three OFF states and
ten collectors over three rounds). Serial SHA256 is
``7787c23e736271dca68adfbbc6d17fd654f9134c3bb28d44d44936a299170d58``.
CAPTURING process CPU peaks at 28.391080ms; CPU through report peaks at
165.632890ms; observed combined RSS peaks at 38,739,968 bytes. Paired per-role
P99 changes range from -581,920ns to +221,330ns. Tail latency remains recorded,
not a passed low-overhead claim. Complete asynchronous/kernel memory cost and
population attribution recall remain unknown. This is PASS_SCOPED, not X7
completion, and quiet collectors do not acquire positive coverage.

Residual scope
--------------

Allocation-bracket identity is not complete tree lifetime or exclusive
container ownership. Allocation does not prove node installation. Native free
entry is not free-backend completion or RCU grace-period timing. Sharing a
cache is not evidence of a common lock. Separate SLUB holder/waiter evidence is
required for supported contention claims. skb backend provenance, block split/
cancel cases, mixed-source truth and complete background/kernel cost remain
in the wider X2--X7 work list.
