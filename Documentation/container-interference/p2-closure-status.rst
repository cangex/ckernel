Periodic profiling closure status (2026-09-18)
============================================

P2 is NOT accepted. No generated P1 PASS receipt exists and automatic periodic
positive/cost runs remain disabled. The experimental WAIT gate is boot opt-in,
not a production default. Dedicated ARM64 KVM evidence is not host NUMA proof.

Implemented corrections
----------------------

* Terminal BPF quality is independent of cleanup and the COMPLETE label.
  Owner sessions additionally audit quiescent producer recursion counters;
  the last source skip can otherwise escape the last emitted BPF counter.
  The v3 source snapshot explicitly synchronizes unregistered tracepoint
  callbacks before terminal BPF counters are consumed. Raw tracepoint link
  release alone does not establish that barrier on this OLK baseline.
  Synchronization is outside the hook but has a lifecycle cost to measure.
* A bounded VM-only recursion diagnostic localized one reproduction to an
  interrupt-context dentry retirement. All four retained examples in that
  reproduction were absent from emitted watched-object records. This does
  not retrospectively explain every older gap or excuse future source skips.
* The optional monotone WAIT bitmap rejects never-waited objects before BPF
  entry without using current's container as an owner filter.
* Owner identity roots and diagnostic targets are distinct: up to 256 pinned
  identities, at most two active targets. A registered non-target holder is
  preserved; unknown holders are not fabricated. IP stays target-only.
* Fixture-induced tracepoint registration is opt-in. Ordinary idle/IP tests
  no longer inherit a dentry-delay callback merely by loading the fixture.
* Admission cancellation is not published complete before durable cleanup
  releases the admission slot. Cancellation responses remain bounded.
* Raw-evidence admission binds source hashes, Image notes and boot flags.
  An all-PASS summary or a gate-off result cannot approve gate-on operation.
* Boundary failure injection and post-window request timelines are available.
  Eight injected allocation/attach boundary failures are not exhaustive
  allocator fault coverage. Timeline export is a diagnostic, not a cost run.

Outstanding work packages
-------------------------

W0 has quality and version gates, but some runtime evidence readers and the
window-tail contract remain incomplete. Missing evidence stays BLOCKED.

W1 has source-gap diagnosis, a prefilter and non-target identity regression.
Remaining budget aborts are retained as PARTIAL, even with zero lost events.
The gate's host-shared bitmap, collisions and saturation retain entry cost;
this is not a claim of comprehensive low-cost owner coverage.

W2 has explicit rollback tests and a nonadditive per-session resource ledger.
The ledger does not prove a 64 MiB complete upper bound: JIT/BTF/verifier
transients, allocation metadata, deferred frees and asynchronous kernel CPU
still need accountable bounds. RSS, fdinfo memlock and shared mappings must
not be added as disjoint quantities. Post-publication tail cost is missing.

W3 has fixed n=5 cost measurements, with all rounds retained. The batch using
worker source 671a10872 passed IP capture quality and IP throughput bounds.
Owner throughput upper95 was 3.307% for the target and 2.998% for the bystander
(means 2.372% and 2.025%). The target therefore did not establish the 3% bound.
IDLE P99 upper95 was 43.673%/45.025%; these are uncertain upper bounds, not
deterministic slowdowns. Do not attribute unexplained tails to hardware.
These are pre-boot-identity-binding measurements, not final-source admission.
The subsequent quiescence barrier also invalidates transfer of those costs.

W4 and W5 remain BLOCKED on real P1 acceptance. Neither duty-cycle arithmetic
nor hand-written PASS receipts can substitute for periodic functional/cost
evidence. Do not start or report them as passed on the strength of unit tests.

Final functional validation
---------------------------

Runtime source fe4afbc314b4b01090e6dadddbbea7e5f99b7087 built an ARM64 Image
and modules, SHA256:
4f11956a64c706d378fc2b0730f59d3f08efa4fec8430173282f0fe38a21d625.

The dedicated 8-vCPU/4-GiB KVM ran with the WAIT gate enabled. Session tests,
eight boundary rollback injections, cancellation, identity and storage tests
passed. The non-target-holder regression preserved 200 E2 associations; this
does not establish E3 causality or universal recall. Mutex and real dentry
truth cases passed, including private objects, address reuse, interrupted
waits and a preempted holder. The periodic test was rejection without a valid
P1 receipt, not a positive schedule or periodic-cost run.

The functional batch sampled combined process RSS at 37.60 MiB. This is not a
total or transient peak bound and cannot approve the 64-MiB contract. No new
formal cost batch was run after the quiescence fix. All earlier failures and
fixed-batch costs remain historical evidence, including safe budget aborts.

Failure classes retained
------------------------

* Source recursion, lost/rejected events: incomplete sampling, not safe PASS.
* Entry or combined CPU limit: valid safety stop, not a complete window.
* Cleanup/identity/control failure: session failure, not a performance result.
* Confidence interval crossing a bound: undetermined, not negligible cost.
* Missing kernel/background/memory bounds: missing measurement, not zero.
* Changed source/boot configuration: historical evidence, not transferable.

Raw records, failed runs and kernel-address material stay in administrator-only
evidence directories outside this source repository. Original host kernel,
other users' workloads, old evidence and unrelated branches are unchanged.
