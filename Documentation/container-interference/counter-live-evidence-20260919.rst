Selected ancestor aggregation evidence, 2026-09-19
=================================================

The ``counter-live-fix1-20260919`` cohort used kernel
99d53547065a4fb62a132ed17acaaebbe77ab785 and tools 6096fba47. The full
source and tree IDs are in the cohort manifest. The isolated ARM64 KVM
Image SHA256 is
af526b4faad7e366cc41cb8b1c3e4d2d5599242394d95c7e8b5f8af9307e31f2.

Eight fixture cases each ran three fixed captures: same leaf, common
ancestor with different leaves, private counters, limit failure/rollback,
different call frequency, CPU migration, valid address reinitialization,
and private counters sharing a CPU. Selection was frozen from eight actual
addresses in preflight native fixture calls before capture. The fixture
uses source shift zero; normal sampled production counts are not inferred.

Independent replay accepted 24 captures. The live per-CPU counts,
quantities, depths, time boundaries and entry-to-step histograms matched
the raw sampled stream in every capture. All 1392 predeclared eligible
native fixture calls were matched. The complete report contains 1633
sampled calls including nonfixture native work; they must not be relabeled
as eligible fixture truth. There were 78 accepted shared object/stage
relations across the positive cases. Private objects and generation reuse
did not invent shared counter relations.

Maximum combined-process CAPTURING CPU was 11.06049ms. Maximum combined
RSS was 38985728 bytes. The unchanged guard is 40ms; these results do not
certify total business-context probe CPU, asynchronous kernel memory or
production tail latency. No cache-line contention cause or lock holder
is inferred from common updates.

Raw serial SHA256:
66271a29be0869ecd44ab763708665db9ecf5d0c8e7170fadd71b3db326ecaab.
Replay with ``counter_vm_check.py`` on
``x2-counter-20260919-105636.log`` and a fresh output directory.

The earlier ``counter-live-20260919`` is retained as a failed development
cohort. Native compilation passed, but the BPF verifier rejected a
variable stage-index access. Replacing the access with seven compile-time
constant slots made the bounded access provable; no verifier protection
or event semantics were relaxed. Historical pre-aggregation captures
remain readable only with their exact old collector-contract digest.
Live admission still requires the current map inventory.

High-event-rate behavior, full-population selected-source counting and
hardware contention proof remain outside this scoped pass. The X7 joint
allocator recursion gap and other required X3-X5 coverage are unresolved.
