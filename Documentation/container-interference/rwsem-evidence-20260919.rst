Rwsem selected-object runtime evidence, 2026-09-19
================================================

Scope and frozen sources
------------------------

Kernel 99d53547065a4fb62a132ed17acaaebbe77ab785 and tools
a3733b6fc502d58e5ffefb4a25c5879185ad5bd0 were used in a dedicated
eight-vCPU ARM64 KVM, not on the host kernel. Four registered container
roots supplied two targets and two identity-only participants. Each
session selected the fixture's two actual addresses before arming;
addresses alone did not certify ownership or object generation.

The repaired full Image and modules built successfully. Image SHA256 is
af526b4faad7e366cc41cb8b1c3e4d2d5599242394d95c7e8b5f8af9307e31f2.
The read-only BTF ELF SHA256 is
a218c8d089ac378ff726749815bb7c4d27352ffa58653c5e1c3ad4985ef8d3b7.
Both input hashes were rechecked after guest preparation and execution.

Independent results
-------------------

``rwsem-window-20260919`` contains ten cases, three fixed alternating
OFF/ON rounds: 60 states and 30 captures. The cases are writer/reader,
writer/writer, multiple readers/writer, private objects, failed trylock,
interruptible abort, non-owner use, pre-window ownership, valid address
reuse, and writer downgrade. Native ioctl timing brackets independently
define the eligible overlaps; they are not generated from observer events.

The independent checker accepted all 60 states. All 24 predeclared
eligible relations were captured. No wrong container, wrong holder,
cross-initialization join, or unsupported E2 in the negative cases was
accepted. Native held intervals include explicit sleeping, not continuous
on-CPU spinning. This does not prove involuntary preemption attribution
or a complete kernel-wide reader census.

Maximum combined-process CAPTURING CPU was 11.23275ms, below the unchanged
40ms guard. Maximum combined RSS was 37474304 bytes. These are process
budget measurements, not total observer CPU or complete kernel memory.
No tail-latency production acceptance is claimed.

Serial SHA256:
a7f66df73b89ff6513bb5b424a9fd1d5b73038cfdc7712e00a132fcd43f994f7.

``rwsem-overflow-window-20260919`` separately ran ten observed readers
against the eight-reader analysis limit, three alternating OFF/ON rounds:
six states and three captures. All three captures observed actual reader
overflow and retained E1/unknown rather than inventing a complete set or
an E2 holder. Maximum combined CAPTURING CPU was 9.05988ms and combined
RSS was 34709504 bytes. Empty negative captures are rejected, not passes.

Overflow serial SHA256:
b0106b2969fc4b3af0658d397ffdc39f2343ca8925c8dec14450a1180b158c78.

Failed development evidence retained
-----------------------------------

Earlier cohorts remain immutable. Source compilation exposed duplicate
tracepoint definitions; tool builds exposed unmatched program/mask tables
and a Make implicit link of the external BTF input. Fixes add compile-time
and isolated input-preservation tests. The kernel Image, modules and BTF
were rebuilt and refrozen, not substituted silently into old evidence.

The first broad rwsem watch collected unrelated startup paths and failed
loss/capacity guards. It was replaced with explicit bounded selection,
not a larger budget. Another fixture reset locks after receiving the
CAPTURING receipt but before its future start timestamp; its empty result
failed independent recall. The fixture now waits until the actual window
and the oracle rejects early operation/reset timestamps. Non-owner,
pre-window and overflow negatives require actual corresponding records.

Remaining boundaries
--------------------

This is PASS_SCOPED for the public non-RT API, selected objects and these
frozen cohorts. Static/pre-window objects remain E1 without an observed
initialization. Address selection is manual and administrator-only;
arbitrary-lock automatic discovery and generation are not solved by it.
Source callbacks still execute before BPF filtering, so high-rate entry
cost remains relevant. Fresh control/fault and joint workloads must be
revalidated on this kernel; the earlier X7 joint cohort used an older
kernel. Mandatory X2-X5 gaps remain and X7 is not complete.
