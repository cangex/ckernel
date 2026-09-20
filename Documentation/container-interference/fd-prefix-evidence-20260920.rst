FD prefix-128 and complete relation audit: scoped VM receipt
==========================================================

Sources and scope
-----------------

Producer commit 333fb8ea895899e743966bff46a0009228a49eb4 changed only BPF/tools,
tests and documentation. Kernel source remains 5c2bf8603b60c963d6a56cb0123a9403c9d87e69.
The ARM64 Image SHA256 is
f33288dea75f1f3dac43a9605dd2350ff083485aa725fa77fe4d58863ebbe969.
The fixture built with KCFLAGS=-Werror. No host kernel, workload, operation
count, source-entry threshold, process CPU guard, output or map budget changed.
The remote prefix producer suite passed 649 tests; the later offline verifier
has additional tests, recorded independently rather than retroactively
described as the producer version.

The fixed order was basic, lifecycle, guard, control, fault and crashes, with
no retry. Evidence root on host14 is
``/dev/shm/cis-x-20260919/evidence/fd-prefix-128-333fb8ea8-20260920``.
The local read-only copy is ``fd-prefix-128-evidence-20260920`` under the
container-interference handover directory. A new analyzer independently
recomputed every receipt from raw serial; a runner PASS alone is insufficient.

Complete calls and validated relationships
-----------------------------------------

All fixture calls remain in the denominator, including observations beyond a
source prefix. Results below hold in each of the three predeclared rounds::

  case                     prefix-64 complete    prefix-128 complete   edges checked
  shared threads           42 / 64              64 / 64               62 / 62
  private tables           32 / 32              32 / 32                0 / 0
  cross-container sharing  21 / 32              32 / 32               31 / 31
  retirement/address reuse 150 / 256             256 / 256             248 / 248

Six address-retirement/reuse boundaries were independently verified per reuse
round; no cross-lifetime, wrong-process or wrong-container edge passed. Zero
private-table edges is a negative result, not evidence that no private table
can ever contend internally. Native open/dup/close still has no independent
full-call or blocking-edge denominator; its prefix markers remain visible.

The display summary still retains at most 128 findings. Reuse generates 248
edges, so the earlier summary-only checker verified only the first 128. The
corrected fixture audit uses an explicitly bounded offline limit of 4096 and
fails if any findings remain omitted. It checks all 248 against independent
brackets, including the 120 not in the display summary. Production display,
source collection and live limits do not increase. Test mutations after the
128th relation must fail, and legacy prefix-64 data remains replayable.

Complete-call coverage is not independently measured true spin/blocking
recall. These relations mean acquisition attempts overlap observed ownership;
they can include pre-lock scheduling and instrumentation. No E3 or full-kernel
recall claim follows. The old partial-call evidence is preserved, not rewritten.

Protection and measured cost
----------------------------

Basic (9 captures): CAPTURING combined-process CPU peak 11.08760ms, whole-process
CPU through report peak 153.54072ms, combined RSS peak 36,564,992 bytes.
Lifecycle (6): corresponding peaks 12.11034ms, 158.94984ms and 36,626,432 bytes.
Largest raw output is 455,494 bytes. Each successful session retained the
40ms CAPTURING guard and completed with no budget violation.

Guard (3): all exceeded the unchanged 200,000 source entries/second threshold,
were rejected PARTIAL, and detached the actual collector. Both business
containers continued: at least 2,055,168 operations per container after detach.
Observed detection intervals were about one second, with 4.33--4.38 million
entries in those intervals. This is a sampled guard, NOT an instantaneous rate
cap or proof that dense FD tracing is cheap. CAPTURING peak was 18.51571ms,
whole-process peak 121.96696ms, RSS peak 35,573,760 bytes. The rejected sessions
produce no accepted ownership findings.

Control passed 16 checks / 14 sessions, fault 1 / 1, crashes 16 / 16. Crash
cleanup passes but interrupted data remains invalid and scope_audit_complete
is false. This cohort does not repeat the real 1200-second expiry experiment.
All final objects were absent; host kernel and boot ID were unchanged. Full
source-context CPU, asynchronous background CPU and total kernel memory are
not certified; no production-overhead acceptance is inferred from process CPU.

Pinned raw serials
-----------------

* basic/x1-fd-20260920-082243.log:
  36819bd164272f121a402a87f9d3b55ac35183d6c32888ffa76556174af5689b
* lifecycle/x1-fd-20260920-082330.log:
  1eda4f6661cdaefec3850da5affddbb5a54145bfd4e3a7116fc3c8931bfb9f18
* guard/x1-fd-20260920-082415.log:
  ca7c36230f5acc8bf57e762a08a9535895da49734ec79bcb72a1d3c99560bb96
* control/x0-control-20260920-082442.log:
  3a37cbe0972ea90ee73cef08180d63fafc2fa63c3ca57389e2b77cb3179053c2
* fault/x0-fault-20260920-082740.log:
  7312235d695e13ac42aaa90d6dfe681abf660944f528cab515f25af77c8fe1bb
* crashes/x0-crashes-20260920-082747.log:
  d4f83106cf361962082ca1bf1d75795d96c439e670902ef8717a932df9bd0065

X7 remains incomplete. This closes a concrete bounded-prefix call-coverage gap
and strengthens whole-output correctness checks; it does not fill the true
blocking-relation denominator, remaining skb transformation/release gaps or
the required cross-resource coverage and cost audit.
