Post-rwsem regression, 2026-09-19
================================

Frozen kernel 99d53547065a4fb62a132ed17acaaebbe77ab785 and tools
b286e55eb8138b7dd3b7bc78cfca2a8901cb3a20 were tested in the same dedicated
eight-vCPU ARM64 KVM layout. Image SHA256 is
af526b4faad7e366cc41cb8b1c3e4d2d5599242394d95c7e8b5f8af9307e31f2.

``post-rwsem-control-20260919`` passed 15 independently checked cases and
13 captures: eleven selective collector loads, pause/drain and budget,
restart/nonce preservation, unregister, and missed-slot behavior. All
ordinary terminal scope audits are complete. ``post-rwsem-fault-selected-
20260919`` passed the intentional failed-cleanup case: FAULTED is retained
and a new session is refused, not treated as a successful capture.

``post-rwsem-crashes-selected-20260919`` passed 15 crash/recovery checks.
Forced worker/controller termination deliberately leaves 13 captures
without complete terminal coverage counters. Those scope audits remain
BLOCKED; the corresponding capture is not usable attribution evidence.
Recovery passes only after actual object absence is verified. A safe
cleanup result never repairs missing data.

The earlier helper labeled ``post-rwsem-fault-20260919`` and
``post-rwsem-crashes-20260919`` but omitted the guest mode marker. They
ran the ordinary control matrix and are retained as mislabeled, redundant
control data, not as fault/crash passes. The corrected helper explicitly
installs the respective marker before hashing the initrd. Independent
verification uses the actual plan in the serial, not the directory name.

``post-rwsem-joint-20260919`` completed 33 ordinary-application states
and 30 captures, but is FAIL. Allocator rounds zero and two reported
source-recursion skipped counts of 538 and 198. Their captures correctly
became PARTIAL/RECURSION_GAP; cleanup still completed. Allocator round one
had zero skipped entries. No ring loss or BPF-program recursion miss was
reported in those three records. This does not establish that the missing
source events are harmless. Their full-window E2 evidence is not accepted.

The next diagnostic revision records the existing per-stage allocator
source counters before and after each workload. This adds no hot-path
instrumentation and preserves all CPU, memory, loss and recursion guards.
Its purpose is to distinguish release capacity, nested release and other
source gaps before changing any producer. Re-running until a zero-gap
cohort appears is not the repair strategy. X7 remains incomplete.
