Y3 selected filesystem public resources
=======================================

Status: PASS_SCOPED for the build and functional cases in
y3-validation-20260920.rst. This is not a performance certificate.
Independent private directories can still share a filesystem journal and block
allocation groups. This is distinct from sharing a writable directory or file.

One initial-user-namespace administrator opens cis_fs_filter and supplies an
already-open directory FD on ext4. The kernel holds its path, checks the live
superblock type, freezes its device and assigns a non-reusable lease generation.
The lease is immutable, exclusive and cannot be replaced while old probes are
attached. Close revokes it and waits for RCU readers before releasing the path.
Its synchronization and final path release are control-plane costs, not free.

Disabled tracepoints bypass clock, selection and BPF work. Enabled hooks compare
one selected device under RCU, using per-CPU counters rather than a global hot
lock. Source entries include unselected filesystems and must enter the budget.
Journal commit and transaction-switch brackets are unsampled; ext4 allocation
results and orphan operations are sampled at 1/16 per CPU and operation.

Commit brackets identify journal address, transaction ID and number of passes
through the native wait condition. Zero passes means no commit wait observed.
Positive passes still do not measure pure sleep, spin time or identify a unique
blocking tenant. Transaction switching brackets include scheduling and wakeup.
Allocation-group records describe native selected allocations, not group-lock
contention. Preallocation and group selection retain native semantics.

Orphan-list add/delete brackets retain the real superblock mutex and acquire
timestamp, with the callback after unlock. They do not collect every holder or
claim another container held that mutex. The orphan-file branch is a different
operation and must never be labelled a legacy-list mutex wait. Orphan-add error
cleanup's second lock acquisition is not bracketed. It remains outside coverage.

Resource addresses are scoped to the pinned filesystem lease and short window;
transaction IDs are not permanent object identities. Lost samples, unfinished
operations, unsupported filesystems, unknown asynchronous actors and missing
lifetimes remain explicit. No sampled count is a full event population.
Filesystem sharing, same transaction participation and actual waiting are
separate facts. They do not establish exclusive causality or latency isolation.

Validation requires private-directory actors on shared/separate ext4 backends,
source-off checks, unselected-filesystem negatives, lease close/replacement and
orphan-file versus legacy-list branches. It must not write or mount host disks.
