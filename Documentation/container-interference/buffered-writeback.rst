Buffered writeback billing scope
==============================

This is a bounded block specialist, not a continuous dirty-page tracer. It
does not change filesystem/writeback policy or claim an exclusive I/O blocker.

Admission and executor are different
------------------------------------

BLOCK protocol 3 first considers the registered current-task root. If that
root is not a selected live target, it walks the head bio's blkcg ancestry,
at most 32 levels, and admits only a selected live registered billing root.
The same 256 request watches and two-second window apply. Missing identity,
generation mismatch, excessive ancestry or unselected billing root cannot
open a watch. Interrupt-context starts remain outside this adapter.

The top-level id/generation are the immutable selected scope, not necessarily
the submitting task's container. Protocol 3 adds explicit admission,
submitter_id/generation and submitter_flags fields. TID and task start remain
those of the real submitter. Later executors are recorded separately. The
issue-local bounded bio list can still differ from the initial head bio.
Task-based admission takes priority if both paths apply.

Early boot kernel threads can legitimately have start_boottime zero. Such
unregistered submitters carry ``start_epoch_unknown``; the report never joins
their TIDs across request episodes. Registered business actors still require
a valid observed start. Unknown completion executor epochs also do not imply
container ownership. A kernel thread's PF_KTHREAD flag does not identify who
originally dirtied its pages.

The wire record reuses otherwise unused cis_event ip/weight/flags/reserved
slots to retain these fields without growing the BPF stack or map value.
They are not IP samples or sampling weights for BLOCK. Capture serializes
explicitly named fields; older protocols remain readable under their frozen
collector contracts.

What remains unknown
--------------------

bio blkcg identifies native accounting at the observed stage. It is not an
exclusive writer, inode owner, device-slot holder or causal blocking tenant.
Different containers may dirty different pages of the same inode; native
writeback ownership and migration can choose one billing context. This
adapter keeps initial_dirtier and inode_owner unknown even when a test fixture
knows which file it wrote. It must not import test truth as production evidence.

Private-file and shared-inode tests
----------------------------------

``specialist_vm_host.py --label x5-writeback`` exclusively creates two new
64MiB regular scratch files below the dedicated VM directory, formats them as
ext4 with eager inode/journal initialization, and presents them as virtio
disks. It never formats a host block device. The guest mounts those disks;
each registered container writes 128KiB through normal buffered pwrite. The
unregistered manager invokes syncfs, which causes real wb_workfn background
submission. An OFF/block, private/shared, three-round alternating schedule
is frozen before execution. Private uses different files/devices; shared uses
disjoint pages of the same inode. No synthetic Profile event is generated.

Workload logs independently record inode/device, bytes and time. After sync
and the capture window, the verifier evicts the tested range and checks its
contents. Captures must contain actual completed background write requests
with native writeback stacks, closed inside the independent write/sync truth
interval. Completed data bytes must equal 256KiB across the two actors, with
128KiB per billing root in private cases. In private tests both billing roots must appear;
shared tests must not require both writers to appear as distinct bio owners.
No percentage recall is computed from pwrite counts: files, bios and requests
are not one-to-one. This is VM functional evidence, not saturated storage or
production latency acceptance.

Cost and validation limits
--------------------------

There is no new live map or attached program in this increment. During an
active block window the additional ancestry lookup for previously ignored
starts is real overhead. The 40ms process CAPTURING budget is unchanged; it
does not cover every probe CPU cycle in business/worker context. Existing
source/callback counters, loss, cleanup and memory inventories remain required.
Buffered source coverage does not complete X5 or X7: dirtying/inode linkage,
writeback throttling, remaining split/cancel cases and full backend CPU/memory
accounting still need dedicated work.
