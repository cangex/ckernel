Native inode writeback context
=============================

This optional block Profile observes existing ``writeback_dirty_folio`` and
``writeback_single_inode_start/writeback_single_inode`` events. No filesystem,
writeback or block scheduling algorithm is changed. Source inventory version 12
includes the three producers, and stop verification requires all to be off.

The dirty event is a directly observed task/folio transition, not every write.
It records inode address, superblock device, number and generation, but these
fields do not prove inode lifetime across two events. Earlier dirty transitions
are therefore not silently joined into an exclusive writer or causal blocker.

The start/end pair encloses ``__writeback_single_inode`` while I_SYNC is held.
A maximum of 256 task-start keyed records retains its inode and wbc. A watched
request started synchronously inside that context emits a separate bridge with
the immutable request episode. Only a closed, nonoverlapping, unchanged context
whose actual executor matches the request submitter establishes the bridge.
Zero-epoch early kernel threads are usable only within this closed call, never
as a permanent identity. Missing starts/ends and asynchronous submissions are
unknown. A nested begin invalidates the outer map entry too. No BPF lock or
inode reference is taken; the native call supplies the limited lifetime.

Four identities remain separate: observed dirty-transition actor, inode
writeback memcg ancestry, bio blkcg billing ancestry, and actual executor.
The bridge identifies submission context, not exclusive content of merged bios,
nor a tenant responsible for another tenant's wait. Shared-inode tests must
observe both dirtying containers without relabeling the chosen billing root
as the unique writer. Private files/devices must not be joined together.

The bounded map adds at most 256 event values plus hash overhead. Entry, filter,
output, map and report costs remain in the unchanged budget and inventory;
high entry rates disable the producers, not merely output. Runtime load and
cost acceptance require isolated VM evidence, not the existence of this file.
