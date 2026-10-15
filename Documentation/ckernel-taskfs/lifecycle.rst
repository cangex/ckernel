Lifecycle and ownership
=======================

ALLOCATING -> READY -> ATTACHED -> RUNNING -> DRAINING -> SEALED
or DELETING -> RECLAIM_PENDING -> DELETED. READY only promises a mounted output
directory; it does not promise a runnable or validated container. Exact container
ID, creation generation, labels, mount source and SELinux process label are
checked before recording RUNNING.

A random control-directory owner identifies the pool. File inode/device/size,
loop backing, DM UUID/table/major:minor, thin ID, activation generation, mount
ID/namespace and task ID are distinct identities. Filesystem UUID is recorded
and changed on the unmounted child, never used as sole ownership evidence.
Thin IDs increase monotonically within a pool; deleted task requests cannot be
reused. Control-directory replacement and manifest symlinks are rejected.

Seal keeps the drained thin result. Delete refuses existing containers, other
mount namespaces, FD/cwd/root/exe/mmap references and open DM mappings. All
unmounts are normal, with native synchronization. The four reclamation levels
are: task access removed; DM mapping absent; thin deletion acknowledged with
pool occupancy counters; outer reserved files actually removed. Per-branch
deletion does not claim the last level. Pool metadata faults affect all children.
