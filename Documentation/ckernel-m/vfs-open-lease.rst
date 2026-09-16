Read-only open-file reference leases
===================================

This default-off prototype requires CONFIG_CKERNEL_M_VFS_OPEN and both
CKM_FEATURE_VFS and CKM_FEATURE_VFS_OPEN. Query-only ABI layouts are unchanged.
Use ``ckmctl --vfs-open READONLY_ROOT MAX_ENTRIES PROGRAM [ARGS...]`` after
explicit private-directory preparation. The registered mount must satisfy
the query-lease contract; a read-only alias of a writable superblock does not.

What is reused
--------------

Native pathname traversal first resolves the path. In ``do_dentry_open``, a
regular read-only file on the exact registered mount may borrow the file-owned
terminal dentry reference from an instance entry. The first occurrence learns
a bounded entry and uses normal path_get. A hit avoids the additional shared
dentry get/put pair. Mount references remain native on every open and close.

Each open still has its own file, position, flags, credentials, security
context and filesystem callback. Directory search, security_file_open, IMA,
fsnotify, leases and attribute operations are not permission-cached. Write,
create/truncate, O_PATH, executable, backing-file and no-account internal opens
do not qualify. Full/contended/stopped caches use normal reference handling.

Lifetime
--------

A conditional ``file.f_ckm_vfs_entry`` records the immutable entry. Each loan
holds an entry reference and an instance reference. The entry records its
state/owner; SCM_RIGHTS, inherited files and delayed_fput do not use current
to find the releasing owner. alloc_file_clone and pseudo-file paths remain
native and never acquire a borrowed ownership pointer by copying a file.

Pre-open error cleanup releases the loan and native mount reference. Failures
after FMODE_OPENED use ordinary fput. Revocation, writable remount and unmount
stop lending and drop cache-owned references. Outstanding files retain the
same object lifetime as native files, including ordinary EBUSY unmounts.
The last loan releases its dentry, then its owner. Core final work and RCU
remain shared reentry paths; this is not a synchronous global drain protocol.

Costs and diagnostics
---------------------

The config adds one pointer to every struct file, not just enrolled files.
Measure both sizeof(file) and filp slab stride for each build configuration;
allocator alignment means they need not change by the same number of bytes.
Entries additionally store an owner-state pointer and per-CPU counters.
Eligibility, instance-local rwsem, entry/owner refcounts and mount references
are additional work. A cold miss may pin an object even if the later native
LSM check rejects the open; this grants no access and consumes bounded cache
capacity. Private tmpfs contents remain charged by native memory accounting.

CKM_IOC_VFS_OPEN_QUERY reports hits, native fallbacks and released loans.
Hits minus releases is meaningful as an outstanding-loan count after new
lending has stopped and statistics have quiesced; concurrent counter reads
are not an atomic snapshot. The launcher also waits for loans to return but
does not claim that closing its handle waits for all final RCU callbacks.

Test ``vfs_open_lease`` in a disposable VM with the supplied real AppArmor
deny profile loaded. It covers independent offsets, dup, denial, failed open,
fork/exec, concurrent revoke, remount/unlink, migration and an FD transferred
to another instance after its originator exits. ``vfs_stress`` additionally
tests allocation failure and concurrent reclaim/exit. Performance acceptance
is separate; real hits alone do not establish a speedup or isolation.
