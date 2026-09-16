.. SPDX-License-Identifier: GPL-2.0

M3 lifecycle and shared-backend reentry
=====================================

This is an implementation inventory, not an isolation or bounded-latency proof.
M2 performance remains unaccepted and Maple is off in the primary M3 runs.

Creation and preparation
------------------------

ckm_mount_prepare runs in the preparing process after native cgroup placement.
Copying and tmpfs mount creation still enter VFS, shmem, memcg and the native
allocator. Source page-cache reads may affect other readers. The destination is
a new explicit copy, not a transparent clone of arbitrary shared writable data.
The byte/inode limits do not cover all filesystem/executable metadata.

ckm_vfs_init allocates state and per-CPU counters with GFP_KERNEL_ACCOUNT.
Allocation failure aborts instance creation and rolls back references. Core
still updates its host-level instance count and cookie on creation; these are
not per-query operations. Registration uses s_umount shared, the instance
control guard and fs_pin's global pin_lock. Administrative contention can wait.

Use and reference ownership
---------------------------

Every lookup keeps native pathname traversal, search permission, current mount
resolution, RCU sequence validation, LSM/audit and getattr. The fast path checks
the task's instance/cgroup, tries the instance read guard, scans at most sixteen
entries and increments an entry reference. It still updates native mount
references. Entry ownership is not inferred from the releasing CPU.

The guard is released before getattr. Read-guard contention, misses, symlinks,
complex lookup flags, writable mounts and unsupported objects stay native.
Learning is optional and uses a write trylock. Cache full causes native
reference handling, not a new errno. The instance guard and entry counter are
shared inside that instance; multiple threads there can still contend.

Invalidation
------------

reconfigure_super calls ckm_vfs_before_write_remount while it already owns
s_umount exclusively. Registration takes the shared side, preventing a new
cache from crossing the transition. Only pins with this feature's kill callback
are selected. The global pin lock is held only to locate a pin, not during its
kill callback. Other fs_pin users are not invalidated by the new helper.

The callback stops lending under the instance guard, releases cache ownership
outside that guard, and removes the pin. It does not wait for getattr under
s_umount. An outstanding query retains an entry reference and its normal mount
reference until completion. A concurrent pin_kill may wait for a callback;
the helper can scan multiple pins on the same superblock. Consequently a
shared superblock's reconfiguration is still a necessary coordination point,
not a per-container independent operation with a proven time bound.

Return and final release
------------------------

ckm_vfs_end returns an entry reference, or performs native path_put after a
fallback. The final entry put runs dput; mntput may trigger native mount cleanup.
These execute without the instance guard, but dcache, mount and allocator
resources are still shared backends. Pending references from a failed RCU
conversion are also released; they are not forgotten in a fallback counter.

Revoke currently uses Core's ordinary shared workqueue. Mount cleanup can run
in native task-work. Final state storage uses kfree_rcu and native freeing of
per-CPU storage. Shared workqueues, RCU progress, memcg and SLUB are remaining
coordination sources. Their attribution and CPU cost must be measured; moving
work off the caller is not evidence that another instance cannot be delayed.

Known limits
------------

There is no byte-accurate total retained-object budget in the query ABI;
metadata_payload_bytes is only declared payload, not allocator rounding or
all referenced inode/data memory. The registered mount must be SB_RDONLY.
RO-to-RW invalidation prevents idle references from retaining deleted file data
after writes become legal; active query references can still retain it as
native queries do. Memcg and tmpfs limit semantics remain native.

No long-lived open-file lease, safety-result cache, FD quota delegation or
socket optimization is implemented here. Extending struct file for M3-C is
awaiting explicit review, rather than hiding owner lookup in a global index.
