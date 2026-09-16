.. SPDX-License-Identifier: GPL-2.0

M3-B terminal dentry reference loan prototype
============================================

This stage retains native pathname traversal
-------------------------------------------

The implementation does NOT cache pathname resolution or permission decisions.
It preserves link_path_walk, final component lookup, directory search checks,
native LSM and audit dispatch, mount sequence validation, vfs_getattr and its
normal security hook. It optimizes only the terminal dentry reference pair on
an eligible RCU-walk hit. It does not claim open/close acceleration, a complete
path lease, or the absence of backend interference.

After a successful native lookup, up to 16 terminal regular-file dentries are
retained for one explicitly registered read-only tmpfs mount per instance.
The subsequent native walk must resolve the SAME mount and dentry. Only then
can the call borrow the retained dentry instead of taking a new d_lockref.
Every operation still takes the normal mount reference and validates the mount
and dentry sequence counters. Symlink walks, scoped roots, directories,
revalidation callbacks and ref-walk paths keep native behavior.

The cache stores object identity, not a filename-to-object answer. Rename,
unlink, replacement, overmount, permission changes and credential changes
therefore still go through the original walk. A read-write superblock remount
permanently stops loans and releases the cache before writes become possible.
No cached permission
is used after a change; there is no fabricated policy generation counter.
Unsupported operations do not acquire new application error conditions.

Control interface
-----------------

After preparation and placement in the intended memory cgroup::

  ckmctl --vfs /private/readonly/mount/root 16 /path/to/program args

This new form selects Core+VFS only. The existing numeric MAX_NODES form and
Maple controls are unchanged. The wrapper registers the mount before binding
the child, retains a control handle, reports VFS counters and requests drain.

CONFIG_CKERNEL_M_VFS is default-off. Create with CKM_FEATURE_VFS and normal
CKM_IOC_CREATE, then call CKM_IOC_VFS_ROOT before binding any task. The request
contains version, size, an open root-directory fd, capacity 1..16, and zero
reserved fields. The directory must be the mount root of a currently mounted,
read-only tmpfs, including SB_RDONLY (a read-only bind alias alone is rejected).
Registration is privileged in the initial user namespace and is permitted once
per instance; unmount, writable remount or revoke permanently stops it.
Registration holds s_umount shared; reconfigure_super holds it exclusive while
killing only this feature's pins before its writable transition. Bind and root
registration serialize on the instance's cold control guard.

The administrator must choose a directory whose private-copy semantics are
explicitly permitted and establish the workload's native memory limits before
preparation. Registration does not prove that the filesystem was privately
created, immutable, or charged to that instance. A shared registered mount is
still shared; permission and underlying filesystem semantics remain native.
No cookie acts as an authorization token.

CKM_IOC_VFS_QUERY is additive to the existing ABI. It returns capacity, cached
entry count, registration/stopped state and cumulative hit/retry/native/full
counters. Counters are per-CPU and query is not a transactional hot-window
snapshot. metadata_payload_bytes counts the state and declared per-CPU payload,
not allocator rounding, retained file data or all mount metadata.

Ownership and teardown
----------------------

A normal persistent path_get would add a mount reference and could turn an
otherwise successful umount into EBUSY. This prototype uses the existing
fs_pin infrastructure instead: one mount/superblock pin owns an instance
reference and the cache's dentry references, but no permanent mntget.

The mount cleanup/superblock pin callback or instance revoke stops loans,
removes the entries under an instance-local rwsem, drops cache ownership
OUTSIDE that lock, and removes the fs_pin. Each entry has its own instance-local
reference count. Outstanding operations keep it alive only until their lookup
completes, just as a native lookup retains a transient dentry reference. Entry
storage is embedded in the state, never reused after stop, and kept alive by
the executing task's instance reference. The last entry put performs dput.
The instance remains alive until its task, handle, worker and pin references
finish. Pin storage is freed after RCU because another pin_kill caller may
still inspect pin->done. No fs/mount.h or struct file layout is changed.

The business path uses down_read_trylock only at the end of eligible RCU walk.
Contention falls back to native, not a sleep waiting for a writer. Optional
learning uses down_write_trylock; no learning is required for syscall success.
A successful loan increments its entry reference and releases the read guard
BEFORE getattr, LSM and mntput. Invalidation never holds s_umount while waiting
for an in-flight getattr or its security hook. The native mount reference also
preserves an in-flight operation's mount lifetime.

Budget, retained memory and residual cost
----------------------------------------

State and per-CPU counter storage are allocated with GFP_KERNEL_ACCOUNT when
the feature is created; there is no per-query owner allocation or global owner
lookup. Entries are bounded and are not evicted/reused until stop. Cache full
means native reference handling, not application ENOSPC.

A retained dentry on a writable filesystem could incorrectly delay deleted
file reclamation and introduce ENOSPC. Therefore the writable-superblock bind
alias is rejected and RO-to-RW transition drops idle references first. Active
lookups can still transiently retain an unlinked inode, as native ones do.
Entry capacity is NOT a byte bound on retained file contents. The
registered tmpfs space limit and native memcg accounting still apply; prepare
bounded file sets and report shmem/retention separately. Registration does not
transfer existing file charges. No extra bytes are made uncharged or assigned
to a worker, and no claim is made that pressure behavior is unchanged in cost.

Costs include an instance read-lock operation, an entry reference update, bounded entry scan,
mount reference operations, native lookup/LSM, per-CPU counters, optional
learning, pinned memory and final dput. Cold pin insert/remove uses native
fs_pin's global pin_lock. Revoke currently runs on the existing Core worker;
mount cleanup may run in native task-work. Cold invalidation can wait for another
pin-kill callback and final dput work; background queue/RCU/SLUB remain shared.
No guard is held across getattr. Bounded entries are not a bound on
waiting time. This is a functional prototype until separate measurements pass.

Validation boundaries
---------------------

vfs_lease_contract first proves native counterexamples (including retained
path EBUSY) without any CKernel-M fast path. vfs_lease then checks actual cache
hits, ordinary unmount without manual eviction, changed names and permissions,
overmount, flags/errors, capacity, fork/exec, rw fallback and concurrent revoke.
Those tests must run against the exact VFS image with no kernel warnings.
This document describes the candidate protocol, not a substitute for test logs.
M3-C, M4, M5 and M6 are not implemented by this file.
