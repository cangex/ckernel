.. SPDX-License-Identifier: GPL-2.0

Explicit private directory preparation
======================================

Scope
-----

``ckm_mount_prepare`` is a privileged, opt-in test preparation program, not an
OCI runtime, snapshot filesystem, security sandbox or path-lookup accelerator.
It creates a new mount namespace, makes propagation private, mounts a bounded
tmpfs over an existing empty directory, copies an explicitly stable source,
and runs a foreground command. It does not change the caller's mount namespace.
The CKernel-M instance is a task ownership context; it is not this filesystem.

Build with ``make -C tools/ckernel_m``. Example, after moving the preparing
process into the intended memory cgroup and resource placement::

  ckm_mount_prepare --source /source --target /empty-target --source-stable \
      --mode ro --bytes 16777216 --inodes 1024 -- /path/to/foreground-command

Run only as trusted root in the initial user namespace. The source and target
names and the launch command are trusted configuration. The command retains
its existing privileges; the new mount namespace does not confine hostile root.
No privilege is added and no CKERNEL_M kernel feature is required by this tool.

Source contract
---------------

The caller must quiesce source writers and namespace changes for the entire
copy, or provide an immutable snapshot. ``--source-stable`` is an explicit
acknowledgment of that requirement, NOT a kernel freeze or an atomic snapshot.
Before/after metadata checks reject detected mutation but cannot prove absence
of adversarial or perfectly timed updates. No workload starts after detected
copy failure. Preparation itself performs reads and allocates memory.

Supported objects are directories and singly-linked regular files. The copy
preserves numeric uid/gid, permission bits, atime and mtime. New inode numbers,
device identity, creation/change times and physical layout are inherent to a
copy and are not preserved. Sparse holes may be materialized within the byte
budget. This is not a transparent replacement for applications relying on
hardlinks, inode identity, special filesystem properties or shared writes.

Symlinks, hardlinked files, devices, FIFOs, sockets, setuid/setgid bits,
ACLs/xattrs and reported non-mount-root statx attributes are rejected. Nested
mounts, including bind mounts within the source, are rejected by openat2
RESOLVE_NO_XDEV; symlinks by RESOLVE_NO_SYMLINKS. Depth is limited to 64 and
the requested inode limit to 1048576. Unsupported openat2 is a failure, not a
fallback to an unsafe pathname walk. Type checking uses O_PATH first, then
reopens that pinned regular file or directory through procfs.

The destination must be an existing empty directory. It is not auto-created,
deleted or recursively cleaned in the caller's namespace. tmpfs uses nosuid
and nodev; mode ro adds a read-only remount before launching the command. No
whole rootfs is copied. Independent rw copies are possible, but shared writable
data must remain shared. Read-only mode is not proof of permanent immutability:
an authorized administrator may remount or overmount it.

The destination cannot be the preparing process's current directory: mounting
over a directory does not retarget an existing cwd reference. Pre-existing
inherited file descriptors also retain their original objects; preparation
does not silently replace them or close arbitrary caller descriptors.

Accounting, lifecycle and failures
---------------------------------

Copying must occur AFTER placement in the destination memory cgroup. tmpfs
uses native shmem/memcg accounting; no charge is bypassed or moved to a worker.
The byte limit bounds logical copied file bytes as well as tmpfs space, and
nr_inodes bounds tmpfs objects. These are not a complete cap on kernel mount,
dentry, source page cache or executable memory; use a native memory limit too.
Source reads can populate shared caches and remain a setup-time shared cost.

The foreground command runs only after a complete copy and metadata check.
The supervisor retains no source or destination file descriptors while the
command runs. It polls the foreground child every 10 ms and forwards SIGINT
or SIGTERM to that child's process group, not unrelated processes. Its CPU
cost must be included if used during a performance experiment.

On child exit the supervisor attempts ordinary unmount. A busy mount is reported
as failure (125), never hidden by lazy unmount. Processes deliberately left
behind may retain the private namespace and objects; callers must use a
foreground command and normal workload/cgroup supervision. No global process
cleanup is performed. Command status is preserved unless preparation or cleanup
fails. Abrupt death relies on normal namespace reference lifetime, not a claim
that all resources disappear immediately.

Tests and interpretation
------------------------

``private_tree`` requires explicit CKM_ISOLATED_GUEST=1 and a tool path in
CKM_MOUNT_PREPARE (default /ckm_mount_prepare). It validates independent copies,
metadata, read-only failures, unsupported inputs, limits, exit status, source
preservation and caller namespace preservation. The accounting case prepares
the copy inside a dedicated memory cgroup, checks shmem charge while it lives,
and requires that shmem charge to drain after unmount. The interruption case
sends SIGTERM after observing the private mount during a large copy and checks
that no workload starts and the caller's destination remains unchanged.
Initial-user-namespace identity is tested separately from numeric uid zero.
Open-file survival after lazy
detach is tested as a native lifecycle fact, not the supervisor's cleanup mode.
``vfs_lease_contract`` contains native counterexamples for future kernel leases.
Neither program proves a VFS cache, isolated backend allocation or speedup.
