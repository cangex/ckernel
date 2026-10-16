Owned task filesystem groups
============================

The backend uses newly allocated regular files, loop devices, and independent
ext4 instances. Each group has a separate superblock, allocator and journal;
containers in the group receive different task directories. The physical disk,
host backing filesystem and other kernel services remain shared. This is not
an internal ext4 namespace or a patch that eliminates every filesystem lock.

Requirements: Linux, administrative privilege, Python 3.9+, util-linux,
e2fsprogs and Docker for reference checks. Use an administrator-owned parent
on the same persistent storage pool as the workload. No physical block-device
argument is accepted for formatting. No tmpfs, existing-disk initialization,
global cache dropping, or forced/lazy unmount is performed.

Fresh creation
--------------

This reproduces the four-group geometry used in the recent Go experiment::

  python3 tools/ckernel_fs_domains/fs_groupctl.py create /PERSISTENT/NEW-RUN \
    --slots 48 --groups 4 --gib-per-group 9 \
    --inodes-per-group 393984 --journal-mib-per-group 192

Replace the path with a NEW non-existing directory under a trusted parent.
Creation reserves 36 GiB plus at least 6 GiB free space and 256 MiB overhead;
the caller must additionally budget workload, grading, logs and other users.
Runtime free space must be monitored by the workload harness. Inode/space
budgets here are not a guarantee that arbitrary tasks fit.

Each slot i uses group i modulo 4. The JSON manifest returns source paths under
bindings. Use that slot's path for the intended writable task directory only.
For the Go experiment this was /usr/local/go, not the entire container rootfs.
For Docker with SELinux, pass the distinct slot path as a volume with :Z; keep
Enforcing and the original container restrictions. The tool does not change
Docker daemon, host SELinux policy, workload commands or cgroup limits.

Do not run two tasks in the same slot directory. Every independent trial must
create a fresh root; this command refuses an existing root. No writable task
state, build cache, or previous output is reused. Do not use the legacy
low-level remount command to recycle completed task directories.

Inspection and release
----------------------

::

  python3 tools/ckernel_fs_domains/fs_groupctl.py inspect /PERSISTENT/NEW-RUN
  python3 tools/ckernel_fs_domains/fs_groupctl.py release /PERSISTENT/NEW-RUN

Stop and remove ONLY the task's containers before release, including stopped
containers that still reference the mount. Release verifies ownership,
image/loop/UUID identity and remaining process mount namespaces, synchronizes,
normally unmounts, detaches the loop, checks the filesystem, and deletes only
the owned image. The small manifest is retained. Other runtimes must provide
their own reference registration; the Docker check is not a generic runtime
reference database. Concurrent external mounting during release is unsupported.

The state root is owner-only and symlink/foreign paths are rejected. This is
not protection against a malicious host administrator who can change mounts.
On ambiguous command failure, retain the state and inspect actual identities;
do not retry formatting, force detach, or delete the directory. Crash/power-loss
fault coverage is incomplete. A manifest checkpoint is not an atomic transaction
with external mount/loop operations.

Cost and evidence
-----------------

preparation_ns and release_ns measure separate lifecycle intervals. Business
timing belongs in the workload harness. Include creation, prewarming, journal
space, resident cache, background work and drain costs in an end-to-end claim.
Do not describe host-owned backing caches as free or sum RSS as physical memory.

The old 24-slot matrix planner is retained as a historical helper; the delivery
CLI supports 1..48 slots and uses the explicit modulo-group rule above. Unit
tests cover this distinction. No dm-thin snapshot backend is shipped here.
