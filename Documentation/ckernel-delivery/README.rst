CKernel delivery candidate
==========================

This branch preserves the old complete kernel source and adds owned filesystem
grouping tools. It is a reviewable candidate, not an approved production kernel.
It does not contain the CKernel-M framework, taskfs dm-thin prototype, observer
kernel patches, or the reverted W1/W2/W3 experiments.

Sources
-------

* OLK baseline: 622eeb9a4278d53debcdcdb8f49b816be45f9a15,
  tree 90bda14c1a6dcc2df4ae12c28fa4e0ff82f2fbd8.
* Complete old CKernel: fa179f4b0a4fa9725857528b47ed3c07b71f5e26.
  All 67 changed kernel files remain in history and in this source tree.
* Filesystem tools: selected files from
  b71a71be141748d31e9dcda1ebe7847ad92a1cc7, followed by delivery hardening.
  There is no merge of that branch's complete tree over the old kernel.

Components and activation
-------------------------

========================= ====================== ===============================
Component                 Delivery status        Activation
========================= ====================== ===============================
Core task context         Retained               /dev/ckernel initialization
AppArmor self-signal cache Experimental, off      parameter + feature bit 8
Maple per-CPU stock        Experimental, off      parameter + feature bit 9
AppArmor path allow       Quarantined            nonzero parameter rejected
FD accounting replacement Quarantined            nonzero parameter rejected
VFS shadow/reference cache Quarantined           nonzero parameters rejected
Socket LSM/token shortcuts Quarantined           nonzero parameters rejected
memcg/shmem/FaaScale       Legacy experimental    off by default; not certified
resctrl monitor           Legacy experimental    off by default; not certified
Independent ext4 groups   User-space tool        fs_groupctl.py, explicit root
========================= ====================== ===============================

The quarantine prevents normal driver configuration from reaching known unsafe
paths; it does NOT repair their algorithms. Historical implementations remain
for review. Do not remove the guard and call the result validated. File safety,
FD quotas and socket LSM checks fall back to the native paths in this profile.
The branch still contains other old built-in changes; mask zero is not a proof
of binary equivalence to OLK or zero framework overhead.

AppArmor cache is only self-signal eligibility for an unchanged, non-stale label
whose profiles do not mediate signals. It is NOT the historical path whitelist
or generic permission bypass. Policy replacement, credential transitions and
LSM composition still require extended runtime qualification. With AppArmor
absent/inactive, there is no AppArmor optimization benefit.

Maple retains the original per-CPU, cookie-tagged stock of up to 16 free nodes,
not private active trees. Hotplug, GFP/NUMA allocation constraints, RCU lifetime,
cross-instance churn and reclamation remain qualification requirements. No
Agent-workflow benefit has been established for this kernel component.

Interface changes
-----------------

Old feature bits 0..7 keep their numbers. New bits 8 and 9 make self-signal and
Maple activation independent of the unsafe AppArmor path gate. A zero extended
mask activates neither even when the module parameters are enabled. An extended
request for unavailable features now fails with EOPNOTSUPP instead of silently
discarding bits. Old callers requesting all old features must handle failure.
The legacy initialization ioctl still requests available features; explicit
extended masks are recommended.

All known unsafe parameters accept zero only. This is enforced on module load,
not merely a default. Their sysfs entries are read-only. No module or kernel is
installed by the delivery tools.

Build and check
---------------

Use a case-sensitive Linux checkout. Retain a full config, compiler identity,
commit, Image/module hashes, and separate out-of-tree build directory. The
historical ARM64 configuration needs MPAM, resctrl and the files controller;
this branch does not claim generic distribution config compatibility.

Run unprivileged source/unit checks::

  python3 -m unittest discover -s tools/ckernel_fs_domains -p 'test_*.py' -v
  python3 -m unittest discover -s tools/testing/selftests/ckernel_delivery -p 'test_*.py' -v

Build the launcher with the selftest Makefile or directly with the target C
compiler. Example, ONLY in an approved isolated guest after loading a matching
module with both experimental parameters enabled::

  ckernel_bind 0x300 PROGRAM ARGUMENTS

0x100 selects the self-signal cache; 0x200 selects Maple; 0 selects neither.
This launcher is not a container runtime or a host-deployment authorization.

See filesystem-groups.rst for storage lifecycle and VALIDATION.md for actual
checks, unresolved risks and performance boundaries.
