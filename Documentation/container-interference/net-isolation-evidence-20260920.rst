CPU quota and network namespace counterexamples
==============================================

Frozen tools ``7a18236255777826eaa277ab8b3a6a395f18be0f`` use the unchanged
``55795f96b`` ARM64 Image (SHA256
``753ac5f59b329afab597e147d6565883881696d09c35a420f9bb160285c6b7d9``).
The guest initrd SHA256 is recorded in the evidence directory.  Tool/BPF
builds and 651 Python tests, 21 ownership tests and seven profile tests
passed on ARM64.  Both fixed cohorts were run once, independently replayed
from raw serial and passed.  Kernel fixtures unloaded without warnings.
Host kernel and boot ID stayed unchanged.

Private-socket quota negative
-----------------------------

Three paired OFF/NET rounds completed, six states.  Actor0 was limited to
20 ms per 100 ms and spent 80 ms thread CPU before its private Socket
operations.  The three captured rounds each recorded three actual throttles,
with 183442, 228336 and 227069 microseconds of cgroup throttled time.
The unlimited bystander recorded zero throttles.  Both distinct socket
cookies and both participating actors were actually observed; the result
was not an empty-capture pass.  No cross-container Socket holder relationship
was reported.  The two inherited sockets shared a VM network namespace,
but their cookies/objects differed and neither belonged to its user's
current container namespace.

Peak combined-process CAPTURING CPU was 8.643050 ms, whole-stage process CPU
103.861130 ms and combined RSS 34304000 bytes.  These are not total observer
CPU or complete kernel memory.  This negative does not assign causal blame
for a production slowdown and is not positive Socket-lock recall evidence.

Serial ``net-isolation-7a1823625-20260920/x4-net-quota/x4-net-quota-20260920-104518.log``;
SHA256 ``8e3a33c843f7f99bebe6c7eb9d7c193597a44a590de4faeec551b805b006cca5``.

Creation, accept and SCM_RIGHTS namespace truth
---------------------------------------------

Eighteen OFF/NET states covered transferred created sockets, independent
replacement sockets and transferred accepted sockets, three paired rounds
each.  All 24 eligible shared/accepted relationships were captured; private
replacement sockets yielded no false cross-container relation.  All eighteen
expected creation/accept facts were matched to their independent native
operation intervals and tasks.  The receiver's current namespace differed
from the transferred socket namespace.  The socket FD returned by SIOCGSKNS
confirmed the original namespace; private replacement sockets instead matched
their own creating tasks.  UDP/raw-TCP exclusion remained verified.

Peak combined-process CAPTURING CPU was 9.414440 ms, whole-stage process CPU
151.763710 ms and combined RSS 37515264 bytes.  The existing 40 ms guard was
not changed.  These are scoped fixture results, not production P99 acceptance
or coverage of arbitrary network backpressure, protocols or skb transformations.

Serial ``net-isolation-7a1823625-20260920/x4-net-origin/x4-net-origin-20260920-104533.log``;
SHA256 ``59c1e4cbc6dc4b73099565541a860b8998ec32e0e1b6802a9eef57220927d678``.
Remote paths above are relative to ``/dev/shm/cis-x-20260919/evidence``.

Storage protection
------------------

Before these runs, root free space fell slightly below the required 4 GiB.
No VM was started while below the reserve.  One 79742464-byte task-owned
historical initrd was losslessly relocated to
``/home/cis-artifact-preserve-20260920``.  Its original path remains a symlink,
and SHA256 ``4726229732f6254cbd99a2ccfe6d1b5d17bc16107f558f11b628f47b70d7851b``
was verified before and after.  No evidence content was deleted or threshold
lowered.  New build and runtime artifacts remain in dedicated shm storage.
