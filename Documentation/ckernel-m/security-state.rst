AppArmor state reference loans and self-signal qualification
==========================================================

CONFIG_CKERNEL_M_SECURITY is default off. CKM_FEATURE_SECURITY requests an
independent eight-label budget; Maple's max_nodes is not reused. Each instance
allocates an accounted state and per-CPU counters. A local trylock protects
the bounded label table. File-loan resolution reads a fixed 256-entry owner
registry; only create/destroy take its mutex, never an ordinary file operation.
A task in a different default cgroup, a kernel thread, a
retiring instance, a full table or contention takes the native path.

Self signal
-----------

Only target == current, no explicit credential argument, and identical
current_cred()/current_real_cred() qualify. get_task_cred(current) observes
objective credentials; override_creds can otherwise give the self sender a
different label from its target. Those cases always use native processing. The
current effective label is obtained through the native critical section.
Every stacked profile must satisfy profile_signal_perm's own early return:
unconfined, or no rule mediates AA_CLASS_SIGNAL. No mediated allow decision
is cached, and no signal audit/deny rule is elided. The optimization avoids
repeating the self target credential/label reference acquisition and the
immutable qualification walk. Other LSM hooks and check_kill_permission
remain untouched. Instance identity by itself never grants a signal.

AppArmor's existing newest-label/proxy/FLAG_STALE protocol supplies validity.
Stale entries are not authorities; the current label is resolved before the
cached qualification is used and checked again before returning. A policy
operation concurrent with a check retains native in-flight semantics. A
completed policy replacement must make subsequent checks use the new label.

File lifecycle
--------------

apparmor_file_alloc_security borrows a label reference from an instance
entry. Each aa_file_ctx records an internal token for that entry. apparmor_file_open borrows the
already-held label only if it equals the file credential's label and is not
stale; otherwise it obtains the newest credential label normally. Native
aa_path_perm, auditing, IMA and all other LSM dispatch remain active.

File use keeps the original AppArmor cache/revalidation code. update_file_ctx
can merge a different subject label: it installs the normal referenced
merged label, clears the loan pointer and releases the old recorded loan.
File close and error cleanup release the original owner, never releasing
current's instance on behalf of an inherited/transferred file. The native
aa_file_perm limitations about already-open-file revocation are NOT fixed
or strengthened by this prototype.

The immutable entry holds one cache reference to its label; each borrower
holds an entry and instance reference. Slots with outstanding loans cannot
be recycled. Stale cache-only slots may be replaced under the local lock,
with the old label put after unlocking. Revocation stops new loans and drops
cache references. Outstanding files survive owner task exit and hold the
instance until their own native lifetime ends. Final label destruction can
still reenter AppArmor's label set locks and RCU; Core final work still uses
the system workqueue. These are not per-container fault-isolation guarantees.

Costs and diagnostics
---------------------

An internal u32 token occupies existing aa_file_ctx tail padding; a build-time
assertion rejects any configuration in which it would grow the blob. It does
not tag the native label pointer or change native label readers. A file loan
holds its entry and instance until release; its registry slot and entry slot
cannot be reused in that interval. Final instance destruction clears the
registry under the cold-path mutex only after every loan reference is gone.
The token is not a user-supplied ID or an authorization credential.

The original shared LSM file blob is not memcg-accounted on this OLK. Its size
and allocation flags are left unchanged, rather than adding uncharged pointer
bytes or changing other LSMs' allocation failures. New dynamic state/counters
are accounted. The registry is 256 pointers of fixed host kernel BSS storage
(2048 bytes on ARM64), explicitly not per-instance charged memory. Its cold
updates can invalidate cache lines read by other instances; this is a residual
shared path, not a no-interference guarantee. Each loan adds
local locking, table lookup, entry and owner reference operations; these can
cost more than native SLUB/reference fast paths. Each instance retains up to
eight immutable label roots, and therefore may prolong the life of policy
objects. management_bytes reports structure payloads only, NOT those transitively
retained policy objects, allocator rounding or page backing. No zero-memory
overhead claim is made. Original policy allocation accounting is unchanged.

CKM_IOC_SECURITY_QUERY reports signal hits/native decisions, file reference
loans/releases, borrowed open labels, learned entries and fallback reasons.
Concurrent per-CPU snapshots are descriptive, not atomic. A self-signal
temporary loan is not counted as a file loan. label_hits == label_released
is a file-loan conservation check only after the measured files quiesce.

Validation requires real profiles and policy replacement, stacked denial,
audit, cross-instance FD transfer, native file-context merging, inherited
descriptors, failure handling, migration, pressure and retirement. Real hits
are necessary but not sufficient for correctness or performance acceptance.
The optional KUnit subject test separately exercises actual override_creds
and explicit-credential fallback; it is not a substitute for policy tests.

Modern-policy absence of a signal rule is NOT an unmediated allow. The
file-only modern fixture intentionally tests denial. The separate legacy
fixture uses the upstream AppArmor 2.13.6 parser test features.nopolicydb
as its explicit compile ABI. Run both first on the unchanged AppArmor
implementation; a missing audit message does not count as an audit pass.
The reload test replaces that native-compatible legacy profile with a
modern denying policy, then verifies that subsequent calls cannot use the
old qualification. This is a compatibility test, not a recommendation to
deploy a legacy ABI or weaken production signal policy.

Shared-path reentry
-------------------

* Creation allocates state and per-CPU statistics through native accounted
  allocators. This can sleep/reclaim and shares allocator and memcg backends.
  Registry insertion/removal takes the global cold-path mutex; live loans
  use a read of their recorded slot, without taking that mutex.
* A local trylock failure never waits for the table lock; it immediately uses
  native AppArmor references and checking. The native fallback can still
  contend on shared label references and policy structures.
* Learning or replacing one of eight entries acquires a native label reference.
  The replaced label is released after the table lock, not while holding it.
  Final native label destruction can take the label-set lock and queue RCU.
* Every file use retains native AppArmor cache validation and permission rules.
  Cross-subject file use can merge labels using the native context lock and
  GFP_ATOMIC path. Instance ownership does not grant cross-subject access.
* Policy updates, newest-label resolution, auditing and permission failures
  remain native. The prototype does not isolate policy writers or audit queues.
* Revoke disables lending before dropping cache roots. Open files retain their
  loan and instance references. Final release uses the recorded owner; Core
  revoke/final work still uses system workqueues and can delay other work.

Table capacity is bounded; latency on allocator, policy, audit, native reference
and system-workqueue paths is not proven bounded. Instance-local refcounts and
the local lock can also contend among the instance's own threads. Background
execution, RCU and default-off status are not substitutes for measuring that
cost or for a proof of correct lifetime.
