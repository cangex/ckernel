Socket ownership and native-equivalent qualification (M6)
========================================================

Status
------

This is a default-disabled development candidate. Compilation, lifecycle
validation, and performance acceptance are separate statuses. Consult the
validation record for actual evidence; this design does not establish a
latency or isolation guarantee. Maple remains disabled in these tests.

Scope and native paths
----------------------

The existing LSM dispatch enters ``apparmor_socket_sendmsg/recvmsg`` and then
``aa_sock_msg_perm -> aa_sk_perm -> aa_label_sk_perm`` for INET sockets.
Native AppArmor permits unconfined subjects immediately, and
``aa_profile_af_perm`` also returns before policy evaluation when a profile's
first ruleset has no ``AA_CLASS_NET`` mediation. M6 reuses only these existing
early-return qualifications. A mediated allow, audit, or deny is never cached.
The complete LSM dispatch, native file/socket permission checks, secmark,
protocol state, packet allocation, and queues are unchanged.

``CONFIG_CKERNEL_M_NET`` is independent of the M4 build switch, but follows its
immutable-label validity protocol. ``CKM_FEATURE_NET`` requests 64 fixed record
slots at instance creation; ``CKM_IOC_NET_QUERY`` is the versioned diagnostic
ABI. The device/instance-handle permission checks remain Core's. A cookie or
socket address identifies an object, not an authorization credential.

Creation, ownership and use
--------------------------

The accounted instance state contains 16 RCU hash buckets, 64 embedded records,
an irq-safe local lock and per-CPU counters. Generic ``sock`` and ``aa_sk_ctx``
layouts and native socket allocation sizes do not grow. There is no separately
allocated object, owner-index lock, global counter update, or allocation per
message. Enrollment may fail explicitly if management-state allocation fails;
optional recording later may not make a native socket operation fail.

After native ``socket_post_create`` succeeds, a supported user INET/INET6
stream/datagram socket is recorded in its creator's ACTIVE, compatible instance.
A record holds that instance, creator credentials and current AppArmor label.
Stacked profiles must all satisfy the native early-return predicate for its
qualification bit to be set. No result is learned from a transferred unknown
socket or from an arbitrary native success.

Native ``sk_clone_security`` locates the listener's recorded owner through a
read-only RCU registry. It does not infer ownership from interrupt ``current``.
Each recorded clone takes its own owner/credential/label references. Full or
contended inventory means native handling, not failed creation or accept.

Send/receive first check only current's instance-local hash. A fast result needs
the original instance, compatible default cgroup, exact creator credentials,
unchanged objective/subjective credentials, matching network namespace, the
same non-stale raw label, supported family/type and ACTIVE state. Only exact
send/receive requests are eligible. A policy replacement, exec, credential or
namespace change, transferred FD, unsupported operation or record miss executes
the original code, including native label refresh and audit/denial. The final
state check rejects observed revocation. As in native AppArmor, an operation
already using a valid label can overlap a policy update; no stronger revocation
linearizability is claimed.

In this OLK baseline an ordinary non-CLONE_THREAD fork invokes prepare_creds
from copy_creds. Even unchanged UID/profile contents do not preserve exact
credential identity. Such a child retains the recorded socket owner but uses
native permission handling; exec then also remains native for that old socket.
Object inheritance is not automatic permission-cache eligibility.

Close and retirement
--------------------

``sk_free_security`` looks up the immutable original owner, removes the record
under its local lock and queues the embedded RCU callback. Socket address reuse
is safe because removal precedes native free, and a record slot cannot be
reused while old readers exist. The callback never dereferences the socket.
It releases the credential/label roots, returns the slot, and drops the owner
reference as its final action. Native socket references, FD sharing, TCP close
and asynchronous native destruction remain authoritative.

Revoke forbids new records and fast decisions, but does not free live records
or copy a shared connection. Transferred sockets can retain a stopped instance
after all original tasks/handles exit. Final Core work removes the registry
entry, waits for registry readers without the local lock and releases state.
This is necessary lifetime retention, not an assertion of immediate reclaim.

Costs, capacity and shared reentry
---------------------------------

* State and per-CPU counters use ``GFP_KERNEL_ACCOUNT``. Socket/protocol charges
  stay native. Live, retiring and free slots share a fixed budget of 64. Held
  credential/policy roots can retain larger existing graphs; 64 is not a bound
  on their transitive bytes. ``management_bytes`` reports logical payload and
  excludes Core, slab rounding and retained external graphs.
* Creation/clone scans up to 64 slots under a local trylock and updates native
  reference counts. No allocator runs under that lock. There may be contention
  within an instance; shortage and contention fall back without new failure.
* A message adds local lookup and eligibility checks. Native unconfined checks
  are already cheap, so positive performance is not assumed. Per-CPU diagnostic
  counters are snapshots, not transactionally consistent multi-field totals.
* Ownerless clone/free scans the RCU list of up to Core's 256 live instances and
  their local buckets, including for unrelated sockets. This O(instances) cost
  is deliberate and must be measured on nonparticipants. No host owner lock is
  taken per socket, but read traffic and RCU duration are not free.
* Free takes the original owner's local lock and queues native RCU callbacks.
  Final release uses the shared system workqueue, a registry update mutex and
  ``synchronize_rcu``. Grace periods, task stalls, queue contention, slab release
  and policy destruction can affect others. Bounded records do not bound time.

This stage does not localize TCP locks, backlog, skb allocation/free, softirq,
the device or its queues. It does not prove complete network isolation and does
not attribute file-domain gains to the network domain.

Required validation
-------------------

The native fixture must first demonstrate real TCP/UDP allow, deny and audit on
the exact kernel/policy ABI. Tests cover unmediated and mediated paths, policy
replacement, stacked denial, credentials, fork/exec, SCM_RIGHTS, accepted
clones, address/FD reuse, revoke with live sockets, abandoned owners, CPU/cgroup
and network-namespace migration, pressure, failure injection and batch exits.
Core-only and all-off kernels run native semantics without treating ABI absence
as a success for feature tests. Configuration builds and runtime are recorded
separately. Same-kernel performance includes cold, steady, exhausted, migrated
and revoked instances, target/bystander roles and paced arrivals. Unmeasured
pressure or exit tails remain explicit gaps, not implied by correctness tests.
