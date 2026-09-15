.. SPDX-License-Identifier: GPL-2.0

============================
CKernel-M ownership prototype
============================

This branch starts from the OLK snapshot commit
622eeb9a4278d53debcdcdb8f49b816be45f9a15, upstream
3832db9d09e243ef4a0ef969801c5ab689bdff64, tree
90bda14c1a6dcc2df4ae12c28fa4e0ff82f2fbd8. No old CKernel patch is applied.

Core
====

core.c owns refcounts, identity, asynchronous revoke/release work and the
ACTIVE -> REVOKING -> DRAINING -> DEAD transition. control.c validates the
versioned UAPI and host capabilities. task.c integrates dup_task_struct,
free_task, successful mm_init and __mmput after exit_mmap. There is no put
in __mmdrop or exit.c. Lazy-TLB references can retain the physical mm long
after its mappings vanish; the instance owns the tree lifecycle, not that
TLB lifetime. Failed task allocation before attachment owns no new reference;
later fork failures use the ordinary free_task unwind.

An attachment is immutable for a task lifetime. Binding an already shared
mm is rejected. Existing mappings keep their original allocator until a
new mm is created. Shared mm lifetime is independent of task association.
Last task release or last control-handle release initiates revocation, but
mm, node records and asynchronous work can keep the context alive. DEAD
is a terminal trace event immediately before release, not a queryable live
handle state. Revoke does not terminate tasks or reject ordinary syscalls.

Maple
=====

The only generic layout change is one pointer in struct maple_tree when
CONFIG_CKERNEL_M_MAPLE is enabled (eight bytes on the tested ARM64 ABI,
plus any containing-structure padding). struct maple_node is unchanged.
An owned mm's tree supplies provenance at allocation; release never uses
current to guess ownership. Side records preserve ownership across node
copying, task migration, deferred RCU free and native/pool node mixtures.

Allocation tries a matching CPU slot, then the same instance/NUMA list,
then native SLUB. Only a narrow GFP_KERNEL class, with optional ZERO and
ACCOUNT, is admitted. Custom task memory policy, active_memcg overrides,
disallowed nodes and incompatible cgroup/objcg identities fall back. New
objects are checked again after backend allocation, including the observed
charging memcg for accounted objects. Data and inventory are not copied
from another owner's live Maple tree.

Original Maple reader exclusion remains authoritative. Dead marks only
classify a record as retired. Actual reuse starts at original mt_free_one,
mt_free_bulk or the completed original RCU callback. Cached objects are
zeroed and KASAN-poisoned using the mempool hook; they are unpoisoned and
zeroed before reissue. This deliberate extra zeroing has a measurable cost.
Bulk allocation rolls back partial results; untracked frees still reach
native SLUB, with native nodes compacted for bulk backend release.

Inventory returns take a short CPU-slot or instance/NUMA lock. A full CPU
slot falls back to the owner's NUMA pool; full pools free to SLUB. The
global address hash has 4096 static buckets, RCU read lookup and per-bucket
update locks. It is not an isolation boundary or a latency guarantee.
Registration, backend release and node reservations write shared metadata.
They are not necessarily cold: sustained inventory misses can make them hot.

Revocation flips admission off, removes idle CPU slots and drains NUMA
lists in worker context with rescheduling between batches. It issues no
on_each_cpu broadcast and does not wait synchronously for all Maple RCU
readers. Original callbacks eventually release outstanding nodes; a second
RCU callback releases the side record and its owner reference. CPU offline
disables local return and moves idle nodes to their owner's pool or SLUB.

Accounting and unresolved validation
====================================

The OLK Maple cache is not SLAB_ACCOUNT. Nodes allocated with __GFP_ACCOUNT
retain SLUB's charge. Other admitted nodes get a supplemental charge to the
captured objcg; idle nodes stay charged. Side metadata uses accounted GFP,
never a refill kworker allocation. Charge failure drops the optional pool
attempt, then uses the unchanged native allocation semantics. It does not
permit a failed native hard-limit charge to pass.

Native accounting owns the charge of shared XArray bookkeeping; its first
allocator can differ from the later users of a shared internal index node.
The per-instance node cap is not a full byte-hard-limit for allocator and
index metadata. Concurrent administrative cgroup moves, memcg reparenting,
memory-pressure retention, all initialization/debug options and inactive
CPU races need explicit tests before production use. No shrinker or hard
reclaim deadline is promised in this first prototype.

Native SLUB already has CPU-local fast paths. This extra ownership layer
must beat an equal-memory-budget ordinary cache, including its metadata,
zeroing, validation and teardown, before an isolation benefit is claimed.
