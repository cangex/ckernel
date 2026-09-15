.. SPDX-License-Identifier: GPL-2.0

CKernel-M Maple ownership contract (M2 prototype)
================================================

This design precedes the experimental implementation.  It changes neither
the Maple node layout nor the authoritative contents of an mm's tree.

Scope and attachment
--------------------
Only a newly initialized mm belonging to an explicitly bound task may hold
an instance reference in its Maple tree.  Binding a task never relabels its
existing mm.  Exec and fork create new mm contexts; CLONE_VM shares the
existing context.  Incompatible execution, cgroup, memory policy, GFP or
NUMA conditions retain native allocation.  A task cookie is not authority.

Node provenance
---------------
An optional side record is registered before a new pooled node can enter
the Maple tree.  It holds the node address, owning instance, allocation
class, NUMA node and any supplemental objcg charge.  Records remain stable
while nodes are live or cached.  A read-mostly address index finds records
from native free callbacks; it is not a free-list or a shared hot-path
allocation lock.  Registration/removal still write shared index state and
are explicitly a reentry cost.  Missing records mean native ownership.

Alternatives and costs
----------------------
Extending struct maple_node would enlarge a heavily aligned structure for
all users; embedding a wrapper would require reliable allocator identity
at every free site.  Side records avoid both layout changes, at the cost
of an extra allocation, index lookup, index storage and accounting.  This
is a measured prototype choice, not a claim of superior scalability.
The address index uses 4096 statically allocated hash buckets: it needs no
per-insert index allocation.  Per-node records are charged and bounded;
failure falls back before publishing a node.  Entries must never be
fabricated in an RCU callback.  Hash-chain traversal and bucket updates
are a shared cost, not a hard real-time bound.

Retirement and teardown
-----------------------
The original Maple reader exclusion and RCU callbacks remain authoritative.
Marking a node dead does not make it reusable.  Only an original safe free
site may return it to inventory.  A record carries its owner's reference
through asynchronous callbacks and tree teardown, regardless of current.
Revocation disables borrowing and drains idle nodes.  Borrowed/retiring
nodes hold references and are returned to the native allocator later.
CPU offline, full pools and incompatible memory policy also return nodes
through bounded drain paths.  No pool lock may enclose sleeping allocation,
RCU waits or a large batch of frees.

Accounting
----------
The fixed OLK maple_node cache is created without SLAB_ACCOUNT.  Allocations
with __GFP_ACCOUNT are charged by SLUB; other admitted inventory needs an
explicit objcg charge.  Never charge the same node twice.  Metadata and index
storage must also be charged to the creator, not a worker.  Cached memory
remains charged.  Only compatible charging identities may borrow nodes.
Charge failure must fall back to the unchanged native operation, not bypass
an existing native hard limit.  Root-memcg operation still has an instance
node cap.  Counters separate idle, borrowed and retired records; test the
conservation equation only at a quiescent snapshot.

The instance pool adds no promise of bounded latency.  Native SLUB, page
allocation, cpuset validation, memcg, RCU and address-index maintenance
remain shared.  A valid prototype must report these costs and compare
against native SLUB and an equal-budget cache before claiming isolation.
