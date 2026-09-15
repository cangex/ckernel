.. SPDX-License-Identifier: GPL-2.0

==========================
Shared-path reentry ledger
==========================

CPU hit
  Business task; local multi-owner slot lock and cpuset/cgroup checks.
  No backend allocation, but zeroing and lookup remain. Same-CPU tasks
  serialize briefly. Slot capacity bounds retained nodes, not wait time.

CPU miss, NUMA hit
  Business task; instance/NUMA list lock, up to 32 entries to inspect.
  Other tasks in the same instance/NUMA can wait on this lock. Different
  instances do not use that pool lock, but still share cache/CPU resources.

Pool miss or unsupported allocation
  Business task returns to kmem_cache_alloc or kmem_cache_alloc_bulk and native page allocation,
  cpuset validation, memcg charge/reclaim as required by GFP. Reclaim and
  ancestor accounting can affect other containers. No bounded wait claim.
  A delegated bulk suffix is handled in one native batch, without repeating
  eligibility and inventory admission for every remaining node. Detailed
  reasons and unchecked suffix requests are recorded separately.

New tracked node
  Business task; bounded reservation, accounted metadata allocation,
  optional objcg charge, sparse pool XArray and shared hash-bucket update.
  This is not a communication-free private fast path. Failed optional
  tracking uses native allocation without manufacturing a pool record.

Node release, pool full/revoked
  Original free context, sometimes an RCU callback; hash removal, SLUB
  free, possible memcg uncharge. No pool lock spans backend free. Side
  metadata remains pinned until another RCU grace period completes.

Revoke
  Initiator atomically disables admission; a worker locks each CPU's short
  slot array in turn, then the instance's sparse NUMA lists. It does not
  broadcast synchronous IPIs. Backend releases are outside locks, with
  rescheduling in the worker. Remote slot locks and reclaim still have
  shared effects. Outstanding borrowers/RCU callbacks delay final release.

CPU offline
  CPU-hotplug callback disables local return and drains at most eight
  cached nodes. Each returns to its owner/NUMA or the native allocator.
  Hotplug itself is a global operation; this callback is not a guarantee
  that other instances never wait.

Query and final release
  Query holds an instance record-list lock for a bounded-size traversal,
  but snapshots across CPU/pool counters are not atomic. Final release is
  workqueue context, after references end: cgroup/objcg/percpu metadata and
  XArray destruction use native infrastructure. Async is not zero-cost.

Evidence requirement
  Source describes triggers and contexts. Runtime counts and latency must
  come from the separate validation results. This table does not claim
  that any path is nonblocking or that four-domain isolation was completed.
