X3 allocator entry audit, not implementation acceptance
=======================================================

This is a fixed-source audit at 8f9540252. No allocator collector has yet
been loaded or validated. X2 evidence does not certify X3. Existing SLUB
or Maple algorithms must not change as a shortcut to observation.

Required separation
-------------------

* lib/maple_tree.c:160--201 has mt_alloc_one/bulk, mt_free_one/bulk,
  mt_free_rcu and ma_free_rcu. Single allocation goes to kmem_cache_alloc;
  bulk does not necessarily produce its single-object tracepoint. RCU
  execution current is not the original allocating container.
* mm/slub.c:3344--3416 selects a CPU freelist operation or __slab_alloc.
  A successful allocation alone does not identify which branch was taken.
  A failed CPU compare/exchange is not proof of another container's access.
* mm/slub.c:3077--3340 has ___slab_alloc/__slab_alloc, CPU partial retrieval,
  node partial retrieval and new_slab. Slow-path wall time is not one lock's
  wait time and can include nested allocation, accounting and preemption.
* get_partial_node at mm/slub.c:2275 uses a particular kmem_cache_node's
  list_lock (2292--2327). This is not a host-global lock on every allocation.
  Other users and release sites need coverage before a holder set is complete.
* mm/slub.c:3926--4071 contains bulk release/allocation. Allocation failure
  can free an already allocated prefix. Requested, successful and rolled-back
  object counts must remain separate. No synthetic single-allocation events
  should be inferred for unobserved elements.

Existing event limitations
--------------------------

include/trace/events/kmem.h's kmem_cache_alloc receives call_site, pointer,
cache, GFP flags and requested node after allocation. It has no begin time,
CPU-partial/node-partial branch or lock owner. kmem_cache_free reports the
freeing executor, not allocation owner. Requested NUMA_NO_NODE is not an
observed physical node. A NULL result must remain a failed allocation.

Therefore attaching only these two events would deliver allocation/free
facts, not the approved phase attribution. Cache address equality is not
object ownership, common-node-lock identity or cache-line contention.

Next implementation slices
--------------------------

1. An independent default-off, cache-selected observer must identify one
   bounded sampled allocation with begin/end and explicitly visited stages.
   Use task identity across migration; nested allocations need bounded
   nesting or a visible truncation result, not a guessed parent.
2. Add minimal stage events only where native events lack information.
   Preserve GFP, memcg, NUMA, fast/slow and failure semantics. Do not add a
   sleeping operation, allocation or global map lock inside a SLUB lock.
3. Keep synchronous allocation attribution separate from sample-lifetime
   tracking for cross-CPU/RCU free. The latter needs a sampled allocation
   generation and complete corresponding release observation, not current.
4. A node-list wait observation can be E1 without an owner. E2 requires all
   relevant acquisition, release and lifetime paths; unfinished X1 coverage
   cannot be silently imported as proof. Generic slab or page-allocation
   latency must not be labelled as blocking by a particular container.
5. Independently verify local hit, cold start, private cache, shared cache/
   node, partial refill, page pressure, bulk failure, migration and RCU free,
   followed by an ordinary container mmap/munmap bridge. Nested intervals
   need union/exclusive accounting, never summation as total cost.

The first native counter bridge shows a real VMA/THP/memcg allocation path,
but its stacks and 1/64 counter samples cannot fill the missing allocator
stage, ownership or latency evidence.
