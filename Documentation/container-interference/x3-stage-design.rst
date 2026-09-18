X3 allocation stages: first implementation slice
=================================================

Scope
-----

This slice instruments native SLUB single and bulk allocation. The exact cache
name is boot-selected (default maple_node); sampling selects one call per 64
eligible per-CPU entries. A sampled call carries a stack-local context through
the native helper chain, including migration and sleeping allocation. Neither
current on another CPU nor a per-CPU active-call pointer is used as its owner.
The context is not a Maple-tree identity or a persistent allocation owner.

Events cover pre/post hooks, CPU freelist success, slow helper, CPU partial,
node partial selection, the actual node-list lock attempt/acquisition/return,
new slab request/result, bulk element production, prefix rollback, KFENCE and
completion. The source emits at most 64 prefix stages plus END. Truncation
does not become a fabricated complete call. Requested node is separate from
observed slab node; unknown physical placement is -1.

What this does not prove
------------------------

Node-list WAIT to HELD is wall time around the native acquisition. It includes
observer entry, IRQ/preemption effects and uncontended acquisitions, not pure
spin time. No complete lock holder set is reconstructed: other acquisition
sites are not instrumented. Cache/lock addresses are within-window candidates,
not lifetime-qualified E2 objects. A shared cache alone is not interference.

Free, cross-CPU/RCU lifetime association, cache generations and ordinary
container/fixture acceptance are separate remaining slices. This commit is
not X3 completion and has no performance acceptance claim. Maple is identified
by actual allocation stack and selected cache, not by fabricated tree owners.

Safety and costs
----------------

The observer does not alter GFP, limits, memcg hooks, allocation order or
freelists. CONFIG is default-off and excludes SLUB_TINY and PREEMPT_RT.
The disabled inline source gate precedes out-of-line selection. While active,
each allocation entry pays the gate, a per-CPU counter and exact-name selection;
selected events pay timestamps, BPF and output. Per-call context and private
partial_context grow on stack. Audit exports five unsigned-long counters per
possible CPU, including capped stages. Counter snapshots are non-atomic.

No object allocation or sleeping lock is added by source hooks. Existing CIS
per-CPU recursion guard is shared with all adapters. A skipped recursive or
interrupt event remains visible and must not certify a complete capture.
Callbacks inside list_lock/local_lock regions extend those sections; actual
cost and shared collector maps need isolated runtime audit. The source clock
does not remove observer cost. Nested stage costs must use intervals or an
explicit exclusive partition, never sum parent and child durations.
