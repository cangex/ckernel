Maple allocation context, not inferred tree ownership
====================================================

``allocator`` adds an opt-in raw tracepoint around the native Maple single and
bulk allocation wrappers. Normal allocation, failure rollback, tree copying,
node layout, locking and RCU disposal remain unchanged. The copy path records
the destination tree, not the source tree. Disabled observation uses static
keys; the standalone user-space Maple tests retain a no-op interface.

While active, a 256-entry task/start keyed BPF map holds a bounded wrapper
context. A sampled SLUB begin can join only one matching cache, operation,
GFP mask, request count and requesting identity. The exact native wrapper
token must close that context. Nesting, a second backend, missing boundaries,
map capacity failure and mismatched fields cannot create a tree association.
Only brackets with an observed backend are exported. There are nevertheless
two source callbacks per eligible Maple allocation, even at low SLUB sampling
frequency; the source audit v5 counts these calls and their callback CPU time.
That timer excludes filtering/preemption wrappers and can include IRQ time;
it is neither total observer CPU cost nor a hard latency bound.

The report distinguishes destination tree, returned node and shared SLUB
cache addresses. It joins an accepted backend call by task identity and call
token, not nearest timestamps or the freeing task's current mm. Existing
node lifetime records carry this original allocation context into release.
Release entry is still not backend free completion or a measured RCU grace
period. The producer adds no global owner table and no reference to the tree.

The tree is valid inside the allocation bracket under native caller rules.
There is deliberately no claim that equal tree addresses across brackets
denote one lifetime, that allocated nodes were installed, or that the requester
exclusively owns the tree. A caller can preallocate or fail later. Shared cache
use does not prove shared-lock contention. The separate observed SLUB lock
collector is required for supported holder/waiter evidence.

Old captures use the immutable prior collector contract. Loading a new live
session requires the added map and program; a missing source is not silently
accepted. Unit tests are not runtime/coverage acceptance. VM tests and source
hashes must accompany any claim about actual collection.
