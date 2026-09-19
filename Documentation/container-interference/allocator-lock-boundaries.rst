Allocator node-lock observation boundaries
=========================================

Earlier captures have NODE_WAIT before spin_lock_irqsave, NODE_HELD after
acquisition, and NODE_DONE after spin_unlock_irqrestore.  The HELD-to-DONE
duration includes unlock and may include post-unlock scheduling.  Old data
must not be reinterpreted as an exact held interval or used to invent a holder.

An appended NODE_RELEASE stage, number 21, records the selected allocation
path immediately before unlock.  The old stage numbers, event layout and
end-of-call marker remain unchanged.  Bounded BPF admission, source sampling,
recursion checks and ordinal/capacity rejection still apply.  The extra event
does not acquire a new global lock, allocate memory or collect a new stack.

For new complete sequences the reader partitions:

* WAIT to HELD: acquisition bracket, including source overhead;
* HELD to RELEASE: an inner interval known to execute while holding the lock;
* RELEASE to DONE: release observation and unlock, potentially scheduling.

These intervals must use the same lock address.  Missing, duplicate or
changed-object boundaries reject the call.  Nested slow/partial intervals
are not added again to the exclusive partition.  Mixed old/new sequences in
one call are rejected rather than silently treating old boundaries as new.

The inner bracket excludes acquisition-side observer execution before HELD
and includes some observer execution before RELEASE; it is neither complete
hold time nor application work alone.  Its actor is the allocation executor.
This patch is a prerequisite for a selected-node-lock relation, not complete
SLUB lock holder coverage.  Other allocation/free/shrink users, object
lifetimes, sampling gaps and source completeness still need explicit handling
before a competing-container statement is accepted.

New Image/module and runtime evidence are required.  Passing old captures or
unit fixtures alone does not validate this newly inserted kernel event.
