# F3 decision: no same-filesystem hot-path admission in this iteration

## Scope and result

This is a resource-specific design decision, not a claim that intra-filesystem
domains are impossible. The reviewed source is OLK snapshot
`622eeb9a4278d53debcdcdb8f49b816be45f9a15`. Running experiments use the explicitly
identified observation kernel. There is no new kernel behavior patch.

The two alternatives required by the task have been compared. A shared-journal
credit/admission domain is the smaller research candidate, but no safe and
effective minimal implementation is admitted now. A deeper multi-journal
design is rejected as the first patch. Therefore F4 kernel construction,
crash testing and F5 OFF/Core-only/full-mechanism performance comparisons are
NOT_RUN, not PASS. Do not manufacture those rows from scheme-one results.

## Why a container label is insufficient

Native `start_this_handle()` holds `j_state_lock` from transaction selection
through publication of `t_updates` (transaction.c:364-445). It also reserves
real journal capacity, with overflow rollback and log-space waits
(transaction.c:236-304). `stop_this_handle()` returns remaining credits and
decrements the update count (transaction.c:701-744). Commit and barriers need
the true set of active handles, not a delayed statistical approximation
(transaction.c:820-879; commit.c:440-456).

Adding a root-cgroup ID before the same operations removes none of these
coordination operations. Returning to the original path for every handle
while incrementing another domain counter is extra work, not an optimization.

## Smaller candidate A: precharged transaction-epoch leases

The only retained direction would charge a bounded credit batch to the real
transaction before local consumption, associate it with a stable filesystem /
registered-cgroup-generation / transaction epoch, and track in-flight use
locally. The lease, not release-time `current`, would carry responsibility.
Unused credits, active handles, consumed metadata credits, revokes and returned
credits must remain conserved. Multiple containers cannot each treat the whole
journal limit as their own allowance.

This could amortize global credit and update-counter modifications **only if**
local admission can safely overlap transaction closure without taking the
original global lock each time. That replacement protocol is the missing core,
not an incidental implementation detail. Specifically:

1. Closure must exclude new local admissions and observe all earlier ones.
   Reading an epoch, dropping a lock, then publishing an active handle permits
   commit to observe zero prematurely.
2. Pinning `t_updates` for every idle lease does not solve closure. Waiting for
   zero before recalling those pins can deadlock. Recall must close admission
   and reconcile leases before the appropriate drain, while preserving existing
   reserved-handle exceptions needed by writeback.
3. Reserved handles can enter some locked transactions, but not T_SWITCH
   (transaction.c:382-427). Treating normal and reserved handles identically can
   deadlock or allow an update after commit stops waiting.
4. Restart detaches a handle and may encounter a freed transaction; the native
   drain loop explicitly re-fetches the running transaction after sleeping
   (transaction.c:764-848). Domain references need an independently proved
   lifetime and fallback protocol through restart, abort, unmount and revoke.
5. Local admission does not make bitmap, inode-table or journal-head state
   private. Native metadata-write and ordered-data dependencies remain.

The six bounded protocol tests preserve concrete counterexamples, not a
memory-model proof. No new public ABI or field layout is frozen in lieu of
that missing protocol. In particular, no permission, persistence, ENOSPC or
credit check is removed to make the prototype look effective.

## Deeper candidate B: transaction/allocation partitioning

Independent directories can still modify one bitmap or inode-table block.
Splitting durable transactions would need rules for block ownership, shared
files, hardlinks, cross-domain rename, ordered data, revoke and crash replay.
Splitting journals by directory alone is not such a protocol. A format-neutral
implementation may be possible, but none is established by this audit.

The prototype budget also matters: separate filesystems preserve total journal
space, so each journal is smaller. This changes transaction sizing, batching,
allocation state and cache locality together. Any observed runtime improvement
does not isolate the cost of one JBD2 lock or prove candidate A would reproduce it.

## Lifecycle and shared-path reentry

| Trigger | Owner / execution | Shared coordination and cost | Decision |
| --- | --- | --- | --- |
| Register directory/domain | Stable filesystem and registered root-cgroup generation | Eligibility, namespace/object consistency, bounded allocations | Design only; no automatic ownership inferred from directory names |
| Local lease admission | Calling task with retained transaction-epoch reference | Must synchronize with closure/abort without a new central lock per operation | Missing protocol; not enabled |
| Depletion or unsupported operation | Calling task | Original journal lock, credits, log-space/commit wait | Required safe fallback, not zero interference |
| Commit, fsync, freeze, barrier | Calling task / journal thread | Close admission, reconcile unused reservations, drain real updates | Cannot defer or omit for performance |
| Shared metadata or cross-domain operation | Original object/handle owner | Native block/journal-head/list and ordered-data coordination | Remains shared |
| Task migration, FD transfer, async work | Original retained owner, not worker/current | Stable references until completion | Unimplemented binding protocol |
| Revoke/exit/unmount/abort | Control and journal lifecycle | Stop borrowing, drain active and reserved work, free state after last reference | Bounded state does not bound wait time |

## Closure rule

Finish the already frozen scheme-one formal comparison and cost report. Report
its runtime evidence independently from net-benefit qualification. Do not
silently expand into a new filesystem project or claim the complete two-scheme
implementation is delivered. Reopening candidate A requires a concrete
publication/closure proof, coverage of the listed exceptions, and evidence
that this coordination remains worth changing relative to the native split-FS
alternative. No host deployment is requested by this design decision.
