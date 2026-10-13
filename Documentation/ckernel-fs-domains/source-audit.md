# Same-filesystem domain: source audit and implementation gate

Source: 622eeb9a4278d53debcdcdb8f49b816be45f9a15, tree
90bda14c1a6dcc2df4ae12c28fa4e0ff82f2fbd8. No kernel behavior change in this task.
This is an intermediate F3 audit, not a claim of F3/F4 completion.

## What the current code actually protects

| Fixed source reference | Meaning for a domain design |
| --- | --- |
| fs/ext4/ext4_jbd2.c:90, __ext4_journal_start_sb | Operations select the superblock journal. An inode argument exists on this wrapper, but it is not a ready-made container ownership contract. |
| fs/jbd2/transaction.c:236, add_transaction_credits | Adding credits is a reservation against a transaction-wide hard capacity, not just statistics. Rollback at243 and log-space handling at276 are part of admission. |
| fs/jbd2/transaction.c:265 | Log space must be available before dirtying checkpointed buffers; forcing checkpoint from commit can deadlock. |
| fs/jbd2/transaction.c:293 | Reserved credits are separately bounded; they cannot be replaced by unconstrained per-domain counters. |
| fs/jbd2/transaction.c:364, start_this_handle | j_state_lock must cover the admission-to-t_updates publication boundary in the existing protocol. |
| fs/jbd2/transaction.c:370,382,423 | Abort/error, barrier, and transaction switch checks are distinct. Reserved handles may proceed in cases where blocking them could deadlock writeback. |
| fs/jbd2/transaction.c:435,439 | The handle gets a transaction and is counted as an in-flight update before the state lock is released. |
| fs/jbd2/transaction.c:701, stop_this_handle | Credit/revoke return and update decrement belong to handle completion, not container exit. |
| fs/jbd2/transaction.c:820, jbd2_journal_wait_updates | Commit/barrier waits for updates; after dropping the state lock it must retrieve the running transaction again because the old transaction can be freed. |
| fs/jbd2/transaction.c:863, jbd2_journal_lock_updates | Stops normal admission and drains reserved handles and active updates before the barrier is established. |
| fs/jbd2/transaction.c:1152, jbd2_write_access_granted | Native code already has an RCU-assisted write-access fast path with identity/order checks; a new domain must not claim every write always takes the slow locks. |
| fs/jbd2/commit.c:440,453,456 | Commit moves to T_LOCKED, waits for updates, then T_SWITCH. A new domain protocol must integrate with these transitions. |

The historical two-filesystem result supports investigating this subsystem,
but it does not apportion the business gain between admission, metadata-block
coordination, allocation layout, journals, or cache locality.

## Compared alternatives

| Alternative | Coordination it could reduce | Still shared / additional cost | Decision now |
| --- | --- | --- | --- |
| A0: cgroup tag plus unchanged JBD2 start/stop | None of the original admission lock/credit/update operations | Adds lookup, lifetime and memory cost | Reject as an optimization design. |
| A1: precharged bounded credit leases plus transaction-scoped domain admission/drain | Potentially amortizes global credit updates and in-flight publication across safe local admissions | Epoch transitions, error/barrier checks, depleted credits, reserved handles, metadata blocks, commit and device remain shared | Only candidate retained for protocol study; NOT admitted to kernel implementation yet. |
| B: multiple transaction/allocation domains within one ext4 | Could separate more journal/transaction and allocation state | Shared bitmap/inode-table blocks, cross-domain links/rename, ordered data, global free-space accounting and crash replay require coordination | Not a minimal safe patch under current evidence. Do not implement independent journals merely from directory ownership. |

## A1 required protocol, not implemented ABI

Owner key must include registered root-cgroup identity and generation, and
filesystem identity. Directory admission establishes eligibility but does not
make all underlying metadata blocks private. Existing operations/objects retain
their original ownership when tasks migrate or FDs are transferred; an async
worker's current cgroup cannot supply an old object's owner.

The control lifecycle would be CONFIGURED -> ACTIVE -> REVOKING -> DRAINING ->
DEAD. Transaction-local leases have a separate epoch and are retired on every
relevant transaction transition, not only when the container exits. Allocate
bounded state on demand; a global owner lock per handle is not acceptable.

Credits must be charged globally BEFORE being handed to a domain. Local use,
unspent balance, consumed credits and returned credits must conserve the total,
including revoke reservations and log-space requirements. Private capacity
checks against the same global limit independently do not preserve this rule.

A normal local start requires a protocol proving that no barrier, abort, switch
or revoke can race between eligibility and publication. Commit must close local
admission, synchronize publication, return unused leases and drain active
handles in a safe order. An idle lease cannot remain a permanent t_updates pin
that is released only after wait_updates succeeds. Nested handles, restart,
extend, reserved handles, failure rollback and synchronous fsync all need
explicit treatment. Holding a domain lock across native sleeping paths is not
an acceptable shortcut.

Metadata blocks keep native buffer/transaction ownership. Different private
directories may still update the same bitmap or inode-table block. b_state_lock,
j_list_lock, frozen data, revoke and ordered-data dependencies are not removed
by attaching a cgroup label. Shared files/cross-domain operations require a
defined native/coordinated path without creating a second inode or block copy.

## Concrete rejected shortcuts

`test_admission_protocol.py` contains bounded illustrative counterexamples:
late publication can let commit observe zero while a local handle remains;
an idle update pin can prevent drain forever; independent local limits can
over-issue credits. It also checks arithmetic conservation of precharged leases.
These are sequential abstract models, NOT weak-memory proofs or kernel tests.
Passing these models alone does not authorize claiming crash consistency.

## Shared-path reentry

| Trigger | Context | Public resource / wait | Scope and source basis |
| --- | --- | --- | --- |
| Lease refill or no credits | Calling task | Transaction credit accounting, journal-space/commit wait | All domains on the journal; transaction.c:236,276. |
| Commit/barrier/transaction switch | Caller and commit thread | j_state_lock, reserved-credit and update drain | All domains on the filesystem journal; transaction.c:382,423,863. |
| Metadata block shared across directories | Calling task / writeback | Existing journal-head state and journal list coordination; possible shadow-buffer wait | Users of the actual block/journal, not necessarily all containers. |
| Async ordered data/reclaim or handle restart | Original handle/object context must be retained | Native writeback, reservation and restart paths | Cannot infer owner from worker; exact additional domain binding remains to be designed. |
| Revoke, exit, unmount or abort | Control / filesystem lifecycle | Stop new admission, finish outstanding updates, release leases and references | Bounded state does not imply bounded waiting time. |

## Gate before a hot-path patch

1. Finish matched 1/2/4/24 filesystem Go comparison with actual geometry and cost.
2. Establish whether admission remains important in this matched backend; no
   need to force an exact business loss percentage, but labels alone are not evidence.
3. Define and test publication/closure ordering under Linux's memory model,
   reserved handles and all commit/barrier entry points. Specify fallback and
   reference ownership through errors and asynchronous completion.
4. Only then freeze A1's actual structure/API changes and build a default-off
   implementation. fs/ext4/ext4_jbd2.c, include/linux/jbd2.h,
   fs/jbd2/transaction.c and fs/jbd2/commit.c are integration candidates, not an
   approved complete file inventory. Audit journal teardown/recovery too.

F4 kernel implementation and crash recovery tests: NOT_RUN. No production or
baremetal deployment requested by this intermediate audit. F2 capacity is being
addressed by authorized cleanup, not by changing the workload or storage medium.
