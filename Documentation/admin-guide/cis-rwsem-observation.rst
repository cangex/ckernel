Bounded rwsem observation prototype
==================================

This is a disposable-VM observation facility, not a rwsem algorithm change.
CONFIG_CIS_OBSERVE adds a separately disabled cis_rwsem_state tracepoint to
the public non-RT rwsem API. No rw_semaphore layout or allocation changes,
owner-pointer dereferences, global owner table or fast-path atomic counter
are introduced. PREEMPT_RT has no event production. Disabled tracepoints
retain static-key checks; that is not a claim of zero instruction cost.

The source records initialization, acquire entry, successful acquisition,
abort, try outcome, release entry, downgrade and non-owner API use. Read
acquisition records name the actual executing task, never the single
rwsem->owner debug value. Acquired-to-release-entry is an interior interval:
the source does not claim to time the unlock instruction or all spinning.
Descheduling while the lock is held remains part of wall time.

The non-owner API is out of line when observation is configured, including
without lockdep. Otherwise its historical alias to down_read/up_read would
misidentify an anonymous reader as an ordinary task-owned read hold. It
retains native lock semantics and does not add ownership enforcement.

The collector opens at most 64 object watches from a registered target's
initialization/acquire attempt; only watched objects emit downstream
records. The source callback still runs at every enabled API hook, so entry
cost and source recursion must be measured, not hidden behind filtering.
Each watch has at most 1024 emitted records. Capacity overflow rejects the
capture's relationship evidence. No watch eviction hides address reuse.

E2 requires initialization observed in this capture. Static or pre-window
objects may yield E1 intervals but no lifetime-certified holder relation.
The analysis retains at most eight simultaneously observed readers. A
non-owner call or reader overflow disables E2 for that lifetime. It never
advertises a complete reader census. Task identity includes start time;
release execution identity and acquired identity are separate on migration.

Initialization timestamp is an observed source event, not a watch-creation
timestamp. Reinitialization partitions relationships. Invalid reinitializing
of a still-held rwsem is outside Linux's supported semantics and must not
be used as a synthetic positive case. Concurrent changes in registration,
missed callbacks, loss and unknown actors retain explicit quality limits.

Implementation alone is not runtime acceptance. The required fixture covers
write/read, write/write, write/multiple readers, private objects, non-owner,
try failure, abort, downgrade, address reuse, pre-window ownership, reader
capacity and sleeping/preempted holders. All require independent operation
timestamps and three fixed rounds before claiming the supported closure.
