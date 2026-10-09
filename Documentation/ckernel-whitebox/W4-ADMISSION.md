# W4 bounded admission decision

Status: EVIDENCE_INSUFFICIENT_FOR_SAFE_PATCH. No journal, writeback or block
behavior patch is admitted. This is not a claim that those resources cannot
be optimized. No host deployment has occurred.

## Actual evidence

The backend-r2 diagnostic binds the live ext4 journal list lock and block
device mapping private lock from the mounted `/business` filesystem. CORE
12-copy business windows contain 208 matched journal-list waits (0.258 ms
summed wall intervals across copies). Go contains 1046 observed pairs (0.975
ms), but two kretprobe misses make that collection incomplete. These sums
are neither CPU cycles nor a fraction of total business slowdown. There is
no complete journal-commit, dirty-throttle or request-queue latency
decomposition. Worker execution cgroup is not asserted to be the origin.

## Source review at fixed OLK tree

- `fs/jbd2/transaction.c:1553-1619`: dirty_metadata already avoids list-lock
  acquisition when the buffer is on the running transaction metadata list.
  The remaining list insertion changes shared transaction membership.
- `fs/jbd2/transaction.c:1646-1782`: forget coordinates current, committing
  and checkpoint transactions. Moving buffers without this synchronization
  can invalidate recovery ordering. No redundant lock-held operation was
  established by the current object samples.
- `mm/page-writeback.c:1691,1870-1945`: dirty balancing controls rates and
  waits against backing-device/memcg dirty budgets. Skipping the wait or
  postponing writeout would transfer pressure, not preserve the same test.
- `block/blk-mq-tag.c:135-216`: tag allocation already has fast allocation,
  queue kick, recheck and wait; migration updates queue identity and wakes
  old waiters. Private duplicated tags would overissue the shared capacity.
- `block/blk-wbt.c:601,664`: writeback throttling is a capacity/latency
  control, not proven redundant bookkeeping by these samples.

## Decision and limits

Retain native transaction/flush semantics, dirty limits and device queues.
Do not invent a W4 patch, claim removed interference, or rerun a Cython
matrix with an unchanged kernel to fill a result table. Earlier incomplete
Cython I/O evidence remains insufficient; CORE/Go VM evidence does not
replace it or establish a bare-metal device bottleneck. A future candidate
requires a specific removable software coordination cost and independent
correctness/recovery design. No unlimited new tracing campaign is opened.

W3 handles the separately identified buffer lookup lock. The 128-group,
128-lock ext4 bitmap sample alone does not establish avoidable hash
collisions or authorize changing allocation/bitmap consistency rules.
