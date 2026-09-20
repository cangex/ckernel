Y4 public I/O pressure additions
===============================

Status: PASS_SCOPED for the bounded implementation and isolated runtime cases
in y4-validation-20260920.rst. Complete tag occupancy, causal blockers and Y7
combined overhead are not accepted by that result.

The existing bounded block collector retains request submitter, issue-local
bio billing, writeback executor and writeback memcg separately. Two additions
make public resource relationships more concrete without inventing blockers.

At an observed request issue, record at most two actual tag assignments: driver
and scheduler pool, normal/reserved bitmap, tag and current capacity. Associate
only with a closed observed issue from the same request epoch. A point inside
an observed wait on the same queue, bitmap and device establishes a concurrent
resource relation. It is not an allocation-to-release tag lifetime, total pool
occupancy or proof that the issuing container caused the wait. No owner map or
scan over all requests/tags is introduced. The existing bounded request and
target admission still applies. All source entries and emitted extra records
remain subject to the capture budget.

A native disabled-by-default tracepoint brackets the actual io_schedule_timeout
in balance_dirty_pages. It records native decision context and a closed wall
interval, including scheduling and observer cost, not exclusive I/O sleep.
The BDP_ASYNC rejection branch does not become a fabricated sleep. Start/end
cgroup must agree and both endpoints must lie in the selected window. WB
accounting ownership is not renamed to the paused task, unique dirtier or
blocking container. No record is produced for a pause not completed before
detachment; this remains an explicit coverage limit.

Offline associations have fixed record and relation limits. An invalid or
overflowed relation set is rejected rather than silently truncated to favorable
examples. Tag capacity changes, request reuse, private pools, timing mismatch
and unknown WB ownership have negative unit cases. Runtime validation requires
independent private-file writers on same and separate disposable devices,
actual dirty throttling, tag pressure, OFF checks and cleanup before acceptance.

The source snapshot protocol advances to version 18 with wb_pause. These
changes do not accept Y4 performance or Y7 combined costs, nor expand old
validation claims to the changed block collector.
