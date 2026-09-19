Block merge provenance prototype
================================

The version 11 source contract adds block_merge_link.  It observes successful
request/bio merge decisions before the native byte/bio transfer.  It neither
changes merge eligibility nor bypasses blk_cgroup_mergeable.  A disabled source
adds a tracepoint static-key check, not a clock read or a bio-list walk.

The block collector retains at most 256 request episodes.  A request address is
paired with its observed block_io_start timestamp; request start_time_ns is not
used as a generation because the native merge path may change that timestamp.
The merge event names the survivor and, when observed, the victim's episode.
An unobserved victim remains unknown, not a guessed owner.  Bio front/back and
discard merges have no victim request.  A transfer is not a data completion.

At each issue the collector walks no more than eight bios and thirty-two cgroup
ancestors per bio.  This runs only for a watched, admitted request.  Remaining
bytes are grouped by observed bio blkcg, separately from the original submitter
and completion executor.  Unregistered, over-depth and ninth-or-later bios are
explicit unknown bytes.  A retry yields another snapshot, not new submitted
bytes.  The collector does not track all bio allocations or infer bio lifetimes
from addresses.  Per-request snapshots are valid only at the observed issue.

Analysis rejects missing issue snapshots, invalid or reused episodes, duplicate
indices, inconsistent bio totals, malformed transfer links and byte-ledger
violations.  Merges before the window, remaps and unobserved origins are not
silently completed.  Historical contracts remain read-only compatible; live
admission requires the new program inventory.  Data loss or scope failure
suppresses the resulting relations.  No relation identifies a device blocker.

Bounded walks, output buffers and maps do not prove a total CPU or memory cost.
Runtime overhead, cleanup and independent merge truth must be measured on the
new kernel/tools before declaring the new coverage validated.  Buffered
writeback and complete dirtying provenance are not provided by these records.

Independent test devices
------------------------

Only the disposable VM may load cis_block_fixture.  Its merge modes submit real
bios under a native plug, retaining pages/bios until endio.  Driver dispatch
records request addresses, bio counts, bytes and timing independently of the
Profile stream.  Data is read back from the private in-memory device and checked.

Mode 3 checks two adjacent bios, reverse-order front merges, nonadjacent bios,
and nine-bio overflow.  The last case must report one bio's bytes as unknown,
not attribute them to the caller.  Mode 4 selects mq-deadline only on the two
test devices and submits sectors in 0,2,1 block order.  The bridge closes the
gap between two requests: one bio append plus one request-to-request transfer.
The verifier requires both watched episodes, the victim's merge terminal, the
survivor's driver dispatch and all completed bytes.  A nonadjacent control must
remain separate.  Each cohort uses two registered container roots and three
alternating OFF/ON pairs.  No cross-blkcg merge restriction is disabled.

These tests do not establish production device saturation, writeback dirtying
ownership, or a unique blocking tenant.  Queue and service intervals remain
wall time.  The request source and fixture/tool commits are recorded separately
from the immutable Image hash.  The offline evidence index may hold up to 64
cohorts; this does not increase any live target, event, CPU or memory budget.
