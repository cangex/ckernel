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
