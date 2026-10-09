# W3 draft: folio-local exclusion during block-buffer lookup

Status: built as an isolated experiment, not accepted for production. Actual
live mapping-lock identity was verified before launch. CORE business windows
showed 1343 matched intervals across 12 slots; summed wall time 1.559ms is not
a business slowdown contribution. Go had two kretprobe misses.

The fixed baseline fs/buffer.c:179-188 already documents this alternative; no
novelty claim is made. __find_get_block_slow gets a referenced blockdev folio,
then takes the whole device mapping's private_lock to prevent buffer removal
while walking its circular buffer list and taking the found buffer reference.

Draft: attempt folio_trylock once. On success, keep that folio locked across the
same unchanged walk/get_bh, then folio_unlock. On failure, use the original
mapping spinlock path. No sleeping lock acquisition, private buffer replicas,
changed I/O amount, changed filesystem, missing fsync or altered error result.

Safety audit must cover buffer attachment and try_to_free_buffers exclusion,
truncate/invalidation, existing-locked-folio callers, lookup misses and reclaim.
try_to_free_buffers documents that either folio lock or mapping private_lock
excludes buffer removal. grow_dev_folio and folio attachment hold the folio lock
as well as mapping synchronization. The returned bh reference is taken before
either protection is dropped, just as in the original path.

Costs: another atomic folio bit operation; unlock can wake folio waiters and
touch shared waitqueue state. Contended folios still use the old shared lock.
Thus lock-wait reduction alone is not success and may move cost to wakeup or
reclaim. No extra retained object memory. Validate CORE first, Go cross workload,
matched solo/12, frozen formal sample count and original guardrails.

Ext4 bitmap group locks and journal lists remain untouched: protecting a live
shared bitmap or transaction is not automatically removable serialization.
Device service limits and virtual block-backend costs are not solved by this patch.

Mandatory correctness: unchanged business checkers, parallel private-file I/O,
rename/hardlink/open-unlinked lifetimes, buffer pressure, clean fsck and isolated
crash recovery. Any unperformed checks remain explicit, not inferred from build.

Matched full Image/modules build passed. Both variants passed parallel private
file operations and fs-r4 guest crash/recovery, durable marker read and clean
read-only fsck diagnostics. Earlier fs-r1/r2 rejected epoch-zero guest timestamps;
fs-r3 crash checker acceptance by exit code alone was insufficient. Full reclaim
pressure/fault-injection/lockdep validation remains open. These limits preclude
production approval even if application correctness checks pass.
