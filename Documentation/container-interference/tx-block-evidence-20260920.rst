TCP allocation and block lifecycle evidence, 2026-09-20
======================================================

Scope and immutable inputs
--------------------------

These are isolated ARM64 KVM cohorts, not host NUMA or production acceptance.
The host kernel and boot stayed unchanged. The kernel was built at
7897796a3cf1668c0f27d79a36c5ae0296bfbc40, Image SHA256
da9d838f343a6ca138bf74d72cdd77fea4a187fc91552e48c8afec08e883858b.
Config SHA256 is
678424d65838341018da716b6eb7f4e13d7213e56201ec97744d92708f156a65.
Full Image and module builds passed. The 40ms CAPTURING process-CPU guard was
not raised. P99 remains descriptive, not a performance acceptance criterion.

TCP protocol 2
--------------

Kernel and tools used the same 7897796a3 commit. Linux tests passed 573+21+7.
The requester is frozen before alloc_skb_fclone, with a separate backend start
timestamp after the initial identity callback. Three OFF/NET pairs each observed
five successful send-window allocation brackets and five original-header release
entries. In every round four releases executed in softirq and one in task
context. Independent SO_COOKIE, container/TID and successful send-call boundaries
matched. Actual sequential header-address reuse did not mix episodes. These are
15 positively validated observed allocations, NOT a full allocation recall
denominator. No clone/GSO/GRO lineage, payload owner, exclusive allocator CPU or
allocator lock holder is inferred.

The backlog cohort passed all six states. Its serial SHA256 is
cb0780a8c6cbc76fb63591af4b24384d035c9e7a961e25d6ce7e8dfed311ade8.
The creation/accept/SCM_RIGHTS origin cohort passed 18 states; serial SHA256 is
ac4a1e8b2b07a6c60701c19b3c57268e103bb460a5ff85e649c05ba64e417313.
Their maximum CAPTURING process CPU was 8.623050ms and 8.475760ms; maximum
recorded combined RSS was 37769216 and 36241408 bytes respectively. TX callback
body time per captured backlog window was 38170, 37210, 37590ns; these exclude
some wrapper/filter/release costs and are NOT total observer cost. OFF source
counter deltas were zero. Boot-high-water callback maxima are not OFF work.

Control cleanup passed 16 cases/14 sessions. Crash/recovery passed 16 cases,
but forcibly terminated captures remain failed and audit-incomplete, not usable
samples. Earlier protocol-1 captures remain development records and are not
relabelled as entry-frozen protocol-2 evidence.

Joint regression failure retained
---------------------------------

The 33-state joint run completed, but independent replay FAILED allocator1:
one BPF rejection, despite no loss, CPU violation or cleanup failure. Its serial
SHA256 is
977820b68a82fd3e70be5d2efa25607c6eafba0a2328f36c18f271dd6eeff448.
Observed allocation/release replay had a maximum of 16 live sampled nodes, no
duplicate live addresses and no unmatched observed releases. No sampled backend
call was unclosed. This does not recover the missing rejection reason.

Source inspection found that Maple end-after-window was incorrectly counted as
identity corruption. ec95c76ee separates expiry from immutable-field rejection,
retires the pending context in either case and does not invent a completed
context. The original raw evidence lacks a per-reason rejection counter, so the
exact cause of this one rejection is not uniquely proven. The failed cohort is
retained; the fix requires fresh regression, not retroactive PASS.

Native split/error/cancel fixture
---------------------------------

Tools/fixture e19962fac48272f594d55294bb4340f0fb9c5237 used the same immutable
7897796a3 Image. Linux tests passed 578+21+7; the fixture module compiled and
unloaded normally. Three alternating OFF/BLOCK pairs for plain, split, cancel
and error passed all 24 states. Each pair used two container actors and separate
dedicated memory devices. Native 8192-byte bio splitting produced two 4096-byte
requests per actor; driver/request lifetimes, sectors, bytes, bio billing identity
and IOERR statuses matched independent truth. Cancel-before-submit produced zero
request episodes. No unique blocker was reported. This is not in-flight request
cancellation or a production parent-bio tracing feature.

Serial SHA256:
5828bd9868009bc0ecebe9e3612edd21c3acab4c32d0aa48cf076c0e5712500c.
Fixture module SHA256:
b5fd6aeeabb9bff02fd93b41b76ac48996d92d1d5b6c97f38fd8ce12f657743d.
Twelve captured windows had max CAPTURING process CPU 10.345330ms, total process
CPU through reporting 186.018620ms and combined RSS 35618816 bytes. These values
are not complete kernel/background observer cost or throughput overhead.

The initial launcher attempt used an already-existing historical bundle name;
its commit guard stopped before building or booting. That failed attempt is
preserved separately. The corrected input used the commit-qualified bundle name
and checked the advertised and fetched SHA BEFORE checkout. No remote branch
was changed by this recovery.

Locations and replay
--------------------

Host evidence lives under /dev/shm/cis-x-20260919/evidence/ in
net-tx-entry-validation-20260920 and block-split-e19962fac-20260920. Exported raw
logs, build outputs and verification JSON are preserved in the corresponding
local net-tx-entry-evidence-20260920 and block-split-e19962fac-evidence-20260920
directories beneath the 20260916 development evidence root. Replay uses
net_vm_check.py, block_vm_check.py, x0_check.py and joint_vm_check.py.

The pinned 60-cohort development index retains one failed joint cohort. X7 is
not complete. Remaining work includes mixed-source independent truth, wider
negative coverage, unresolved asynchronous costs and the fresh Maple regression.
