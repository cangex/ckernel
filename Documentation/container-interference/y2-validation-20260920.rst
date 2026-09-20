Y2 public memory-backend validation, 2026-09-20
=============================================

Status and scope
----------------

Y2 is PASS_SCOPED for the bounded coverage below: 138 independently replayed
functional OFF/ON states, full ARM64 ON/OFF builds and 703 Linux unit tests.
The counter, selected-cache/node, physical-page and memcg-pressure cohorts
passed their stated scope. Y3--Y7 have not passed. No average-throughput or tail-latency certification follows
from these functional cohorts. The host kernel was not replaced.

The native adapters leave accounting, allocator selection, locking and
reclamation algorithms intact. An actual ancestor counter owner is not a
lock holder. A shared zone address is not a measured blocking relationship.
Private memory and private SLUB caches are negative controls, not default
cross-container interference claims.

Evidence roots are under the dedicated host tmpfs directory
/dev/shm/cis-x-20260919/evidence/. Each directory retains source, command,
kernel/tool hashes, VM serial and raw per-session data. Independently replayed
serial hashes are recorded below; a successful QEMU exit alone is insufficient.

Ordinary containers and resource provenance
-------------------------------------------

y2-replenish-c9a5c5194-20260920: 24 states, PASS_SCOPED.
Serial SHA256: e36bb2b924c2e1afaa0ff1e844c4b616d494754da07ecc9ea6d16eda57fe9346.
Kernel 97b4c04d0; tools c9a5c5194. Two actors use private anonymous mappings,
with common versus separate cgroup parents. The source reports actual owning
cgroup IDs and resource kinds, not owners inferred from the actor. Native
ancestor walks and private-parent negatives pass. All original charge,
uncharge and failure semantics remain active.

The selected page-zone cohort uses a 64-MiB MADV_NOHUGEPAGE allocation shape
at the default 1/64 source sampling. Three selected-node captures contain
2, 3 and 3 PCP-refill observations; the unselected-node controls contain none.
This is positive ordinary refill coverage, not coverage of every page path.
The earlier 8-MiB cohort y2-memory-97b4c04d0-20260920 is retained as a failed
coverage test: reuse stayed in PCP and yielded no accepted page-backend samples.
No empty capture was declared a successful positive test.

SLUB-node lifetime and selection
-------------------------------

y2-slub-c43eb7614-20260920: 48 states, PASS_SCOPED.
Serial SHA256: 2cb8cbe34b41e8cd0ef6193669432c74294ee3dd10b8a7f5eefe2508cb4c78c0.
Fifteen eligible holder/waiter pairs are checked against independent fixture
truth, with private nodes, owner changes, preemption, unknown actors, three
same-address recreations and six excluded-cache/node ON states.

The earlier cb3def3ee cohort failed all three recreation cases. The filter
could not see node reset before publication or retirement after pointer
removal. Commit c43eb7614 places observation after native node publication
and before removal. It changes neither lock acquisition nor ownership.
Both failed and corrected evidence remain available. A controlled native-lock
fixture validates the adapter, not ordinary workload contention prevalence.

Physical-page supply and return
-------------------------------

y2-page-2fdb0f020-20260920: 12 states, PASS_SCOPED.
Serial SHA256: e08e7def2d0c01d571d7503195149eb31d6c778c5beb13f16854842ad0fefd2d.
Kernel d79904989; tools 2fdb0f020. Each selected-node capture contains all
four native shapes: PCP refill/drain and direct buddy allocation/free.
There are 2177, 2178 and 2189 accepted brackets, with zero samples for the
unselected node. Two containers allocate and return their own pages; no
synthetic observation event is injected. Native allocated/freed quantities,
allowed node, source-off counters, module unload and VM sysctl restoration
are checked independently.

This is deliberately a full-rate, paced functional fixture: four operations
per actor, 3088 pages per operation, 1--1.1 ms pause per 16 native calls,
page_shift=0, VM-only PCP high fraction 4096. It is NOT a performance cohort
or the default production sampling configuration. Two failures are retained:

* 4396c0f86: high-order frees bypassed free_one_page and were absent. The
  real __free_pages_ok zone-lock path is now bracketed too (d79904989).
* d79904989 unpaced: all shapes appeared but the full-rate bursts lost
  records. Quality rejection stayed active; the run was not accepted.

Selected-cache allocation and release
------------------------------------

y2-allocator-dd3dae18f-20260920: 36 states, PASS on independent replay.
Serial SHA256: 350397e91e1090c60bbc3ca90fcbd346017323767063239ce151c4b9868202ee.
Kernel d79904989; tools dd3dae18f. The boot cache is maple_node while the
session explicitly leases cis_alloc_test, exercising a real override rather
than coincidentally using the boot default. The alloc_backend collector omits
private Maple-context probes/maps. Cold, warm, bulk, separate-cache,
cross-CPU free and RCU free scenarios each have three alternating OFF/ON
pairs. Native ioctl object truth, returned quantities, requester versus
release executor, source-off counters and module removal are checked. A
separate cache does not acquire the selected cache's attribution. Returned
objects are not equated with physical page reclamation.

Native reclaim and false-attribution controls
--------------------------------------------

y2-reclaim-6979f1924-20260920: 18 states, PASS_SCOPED on independent replay.
Serial SHA256: 3e567b8d5c1b5d340e4f869791af9ca9bbf3ef5b24777cea00f9bcf6082cea9c.
Kernel d79904989. Three alternating OFF/ON pairs exercise private 64-MiB
mappings under a common 96-MiB parent high limit, separate parents with the
same high limit, and one actor's own 16-MiB high limit.

Common-parent ON captures each contain 68 reclaim intervals, involving both
actors. Separate-parent captures contain none. Own-limit captures each
contain 18 intervals for that actor only, not its bystander. Local high
events occur at the configured ancestor or private leaf as appropriate;
OOM, memory.max failure, abnormal exit and early limit release are rejected.
The limit is released only after collection, to permit bounded business drain.

The first replay used a shortened display source_identity in place of the
complete receipt source bundle and therefore failed its source check. Commit
e3b36b504 validates all top-level SOURCE_KEYS plus actual collector inventory
and window equality; the same raw serial passes, without rerunning workloads
or discarding the original failed report. Tampered/missing bundle identity
has a unit negative test.

These native tracepoints identify the reclaiming task, not the target memcg
or owner of scanned pages. Configured ancestry and local high counters are
separate evidence and never substituted for that missing native identity.
Global direct-reclaim pressure, kswapd, compaction and unique blocking-tenant
attribution are not certified by this cohort.

Cost boundaries and remaining work
---------------------------------

The ordinary 24-state cohort recorded 9.72--10.94 ms CAPTURING process CPU
per two-second session and approximately 31.95--36.62 MB combined process
RSS. This excludes complete source-side, asynchronous and BPF memory cost.
The reclaim cohort recorded 11.09--24.87 ms and 32.07--36.01 MB respectively.
These are scoped accounting values, not whole-machine overhead percentages.
P99 cannot be certified from four/eight/sixteen-operation functional shapes.
Shared counters/zone participation never imply pure spin cycles.

pahole on the ARM64 ON kernel shows page_counter remains 192 bytes, the
same size and usage-field offset as the preceding generation-only observer;
new provenance consumes existing tail padding. This is architecture/config
specific, not a universal size claim.

y2-off-6979f1924-20260920 contains a separate full ARM64 Image/modules build
with CIS_OBSERVE and its dependent observations/fixtures disabled. Image
SHA256: baf8c78993d8b5c83fabc1c244a2a9dd909b0488bf236e39be9f4cfde2f90bee.
The off structure is also 192 bytes with usage at offset zero, without CIS
provenance fields. The tested page-source, bind and backend-filter symbols
are absent. This is compile/link and layout acceptance, not a booted OFF
performance comparison. Five unused-function/variable warnings are retained
in unchanged upstream ARM64 KVM files; no warning is hidden by disabling
compiler checks. The 703 host-side tests pass on ARM64 Linux; the same suite
on macOS has two explicit Linux-only skips.

Y7 must measure full source/worker/background CPU, kernel and process memory,
target/bystander throughput and latency under the frozen periodic policy.
Neither a full-rate fixture nor filtered callback time replaces that test.
