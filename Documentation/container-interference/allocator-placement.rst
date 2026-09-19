Selected allocation placement regression
========================================

The isolated fixture adds a separate versioned placement ioctl, leaving the
original lifetime ioctl and existing kernel source interfaces unchanged.
It invokes real kmem_cache_alloc_node/free on the test cache and reports
timestamps and the allocated object's physical page node independently of
the observer. It accepts only an online node in the calling task's allowed
mems set, requires initial-namespace CAP_SYS_ADMIN, bounds the allocation to
one 256-byte object and frees it before returning. Kernel addresses are for
the privileged isolated test only.

The dedicated x3-placement VM has two 2-GiB virtual NUMA nodes, CPUs 0-3 and
4-7, and the same eight host-pinned vCPUs as other dedicated tests. It does
not change host topology or claim to emulate physical NUMA contention.

Two container actors remain on virtual CPUs 0 and 1. The frozen cases are:

* local: each container permits node 0 and explicitly requests node 0;
* remote: each permits node 1 and explicitly requests node 1;
* split: container A permits/requests node 0, B permits/requests node 1.

Each case uses three opposite-order OFF/diagnostic pairs, eight calls per
actor and full-rate selection of the test cache. Cpuset effective CPU/mems
values are retained before and after the window. Independently recorded
ioctl brackets must match request node, observed allocation node, address,
actor and release entry. Same cache does not mean same NUMA backend, and
these facts never manufacture a blocking container or a lock owner.

This covers explicit allowed placement without memory exhaustion. It does
not validate every native cpuset/GFP interaction, disallowed-node fallback,
concurrent policy changes, memory pressure or failure rollback. Warm SLUB
reuse and native softwall semantics must not be presented as hardwall
guarantees. No sampling algorithm or resource-management algorithm changes.

Use allocator_vm_check.py --placement on the raw serial. A guest exit code
alone does not establish placement or attribution correctness. Runtime
results must be recorded separately from this test design.

Runtime evidence, 20260919
-------------------------

The frozen kernel is 394341472bc161e537d8f103f1042a4b1cf80d88, using the Image,
config and BTF digests in allocator-callback-evidence-20260919.rst. Tools and
the separately rebuilt VM fixture are f431dc186. The cohort is
``/root/cis-20260916-232524/evidence/allocator-placement-20260919`` and raw serial
``x3-placement-20260919-115122.log`` has SHA256
``3793f4409f6a142c36e6e9b19c281d21f3a577a740391a5de0623b263ac52279``.

Independent replay passed all 18 states / 9 diagnostic captures. All 144
eligible allocations and 144 release entries matched the independent truth,
including requested node, physical page node and effective cpuset boundaries.
Maximum combined-process CAPTURING CPU was 18.08263 ms; maximum combined RSS
was 36,315,136 bytes. These are not complete kernel overhead measures.
The unmodified lifetime cohort also replays successfully with this reader.

This is PASS_SCOPED for allowed placement, not X3/X7 completion, hardware NUMA
performance, concurrent cpuset updates, pressure or disallowed-node behavior.
