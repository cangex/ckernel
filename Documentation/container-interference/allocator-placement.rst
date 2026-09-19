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
