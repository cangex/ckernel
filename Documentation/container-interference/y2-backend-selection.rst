Y2 counter provenance and selected allocator backends
=====================================================

Native memcg counters bind their owning cgroup ID and memory/swap/kmem/TCP
memory kind once, before online publication. Counter initialization clears
the binding. No hot global owner lookup or counter is introduced. Sample
protocol 3 reuses otherwise unused event fields, preserving BPF event size;
CO-RE on older kernels reports an unknown binding. Init generation still
separates address reuse. A resource owner is not a mutex holder. Shared
updates do not prove cache-line contention, atomic latency or a unique
blocking tenant. Actual structure size is part of the runtime audit.

New kernels require an exclusive administrative backend-filter lease before
allocator, release, optional Maple or SLUB-node probes can attach. The lease
selects one exact ASCII cache name and, for SLUB lock observation, up to eight
node indexes (empty means all existing nodes). A write publishes an immutable
RCU object; no reconfiguration is permitted while probes are attached. Close
revokes selection and defers only metadata freeing through RCU. A killed
worker cannot leave a selection or fall back to a different boot cache.
New leases remain blocked until old probe registrations have detached.

The source fast check uses a bounded read-only comparison and no control
mutex or allocation. Node checks compare the native live cache's node array
entries with the node supplied by SLUB. No user-provided pointer is
dereferenced. Cache names remain selection keys, not proof of cache lifetime;
native reset/retirement evidence remains necessary for accepted lock links.

The session request's optional backend field contains cache and nodes. Nodes
may only restrict the SLUB lock collector. Allocator-stage and release
observation deliberately span all nodes of the selected cache: requested
placement is not necessarily actual placement, and release may occur on a
different CPU/node. Filtering those records independently would fabricate
complete lifetimes. Actual placement and fallback stay explicit in native
stages. The old audit header's cache field is the boot default, not an active
session selection; the immutable readback record names the actual selection.

Absent an explicit selection, the worker reads the frozen boot cache default
and obtains the same lease. Historical kernels without the lease interface
support only their boot default; explicit overrides fail instead of silently
collecting something else. The worker records exact readback and closes the
lease after detaching producers. Source-switch version 15 reports selection
presence independently of source enablement. Offline analysis validates the
request/readback/close binding and preserves historical contracts.

No claim of Y2 completion follows from implementation or parser tests. ARM64
build, source-off behavior, permission and race negatives, real-container
counter provenance, selected/unselected caches/nodes, release coverage and
cost are separately validated. Physical-page and reclaim coverage has its
own adapter and acceptance; this change does not supply those observations.
