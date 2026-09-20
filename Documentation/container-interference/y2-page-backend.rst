Y2 selected physical-page supply
===============================

The page_backend specialist observes selected node/zone backends, not private
VMA trees or every page lifetime. Its immutable backend lease uses the reserved
selection name page_zone, plus zero to eight node IDs. There is one bounded
two-second session and the existing global entry/output/process budget.

Four native operations are bracketed: PCP refill, PCP drain, direct buddy
allocation and direct buddy free. Source sampling selects one in 64 eligible
calls per CPU by default. A begin saves the actual zone/node and cgroup ID;
two clock reads bracket the inner native zone-lock critical section. Only
after unlocking is one tracepoint/BPF callback emitted. The caller may still
hold a PCP lock or have interrupts disabled; this is not a claim that all
native locks are released. Counts and timing overhead must be measured.

The native request and returned quantities are retained, including failed
allocation and mixed-order drain batches. BPF checks cgroup identity at the
endpoints and admits only an entire bracket within the selected target's
window. It uses no in-flight object map or global ownership lookup. Recursion,
interrupt exclusions and all source entries are separately audited. Sources
are disabled and the filter revoked outside sessions. Source-switch version
16 makes both states visible.

The report separates wait-to-acquire wall time, inner-held wall time and time
after the release timestamp. None is pure spin cycles. Clock overhead,
preemption and interrupts remain possible. The begin includes small source
setup work. Same-zone participants are E1 observations; no holder or unique
blocking container is inferred. Other zone-lock users (for example compaction
and isolation), interrupt-context operations, page lifetime and asynchronous
business ownership are not supplied by this adapter. Memory-hotplug lifetime
outside a single observed bracket is not certified.

The reclaim specialist remains separate: direct/memcg reclaim intervals are
wait/pressure evidence, not identification of the tenant responsible for all
pressure. The final Y2 validation must check ordinary independent-container
allocation, selected/unselected nodes, native counter provenance, absence of
private-tree tracking, source cleanup, rejected data and measured cost.
Implementation and unit tests alone do not complete Y2.
