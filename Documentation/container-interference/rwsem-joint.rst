Rwsem truth with four active ordinary containers
================================================

This cohort extends, rather than relabels, the existing native rwsem
fixture. Four registered container roots continuously perform the same
fixed-arrival file/VMA workloads used by the ordinary joint cohort. During
their execution, container tasks execute the selected native rwsem
positive/negative cases. Probe-off counterparts execute the SAME fixture
case and ordinary work, not a quiet baseline. Three alternating OFF/ON
pairs cover all ten original fixture cases (60 states, 30 captures).

Target roots rotate from 0/1 to 2/3 to 0/3. The fixture's logical holder
and waiter map to these roots; the extra reader maps to a registered
non-target root. Initialization, lifetime tokens, operation modes and
native return values remain independently recorded. The validator checks
the complete planned job population and container mapping, not only the
relationships that happened to be reported. Private objects, address
reuse, pre-window holders, failed trylock, interruptible abort, non-owner
read API, readers and downgrade retain their existing evidence limits.

All four ordinary workloads must cover the entire diagnostic window and
complete 1500 operations at the unchanged 2ms offered period. Latency is
arrival-relative, with all 1500 samples retained and P99 independently
recomputed. Timeout/error outcomes are not discarded. P99 remains
record-only under the prototype policy, not a passed production gate.
The 40ms CAPTURING process CPU policy is unchanged.

Resource bookends include management and actor cgroups, whole-VM CPU,
kernel-thread counters and memory gauges. They enclose ordinary work,
fixture work, preparation, snapshots and reporting; they are NOT
exclusive observer CPU/memory or complete asynchronous attribution.
Diagnostics are compared only to the same case and round. The existing
ordinary joint evidence is not retroactively upgraded to positive rwsem
coverage, and old rwsem-only evidence cannot satisfy the new joint verifier.

This is a controlled kernel-API mechanism test under concurrent ordinary
container operations. It does not establish how frequently real applications
hit these locks, does not cover every mixed resource, and does not complete
X7 by itself. Runtime receipt and evidence hashes must be added separately.
