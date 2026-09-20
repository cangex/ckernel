Y5 selected public transmit queue
================================

Status: PASS_SCOPED. See y5-validation-20260920.rst for separate build,
control, traffic, negative and source-protection receipts. This does not
accept complete packet provenance, physical-NIC causes or Y7 overhead.

Scope
-----

Independent container connections may converge on one actual egress qdisc and
device queue. Default profiling observes that public resource, not every socket
lock. One administrative lease pins one net_device, transmit queue and qdisc
object. Namespace inode, ifindex, queue number, qdisc handle and a monotonic
lease generation identify the selection; equal names or handles are not equal
resources. Replacement/reset or a qdisc change invalidates the lease; resets
or qdisc changes on another queue of the same device conservatively do so too.
Class/filter-only administration is not yet a complete invalidation contract:
the first test scope must freeze these and cannot certify arbitrary TC mutation.
Unrelated queues are filtered
before BPF, with native per-CPU entry/filter accounting retained.

The first adapter records sampled closed admission brackets and sampled service
points. For locked qdiscs the admission sample records when root_lock was
acquired, after any busylock acquisition. This is combined acquisition wall
time, not pure spin cycles and not a lock holder identity. NOLOCK/bypass paths
remain explicit. Queue length and backlog are point values, not synchronized
occupancy integrals, and service is not wire completion or device latency.

Executor cgroup, socket accounting cgroup, CPU/interrupt context and the selected
resource remain separate. Forwarded, orphaned or transformed packets may have
unknown socket origin. No payload is read. A packet address is only a point
identifier: it must not be joined across time as a proven skb lifetime. Complete
packet lineage, per-tenant queue occupancy and unique blockers are not provided
by these observations. A queue delay graph requires additional proven lifetime
evidence, not visual correlation.

The administrative pin can delay device unregister until the lease is closed.
It is not a free or wait-bounded operation; the controller must release its
bounded session lease before deleting its test device. No host device is changed
by the test harness. Queue-local raw qlen/backlog fields for per-CPU-stat qdiscs
are not their aggregate values and must be reported as such or unknown.

Boundedness and tests
--------------------

The native adapter is disabled by default, samples at 1/16 per CPU and event
class, uses no global hot-path owner index or allocation, and exposes source
entry counters so userspace can detach on a source budget violation. Control
locks and RTNL are administrative only. A two-second specialist must release
the lease and detach the producer; output suppression alone is not accepted.

Required isolated validation: independent sockets/private namespaces through
the same queue and distinct queues; unselected queue; idle/OFF; queue reset and
replacement; privileged lease misuse; unknown/orphaned source; IRQ executor not
renamed to a container; repeated queue/address reuse; output/source storms and
cleanup. Retain the existing private-socket collector only as an explicitly
requested extension. Netem/TBF/emulated-device observations do not establish
physical NIC contention or all-container network causality.
