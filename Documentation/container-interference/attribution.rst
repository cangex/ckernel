========================
Evidence and attribution
========================

E0 is a sustained anomaly in observed pressure/resource state. It is not a
business slowdown percentage and not an external-interference claim.

E1 is a directly observed scheduler wait, lock-contention interval, direct
reclaim or memcg-reclaim interval. Lock duration includes descheduling and is
not pure spin CPU time. Nested/unfinished intervals are explicitly represented;
missing ends never become zero waits. Stack lookup failure remains visible as
a negative stack ID. Reclaim execution identifies the executing task's root,
not every owner of pages scanned by reclaim.

E2 can associate overlapping, valid mutex contention intervals with the same
object address and the observed participants. It means co-waiters, not a
holder/victim relation. Non-overlapping address uses are not merged because
reuse cannot be excluded. Other lock types remain interval-only unless their
protocol/lifetime evidence is established. Within-container and cross-container
co-waiters are distinguished; thread/process identity is retained in raw data.

E3 requires a separately recorded controlled intervention and an appropriate
comparison. The production classifier never promotes timing overlap to E3.
Tests using a module with known object/ownership truth are not proof that the
production observer knows arbitrary kernel object owners.

Asynchronous work
=================

Short-window workqueue_queue_work/execute_start/execute_end tracing correlates a
bounded set of work pointers and queue timestamps. Submitter identity is
separate from worker identity. cancel_work_sync entry/return is recorded when
the tracked work and window permit it. A worker is not the business owner.

The test fixture guarantees one cgroup-owned per-open context. This supplies a
verifiable lineage example. Production merged work, self-requeue, callbacks
originating outside the observed window, cancel variants, RCU callbacks and
ambiguous object lifetime stay unknown/incomplete. Work addresses alone are not
a persistent object identity. No all-object provenance tracker runs ambiently.

Aggregation
===========

Do not add inclusive parent/child stacks, lock wait and scheduler wait or
overlapping reclaim intervals. Reports deliberately have no additive global
interference total. Business normalization requires an independent same-window
success counter and a comparable solo; the synthetic selftest counters are only
test truth, not an application instrumentation requirement.

attribution.py is an offline administrator analysis tool, not part of the
always-on resident-memory claim. Bound its input/window externally. It reports
parse errors, raw counts and ambiguity. The low-overhead daemon has fixed
capacity independently of the archived report size.
