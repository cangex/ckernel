FD fixture population accounting
================================

The independent fixture brackets every successful ``files_lock`` and
``files_unlock`` call before/after the native helper. The frozen population
is ALL successful fixture calls inside the session window: no selection by
observed records, wait duration, overlap, or the source's 64-event prefix.
Two fixture threads execute 16 calls each in the shared-table case. Private
tables and explicit cross-container CLONE_FILES use their existing fixed
plans. Reuse covers every generation, not only an address's first watch.

``fd_population_check.py`` independently counts that population and matches
WAIT/ACQUIRE/RELEASE_BEGIN observations by object, original cgroup, host
TGID/TID, and the fixture's time brackets. A complete call must retain task
start, identity generation, object epoch, protocol and paired attempt ID.
Duplicate truth, duplicate observations, overlapping calls in the same
task, window violations and mixed sessions cannot increase coverage.

Missing calls remain in the denominator, including calls after a bounded
prefix marker. The report separates complete calls, partial calls and
unobserved calls. A prior marker on the same address is only context, not
proof of the omission's cause: address reuse or another loss may intervene.
Startup or teardown operations outside the fixture's brackets are not
misclassified as false positives; they are outside this denominator.

This measures fixture CALL coverage, not contention or holder-edge recall.
The fixture timestamps bound an acquisition attempt; they do not prove
continuous spinning or exclude pre-lock scheduling. An overlap does not
establish the exact delay caused by a holder. Existing ``fd_check.py``
separately checks reported relationships against actor/interval truth.
Native open/dup/close workloads without independent fixture truth have
UNAVAILABLE denominators, never zero waits or 100% recall.

``PASS_SCOPED`` means the population accounting is valid, NOT that its
coverage met a recall threshold. Historical replay is explicitly marked
RETROSPECTIVE_REPLAY; only new cohorts freezing ``population`` in their
plan are PREDECLARED. No source cap or CPU budget is raised by this work.
The source remains a bounded-prefix diagnostic, not continuous full tracing.

Historical diagnostic
---------------------

Replaying the unchanged 2026-09-18 independent-FD basic/lifecycle cohorts
shows why observed-edge precision was insufficient. Shared threads had
42 complete calls out of 64, while cross-container CLONE_FILES had 21/32,
both 65.625%. An address-reuse round had 150/256 complete calls (58.59375%).
These are retrospective fixture-call results, not a new runtime result,
population interference recall, or an application-wide loss estimate.
All omissions remain reported. Full eligible contention-edge truth and
dense-source observer acceptance are still unverified.
