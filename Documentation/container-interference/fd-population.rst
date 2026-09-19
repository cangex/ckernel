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

Predeclared new-kernel receipt
-----------------------------

Kernel ``63df60de9`` and guest tools ``96095cd5b`` ran the unchanged basic
and lifecycle workloads, with the independent population plan written
before captures. Both cohorts passed raw re-verification, including the
stricter per-task population checks added afterward. Serial files::

  fd-population-basic-runtime-20260920/x1-fd-20260920-000234.log
  85bd8ef2c40e87ee0ef7a4fd139779806eb5caeb91486da24dbce8cc39599ca6
  fd-population-lifecycle-runtime-20260920/x1-fd-20260920-000456.log
  f645c002b00da6ad95fb083f39bb6fa860a6a9e954884fefbda9856943cbbb29

Nine basic and six lifecycle captures completed. Across three fixed
rounds, shared-table thread calls each yielded 42 complete / 2 partial /
20 absent out of 64 independent calls. Private tables yielded 32/32
complete calls and no holder-waiter edges. Cross-container CLONE_FILES
yielded 21 complete / 1 partial / 10 absent of 32 calls. Reuse yielded
150 complete / 8 partial / 98 absent of 256, with six verified address
retirements/reuses per round. All measured fixture edges were independently
matched: 40 per shared-thread round, 20 per cross-container round and
128 per reuse round. Native syscall operations still have no independently
enumerated lock-call denominator. These numbers are not wait-recall rates.

Maximum CAPTURING combined process CPU was 11.78443 ms (basic) and
10.70294 ms (lifecycle), against the unchanged 40 ms policy. Peak process
RSS was respectively 36,777,984 and 35,860,480 bytes. These do not include
complete kernel/asynchronous memory or isolate all callback CPU costs.
No runtime prefix was enlarged, no missed call was removed, and no
percent-recall acceptance threshold was declared passed. Current limitations
are now quantified rather than hidden behind matched-edge precision.
