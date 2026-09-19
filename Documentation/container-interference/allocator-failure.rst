Native allocation failure controls
==================================

The x3-failure disposable-VM cohort enables the existing OLK FAILSLAB mechanism
in a separately identified diagnostic kernel configuration.  It does not make
the fixture return a fabricated NULL, change the SLUB algorithm, or enable
fault injection on the host.  Image, BTF and module digests must match this
configuration; a prior non-fault kernel result is not its runtime validation.

Only cis_alloc_test has the native cache failslab flag.  The native task filter
also requires the individual container task to set /proc/self/make-it-fail.
Probability is enabled last, after both filters, and disabled before restore.
All native settings and both test cache flags are read back around every state
and restored after the cohort.  The selected tasks clear their own flag before
release/output and at normal exit.  The VM is discarded after the test.

Five predeclared cases run three paired OFF/allocator rounds with alternating
order and two container actors on CPUs 0/1:

* Single and bulk requests: native pre-allocation hook rejects marked tasks.
* Private cache: the marked second task uses an unflagged, unselected cache.
* Bystander: the second task uses the selected cache without the task flag.
* Recovery: each task alternates marked and unmarked requests.

Eight requests per actor give a fixed selected-call denominator.  The workload
records ioctl intervals, returned count and objects independently of BPF.
Failed calls must have no returned object, release entry or invented holder.
Successful controls must retain matching allocation/release identities.  A
private-cache call is an explicit selection negative, not a lost selected
event.  All selected calls, including failed ones, must be present for this
small full-rate fixture to pass.  Raw source/capture quality checks still apply.

These are real native injected pre-hook failures, not natural memory pressure,
memcg reclaim, physical exhaustion or partial-bulk rollback coverage.  Native
pre-hook failure is not by itself evidence of a competing container or lock.
The scope does not certify production performance or complete X3/X7.
