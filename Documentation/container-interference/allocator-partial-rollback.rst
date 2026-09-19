Native partial bulk rollback validation
=======================================

This disposable-VM cohort fills a gap left by the failslab pre-hook test:
``__kmem_cache_alloc_bulk`` can acquire a prefix, fail in ``new_slab``, call
``slab_post_alloc_hook`` for that prefix, and return it through
``kmem_cache_free_bulk`` before returning zero. No fixture substitutes a
NULL return or emits allocator source events.

The production source hooks are unchanged. A separate ARM64 4K-page build
enables native ``CONFIG_FAIL_PAGE_ALLOC`` and debugfs fault control, with
``CONFIG_FAILSLAB`` disabled. The test module's opt-in ``rollback_mode``
uses nonmergeable 65536-byte caches. Runtime verifies one object per slab;
it does not silently adapt the test denominator on other configurations.
The first container uses the selected cache, the second a distinct private
cache and is never task-marked. Both execute native allocation operations.

Each container prepares two objects, keeps one live anchor and frees the
second to provide a real reusable slot. The first four-object bulk call in
the ``partial`` case task-marks only the target through native
``/proc/self/make-it-fail``. Page-allocation failure probability is enabled
only after task filtering is configured. ``GFP_NOWAIT | __GFP_NOWARN |
__GFP_NORETRY`` bounds retry behaviour, not allocator completion time.
The native bulk loop consumes the free slot before new page allocation
fails. The task mark is cleared and checked before output and cleanup.
A second unmarked bulk call verifies recovery, followed by anchor release
and cache shrink. The ``unmarked`` case performs the same sequence without
task marking. Each case has three opposite-order OFF/allocator pairs.

The ioctl copies, but never dereferences, the populated caller array after
a failed bulk return. The fixed OLK implementation preserves its acquired
prefix (possibly reordered by native bulk free); this is test-only truth,
not a promised public allocation API contract. Independent verification
matches those addresses to allocation ordinals and release-entry events
within the ioctl interval. Successful native allocation and in-call bulk
release are checked too. Private-cache operations are excluded by the
predeclared selection, not after observing the results.

The monitor may report ``FAILED / bulk_rollback / cause=UNKNOWN`` and
observed requester-to-release identities. The known injection cause comes
from separately recorded test controls, not from guessing another
container, natural memory pressure, or a lock holder. Object return entry
does not prove allocator release completion, and this cohort provides no
full SLUB lock-owner relation. X3/X7 remain incomplete pending their wider
coverage and joint acceptance requirements.

Fault settings are saved, checked at every state boundary, disabled first
on cleanup and restored. The module, configuration and kernel are only
loaded in a dedicated VM, never the 14-machine host. All failures and
source/budget audits must be retained. Runtime acceptance is recorded
separately; source implementation and unit tests alone are not acceptance.

Runtime evidence, 2026-09-19
---------------------------

The complete Image and modules built successfully from kernel source
``cfd2b935d49078e04a0a600d79b9d48c5f706d4c``. The runner and test module
used tools commit ``d6b3247e5252eb4e29106a3b5a3f8b0c4a203dcc``. Only
fault-injection configuration differs from the preserved normal build::

  Image     83ad79bd9744d8e2aa3b5af2926320f337845466f229316b52a1c1a0a740e53d
  vmlinux   79d8f4504a58389050ff5a6afaef5095d1228e606a265f378830949a94fc65e3
  config    8436ec754cd3e47b247d6f91c431c60d6200d76fe432a09309550688812dd569
  serial    7535c48c286cab01ebd17f9e204b357f383b26d356d8005ed9cde0b88c09f413

Remote evidence directory::

  /root/cis-20260916-232524/evidence/allocator-rollback-runtime-20260919

Serial file: ``x3-rollback-20260919-190852.log``. Independent replay::

  PYTHONPATH=tools/container_interference python3 \
    tools/container_interference/allocator_vm_check.py \
    /path/to/x3-rollback-20260919-190852.log /new/output --rollback

All 12 states and six captures passed the scoped independent check. The
24 selected allocation calls were observed (two setup singles and two
bulks per capture), with three actual failed bulks, each returning one
already acquired object to native bulk free. All 51 observed release
entries matched their allocation identities: 12 setup objects, three
rolled-back prefix objects and 36 successfully allocated bulk objects.
Unmarked private-cache actors succeeded throughout, as did the target's
post-fault recovery calls. The fixed private-cache exclusion is not an
overall allocator recall claim.

All OFF source audit counters were zero; active source clipping and nested
release recursion were zero. Source settings were checked at every state
boundary and restored, and module unload succeeded without kernel warning.
Combined-process CAPTURING CPU peaked at 10.51225 ms (40 ms limit), RSS at
36,069,376 bytes. This does not account for all probe work executing in
business context and is not production-overhead acceptance. The measured
release-callback inner brackets peaked at 25,020 ns per capture; they are
not a total source-entry cost.

Failure cause remains UNKNOWN in the monitor's report. Native
``fail_page_alloc`` is proven only by the independent frozen test controls.
This successful cohort does not establish natural page-pressure attribution,
SLUB holder relationships, Maple tree identity, or complete X3/X7 coverage.
