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
