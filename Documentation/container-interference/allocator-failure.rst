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

The allocator report now labels a returned versus failed request.  Failed
requests retain an observed region (pre_allocation_hook, bulk_rollback, or
backend_or_post_hook) but a cause of UNKNOWN.  A four-event begin/pre/end
path alone cannot distinguish fault injection, accounting rejection and
other pre-hook failures.  Only the independent test configuration identifies
failslab in this cohort.  Phase times still include observer execution.

These are real native injected pre-hook failures, not natural memory pressure,
memcg reclaim, physical exhaustion or partial-bulk rollback coverage.  Native
pre-hook failure is not by itself evidence of a competing container or lock.
The scope does not certify production performance or complete X3/X7.

Runtime evidence, 20260919
-------------------------

The new fault-enabled Image and all configured modules built successfully
from kernel 394341472bc161e537d8f103f1042a4b1cf80d88, without host deployment.
Only FAULT_INJECTION, FAILSLAB and FAULT_INJECTION_DEBUG_FS were enabled;
other injection facilities remain disabled.  The original non-fault Image,
configuration and BTF ELF were hash-verified unchanged.

Image SHA256:
``f4e2190966f395f2cad016d70a655126bc9c21923f3a0fa18886222ab4a3f92a``.
BTF ELF SHA256:
``e3e087a77c0512a8cb6900499400c7c371db9cba9de836dc6a711861423c98a2``.
Configuration SHA256:
``ea1a71e9c6fc6c185d1e04ef17a9e858dee75e02043d8b092a45bbe33678ad90``.
Guest tools/fixture are 5e4b11d90.  The raw serial is
``/root/cis-20260916-232524/evidence/allocator-failure-20260919/x3-failure-20260919-175839.log``;
SHA256 ``0d25097c93bd6fd48ec8066ee5de89667d55bedece5d02e651c4028e66f119e1``.

``allocator_vm_check.py --failure SERIAL NEW_OUTPUT`` independently passed
30 states / 15 captures: all 216 eligible selected calls, including 168
failed requests and 48 returned allocations, matched the native ioctl truth.
All 48 successful allocations had matching release entries.  Private-cache
controls were not counted as selected events.  The bystander remained able
to allocate and the alternating task-flag recovery control succeeded.
No failed request was given an object, release or fabricated blocker.
Configuration readback/restore and module unload passed.

Maximum combined-process CAPTURING CPU was 10.38844 ms against the unchanged
40 ms protective limit.  Maximum combined RSS was 36,401,152 bytes; complete
kernel memory and asynchronous CPU overhead remain unmeasured.  These costs
are specific to this fault-enabled VM, not inherited production acceptance.
Reader 2c05c9f14 additionally classified the 168 failures as pre-hook failures
with cause UNKNOWN and the other 48 as RETURNED.  Failslab cause is established
by the separate controlled configuration, not inferred from the event alone.

Local regression: 398 tests, 397 passed and one platform-specific skip.
No partial-bulk rollback, natural pressure or shared-backend lock-owner
acceptance is claimed by this cohort.  X3/X7 remain incomplete.
