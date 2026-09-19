Allocator callback fix: isolated joint evidence, 20260919
=======================================================

Scope and immutable inputs
--------------------------

Kernel and tools: 394341472bc161e537d8f103f1042a4b1cf80d88.
Tree: 9ce18bb4489960eebb572693bb6f212f122893da.
ARM64 Image and modules rebuilt successfully, without replacing the host.

Image SHA256:
``ce2adb331cef71d9fb26af256a388b8406fbe6cf28652612dfc30024ae373dc4``.
BTF ELF SHA256:
``e5edda5aa0b8a8ae2cd29d124ad6d8fcb44de06824f862551795393a7fd57e6c``.
Configuration SHA256:
``a4442c97080c31d049a2ceef073709dddd6cbb4d2c3b0403b86354697c68904f``.

Remote cohort: ``/root/cis-20260916-232524/evidence/alloc-callback-joint-20260919``.
Serial: ``x7-joint-20260919-111900.log``; SHA256:
``0ac28021fb353a874ab22d7b321326741bae21c5cebd1c54a2b974c1d9d90500``.
Recompute using ``joint_vm_check.py SERIAL NEW_OUTPUT_DIRECTORY``.

Fixed matrix result
-------------------

PASS_SCOPED, 33 states, 30 captures, four active containers, three rounds.
The ten collectors ran separately under the same fixed file/VMA workload
and target/bystander rotation. The selected-object rwsem adapter is not part
of this ordinary-workload cohort. Empty findings do not establish coverage.

The earlier source-audit cohort failed with 404 nested release skips in
allocator0. New allocator rounds have free_nested=0, free_nmi=0 and
free_capped=0. No old failure was removed or relabelled as a pass.
All capture quality/source cleanup checks passed. Each allocator summary
reaches the display cap of 128 relations; full specialist records and the
omitted-relations count remain available. This is not a population recall
claim for the ordinary workloads.

Measured costs and limits
-------------------------

Maximum combined-process CAPTURING CPU: 34.17182 ms (40 ms gate unchanged).
Maximum combined RSS: 40,054,784 bytes. These are not complete kernel costs.

Release callbacks, all admitted cache releases, not target-only:

=========== ========== ============= ================
Round       Call count Body total ms Nested skips
=========== ========== ============= ================
allocator0  144752     22.02614      0
allocator1  145306     22.80066      0
allocator2  144862     19.90582      0
=========== ========== ============= ================

The callback body's boot high-water was 9,670 ns. This is not a complete
IRQ-off latency bound or a per-round maximum. The new timing excludes some
bookkeeping and save/restore work; virtual CPU descheduling can affect it.
Never add it to enclosing CPU/latency measures as an independent cost.

Under the fixed offered load, all 198,000 operations completed and there
were zero timeouts. Per-actor throughput changes relative to the round's
OFF state ranged from -0.03280% to +0.03772%; these are completion-timing
differences, not a saturated-capacity result. Across all collectors the
largest P99 absolute increase was 610,450 ns. For allocator specifically,
the largest bystander P99 increase was 10,930 ns (12.88%). P99 remains a
record-only prototype item, not a passed low-tail-latency certification.

Lifetime and cleanup regression
-------------------------------

Allocator lifetime regression also passed on the same kernel and tools.
``alloc-callback-fixture-20260919/x3-fixture-20260919-112639.log`` has SHA256
``111f28692a1e165cccba5e5d92628732abac73946c8b4f09571e54d22b3df8b1``.
Recompute with ``allocator_vm_check.py --fixture SERIAL NEW_OUTPUT``.
Cold, warm, bulk, private-cache, cross-CPU free and RCU-free cases each ran
three predeclared OFF/diagnostic pairs: 36 states and 18 captures. All 240
eligible selected-cache allocation calls matched independent ioctl truth;
744 release entries matched allocation identity and actual executor
context. The private-cache negative did not become a shared-cache claim.
Release recursion skips were zero. Callback body boot high-water was
7,320 ns in this separate boot. This does not establish RCU completion cost,
Maple tree ownership or production allocation recall.

The same kernel/tools also passed independent ``x0_check.py`` control and
fault-recovery checks:

* ``alloc-callback-control-20260919/x0-control-20260919-113059.log``:
  15 checks, 13 captures, all scope audits PASS. Serial SHA256
  ``f3737ee362ac06b1cdb1baacd5f128323b6bed8bed3d709b9b9581b6854f134a``.
* ``alloc-callback-fault-20260919/x0-fault-20260919-113456.log``:
  one deliberate uncertain-cleanup case remains FAULTED and rejects new
  admission. Serial SHA256
  ``0ddce27cd82ddf7188f4c199f3311dc57490bb2ac02408325edcfb3251a0ad65``.
* ``alloc-callback-crashes-20260919/x0-crashes-20260919-113709.log``:
  15 process-fault cases and 15 captures, all cleanup/recovery cases PASS.
  Thirteen deliberately interrupted captures have BLOCKED scope audits
  because terminal counters are absent; they are not usable attribution
  evidence. Serial SHA256
  ``750131a12c9e2a90cc6e9847e372515ffeb8b61fb02ea1c15b73661c42945589``.

Local Python regression: 390 tests, 389 PASS and one macOS-only SKIP.
ARM64 tools/BPF rebuild and the fixture module rebuild also succeeded;
runtime claims above are from the new isolated Image, not a host deployment.

Residual work
-------------

This cohort resolves the observed release recursion regression on the new
kernel. It does not finish X7: pressure/failure/cpuset cases, backend lock holders,
Maple tree ownership, skb source transformations and extended block-I/O
lifetimes still need their own evidence. No host kernel, legacy branch or
production admission policy was changed.
