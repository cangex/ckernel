M4 validation record (2026-09-16)
================================

This is a default-off AppArmor prototype, not acceptance of general container
isolation or all security semantics. Maple was disabled. No new kernel was
installed on the physical host. Full ARM64 Image/modules were built with
separate diagnostic and performance configurations and booted under KVM.

Diagnostic evidence
-------------------

Evidence root on the development host::

  /home/ckernel-m-through-m6-20260916

``evidence/m4-token-20260916_112356.log`` has 19 security cases, 12 combined
M3/M4 open cases and the AppArmor subjective/objective-credential KUnit test.
They passed with KASAN and lockdep. The gate requires real allow/deny/audit
profiles and AUDIT_GET enabled=1, lost=0, backlog=0. It also checks policy
replacement, stacked labels, credentials, inherited and transferred files,
instance exit, token reuse protection and retained native permission checks.
Sixty-four task-local failslab probes rejected 8 creates, completed 56 and
permitted all 64 subsequent uninjected creates. A transferred file stayed
alive across 512 other instance creations without reassigning its token.

Token log SHA256::

  b63d3bb985821ceb16ead1ec07286ce2eef521a40b0fd048b9e7aa25c6aba1c4

The unmodified AppArmor-path reference is
``evidence/m4-native-reference-20260916_112302.log`` (six cases, audit lost=0).
It uses the prior M3-C image, not a pure OLK image. An earlier modern profile
incorrectly assumed that absence of a signal rule meant no signal mediation;
native Linux correctly denied it. The corrected legacy-ABI fixture is
explicitly identified and uses upstream AppArmor features.nopolicydb. It is
not a claim that arbitrary current profiles qualify for the fast path.

An earlier pointer-layout diagnostic passed functional assertions but lost
audit records. Its log and old marker remain evidence of that failure, not
full acceptance. The token layout uses existing aa_file_ctx tail padding;
the ARM64 diagnostic layout remains 80 bytes. A compile-time assertion guards
the native rounded size. It does not enlarge the unaccounted LSM file blob.

Pressure observation: memory.current initial 262144, observed high value
25767936 and post-500ms 425984 bytes under a 50331648-byte limit. The test
includes explicit pressure and instance batches; these snapshots are not a
leak-freedom proof or evidence that every RCU callback has completed.

All four full Image/modules configurations were built and boot-tested:
cumulative, security-only minimum, Core-only and fully off. The first fully
off test failed because the supposed native fixture tried to open the absent
/dev/ckernel-m. The corrected native fixture performs no CKM ioctl or bind.
The original failure log and nonzero matrix exit remain intact. No kernel
binary was changed to make the fixture pass. All four immutable images were
then retested successfully with audit lost=0:

* m4-token-fixture-v2-20260916_121933.log: 19 security, 12 combined open,
  subject KUnit, faults/pressure/owner-lifetime checks.
* m4-minimum-fixture-v2-20260916_121936.log: 19 security and subject KUnit.
* m4-core-fixture-v2-20260916_121939.log: six native policy cases.
* m4-off-fixture-v2-20260916_121941.log: six native policy cases without CKM.

Their SHA256 manifests are evidence/m4-{token,minimum,core,off}-fixture-v2.passed.
The successful closure is m4-config-revalidated.exit, not a rewritten initial
matrix failure. The minimum configuration excludes both VFS options and Maple.

Same-kernel performance
-----------------------

Primary raw logs::

  evidence/m4-perf-quiet-file-20260916_114538.log
  evidence/m4-perf-signal-20260916_114059.log

SHA256 respectively::

  18116bb47a7617ac6950794527b058320ba6a80de291d0eeb86b84f4f60d8ea3
  eb81edd063b1522e5e2f523780d0f952692d16b1d2e35b4dc16494ab73c3aa30

Each workload has 180 run states and 240 worker records, n=3. Target-only,
bystander-only and paired cases exchange CPU roles. Core and security modes
share the same non-debug kernel, private object layout and fixed operation
count. File operations are open/fstat/close; signal operations are self
tgkill with an ignored signal and an explicitly eligible policy. Closed-loop
runs use 200000 operations; equal-arrival runs use 20000 at 20us intervals.
These measurements are not production HTTPD/Agent or bare-metal NUMA results.

Steady paired security-vs-Core ranges across role/placement group means:

=====================  ===================  ===================
Metric                  File                 Self signal
=====================  ===================  ===================
Throughput              +13.54..+17.14%       +42.67..+45.23%
Service P99             -11.16..-8.08%        -35.56%
Foreground CPU/op       -15.39..-12.20%       -31.15..-29.90%
Paced response P99      -7.60..-0.86%         -0.23..+16.18%
=====================  ===================  ===================

Ranges are not confidence intervals, pooled quantiles or independent-domain
contributions. Signal paced response latency is NOT uniformly improved,
despite lower service time. Maximum and one-operation cold-start latency
remain variable. Saturating the eight-label cache with twelve profile
transitions regresses file throughput 2.55..5.03% and signal throughput
3.40..5.14%, with P99 increases up to 5.59% and 5.57%. That scenario includes
profile-transition work; it is not isolated cache-lookup timing. Invalidation
here revokes the target instance halfway through the run, not policy reload.

Relative to each mode's own solo, file paired throughput changes are
-18.93..-17.41% for Core and -5.85..+2.83% for security; corresponding service
P99 changes are +17.19..+19.82% and -0.50..+5.68%. These descriptive results
support reduced shared-label maintenance interference in this workload,
not a guarantee of no interference for every policy or phase.

Background and memory limitations
--------------------------------

The primary file batch's matched-kthread foreground CPU mean rises from
5.081ms to 6.972ms per paired run; cleanup means are 0.0628ms and 0.0526ms.
Signal foreground means are 0.0290ms and 0.0465ms; cleanup 0.0595ms and
0.0798ms. These count matched guest kernel threads, NOT fully attributed
workqueue/IRQ/softirq CPU. Different foreground run durations are explicit;
the values must not be reinterpreted as equivalent-window CPU rates.

The security query reports 704 logical management bytes per instance in the
performance guest, excluding Core, allocator rounding and retained policy
graphs. Eight root label references bound the root count, not total reachable
policy bytes. The fixed host registry additionally occupies 2048 B. The
ready/finished memory.current snapshots are all 4718592 B and do not resolve
this small extra charge. Zero observed kernel-stat fields do not prove zero
kernel memory cost. Post-250ms snapshots are not complete background drain.

The first file batch overlapped an idle failed-fixture VM during its early
part. It is retained as preliminary; the named quiet batch is the serial
replacement, not a selected best round. No build or diagnostic VM overlapped
that quiet file or the named signal batch. All rounds are retained.

Remaining limits
----------------

Pressure/batch-exit tail performance, complete background attribution and
stronger cold-start statistics remain unaccepted. Cache miss, stale label,
contention, full cache and unsupported credentials fall back to native.
Instance-local locks and references can still contend; final label put,
policy replacement, RCU and Core system-workqueue teardown remain shared.
Correctness evidence here does not prove independent-kernel fault isolation
or bounded interference latency. The feature remains default off.
