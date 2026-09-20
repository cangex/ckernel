In-flight termination and block regression evidence
==================================================

Tools/fixture source ``b91dfab67`` ran with the unchanged ``5c2bf8603`` ARM64
Image and fault-enabled configuration recorded in ``net-tx-evidence-20260920``.
No fault injection was active here. All devices were new disposable in-memory
devices in dedicated KVM guests. The host kernel and boot ID stayed unchanged.
Only the test module was rebuilt, with KCFLAGS=-Werror; its build had no warnings
or errors. No production kernel algorithm was changed by these test additions.

Evidence directory:
``/dev/shm/cis-x-20260919/evidence/block-clear-b91dfab67-20260920``.
Each fixed three-round cohort replayed independently with ``block_vm_check``:

* Inflight: 12 states, six BLOCK captures, serial
  ``inflight/x5-fixture-20260920-080417.log``, SHA256
  ``f90330bde8111adb4710e6f4bc19a19e25ed7f498f47b384abb654c277684099``.
* Lifecycle: 24 states, twelve captures, serial
  ``lifecycle/x5-fixture-20260920-080443.log``, SHA256
  ``3d9464f29ad57187ed6986f3429277038d8ceb10072d29584b3a89697d865b7d``.
* Plug merging: 24 states, twelve captures, serial
  ``merge/x5-fixture-20260920-080536.log``, SHA256
  ``ee329ce1eee414376097a99ce43ff4f8b0696069170c62048ceb0948ff6f4f1e``.
* Scheduler request merging: 12 states, six captures, serial
  ``merge-scheduler/x5-fixture-20260920-080629.log``, SHA256
  ``fb3eb9a9262e1af2748cb11d0461a917feaae2641c5fe06cdff700b3912b2d43``.

The new inflight cohort has 24 independently verified request lifetimes across
OFF/BLOCK. Twelve occur under observation: six driver-terminated requests and
six deferred normal completions. All were started and still pending after
submission. The production report retained the exact request episode, actual
completion status, 4096 bytes, submitter and bio billing identity. No duplicate,
false successful completion or unique blocking container was accepted.
This is native driver-owned termination, not generic cancellation-intent
attribution or an io_uring/AIO cancellation claim.

The older split, pre-submit cancellation, error, front/back bio merge, bounded
source overflow and scheduler transfer controls were rerun in full. A pre-submit
cancel still produces no request; split byte counts and partial provenance
limits are retained. More than eight bio sources do not become a fabricated
complete provenance list. Each cohort has a separate bounded permit, normal
source-off state, verified object removal, module unload and guest exit.

Combined CAPTURING process CPU peaks, in the above order, were 9991010,
10009690, 10047050 and 9999830ns. Whole-stage process CPU peaks were 173153900,
178271470, 202362820 and 187233460ns. Combined RSS peaks were 34443264,
34697216, 34897920 and 34566144 bytes. None exceeded the unchanged 40ms
CAPTURING guard. These figures exclude unquantified kernel/asynchronous cost;
they are not production throughput overhead or total memory accounting.

The initial ``bbdb9d418`` inflight/lifecycle runtime cohorts also completed,
but the fixture build exposed an existing field-spanning memset warning in
merge-output initialization. ``b91dfab67`` preserves validated request inputs,
clears the entire output structure, then restores those inputs. The warning
was not suppressed; the complete affected cohorts above were rerun after the
fix. Initial build/test logs and earlier packaging failures remain preserved.
