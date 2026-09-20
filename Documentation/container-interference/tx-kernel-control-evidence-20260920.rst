Control and mixed-source regression on the TCP-context kernel
============================================================

The dedicated ARM64 KVM guest retained Image/source ``5c2bf8603`` from
``net-tx-evidence-20260920.rst``. Host kernel/boot ID did not change. This
regression does not certify production monitoring or a later kernel.

Control fixtures used tools ``d4a30a079`` and the directory
``/dev/shm/cis-x-20260919/evidence/tx-kernel-closure-99d6bdd81-20260920``.
Independent ``x0_check`` replay passed the following complete case sets:

* Normal control: 16 checks, 14 sessions, complete terminal scope audits.
  Serial ``control/x0-control-20260920-074740.log`` SHA256
  ``32ffdf76a3d010c5d687737e10bcbec5ca744b6fef1b06830db34f8670880f15``.
* Deliberately failing cleanup verifier: one check/session. Admission remained
  FAULTED despite an independent real verifier finding no residual objects.
  Serial ``fault/x0-fault-20260920-075039.log`` SHA256
  ``94007ee8f15da0b2a4b12e288ab140c4a836af595a43d048040d0733a9597a17``.
* Process failures: 16 checks/sessions, covering all twelve collector workers,
  stopped worker/controller and controller/both-process SIGKILL recovery.
  Serial ``crashes/x0-crashes-20260920-075047.log`` SHA256
  ``78eb9e608364aff72aeedbf5e514bc72e5990fe6a93563c3a7acb3da5a1a50be``.

Interrupted captures keep FAILED results and incomplete terminal scope;
``scope_audit_complete=false`` in the crash cohort is retained. The PASS is
cleanup/recovery correctness, not admissible profiling or zero lost data.
The real 1200-second expiry case was not repeated in this cohort and is not
silently inherited as fresh-kernel expiry evidence.

Two new mixed-workload attempts failed packaging: one omitted net_vm.py and
the next omitted the container's net_workload executable. Both failures and
the latter's ordinary/IO results are retained; neither is mixed-source PASS.
The complete guest was rebuilt, checking all required harnesses/executables,
and all 24 frozen states were rerun without workload, sampling or gate changes.

The successful mixed cohort used tools ``bbdb9d418`` with the same Image, in
``/dev/shm/cis-x-20260919/evidence/block-inflight-bbdb9d418-20260920``.
Serial ``mixed/x7-mixed-20260920-075806.log`` SHA256
``b515af389866d90b7ddd392bb7453626055b5cc2acf524d2473e4365939154ef``.
Independent ``mixed_vm_check`` replay was PASS_SCOPED for 24 states/18 captures.
The four ordinary containers completed 144000 fixed-rate operations with no
errors/timeouts. All 384 direct-I/O operations overlapped real bracketed TCP
holds. Shared Socket truth matched 4/4 relationships in each of three NET
windows; private Socket controls produced no cross-container relationship.
I/O submitter/billing provenance is separate from Socket ownership, and no
unique device blocker is inferred.

Combined CAPTURING process CPU peaked at 9774090ns, whole-stage process CPU at
186163060ns, and combined RSS at 39632896 bytes. These are not exclusive total
kernel/background costs. Paired target P99 changes ranged from -648790 to
+443640ns, bystanders from -497530 to +473610ns, retained as record-only.
The fixed offered rate is not saturated throughput. Quiet source switches,
object removal, module unload and guest shutdown passed. This closes the
stated new-kernel mixed/control regressions, not all X7 obligations.
