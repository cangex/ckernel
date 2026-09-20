Y1 public-resource boundary view validation
==========================================

Status: PASS_SCOPED. Frozen tools: f01cb53b6, including 8404566a5. Frozen
guest kernel: 55795f96bfd626d91090fd7389ddf2771ebaf74c. The kernel image hash
is unchanged from Y0. This receipt does not accept Y2--Y7.

Raw evidence on the dedicated host::

  /dev/shm/cis-x-20260919/evidence/y1-topology-f01cb53b6-20260920

Downloaded evidence, per-file hashes and frozen-source local replays::

  .codex-tmp/container-interference-20260916/y1-final-evidence-20260920

The independent topology checker passes 37 checks over real disposable-VM
containers: common ancestry, distinct private tmpfs and network namespaces,
affinity changes, descendant-cgroup migration, mount-namespace replacement,
generation changes, exit and cgroup deletion/recreation. The live daemon also
unregisters/reregisters the same group and deletes/recreates another group;
the independent joint checker verifies both generation transitions.

The joint cohort passes nine predeclared alternating states (OFF, IP and
backend-only, three rounds), with four independent file/VMA containers and
rotating target/bystander roles. All six sessions have accepted endpoint
topology and complete source cleanup. Raw serial replay on the local host,
using the frozen f01cb53b6 analyzer, reproduces PASS and PASS_SCOPED without
errors. Kernel warnings are absent; host kernel and boot ID are unchanged.

The separate live-topology snapshots consume 0.028--1.116 ms of thread CPU
and at most 25 reads / 3465 bytes each in this small VM. These observations
are not maximum execution-time guarantees. Complete session process, manager,
kernel-thread, memory and arrival-relative latency records remain in the
joint verification output. P99 is record-only; no production cost claim is
made. Configured sharing is never promoted to observed contention.

The first 8404566a5 run also passed, but review found that the survey reference
epoch omitted the new resource fingerprint. The f01cb53b6 follow-up includes
that binding and suppresses automatic old-reference comparisons for partial
or changed topology. Unit tests exercise fingerprint changes and partial
coverage; the final VM run exercises the changed source. Historical evidence
is retained, not replaced. ARM64 preparation builds and regression suites
pass; local non-Linux platform skips are not counted as runtime passes.

Eight-task, cgroup-depth and mount limits remain explicit. Equal endpoint
snapshots cannot exclude a change-and-reversal inside the window. Stacked
devices, overlay lower layers, veth peers and NIC queue attribution remain
unresolved here. The boundary view provides configuration context, not proof
of a particular accessed object, lock holder or causal blocker.
