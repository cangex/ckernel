Bounded explanation prototype
=============================

The prototype is a functional experiment, not a P1 performance acceptance.
The default controller policy remains strict. No P1 receipt is manufactured.
The explicit ``--admission-policy prototype --prototype-permit FILE`` mode
requires a private root-owned permit bound to source hashes, the current boot,
and the declared disposable ARM64 QEMU environment (8 vCPUs, 4 GiB, 4K pages).
These are operator guardrails, not attestation against a hostile administrator.

A permit lasts 20 minutes, permits at most four registered roots and two
targets per session, and limits a controller state directory to 32 sessions
of at most two seconds. The counter survives a daemon restart. Existing
identity, storage, CPU, data, terminal-quality and cleanup limits still apply.
Expiry pauses periodic collection. A permit cannot be used as a strict P1
receipt. Host deployment and automatic mitigation are out of scope.

``explain.py --record SESSION.json --events SESSION.jsonl --output REPORT``
creates a JSON and readable Markdown explanation. It joins only finalized,
quality-checked, same-session evidence. Owner edges require known identities,
object generations and closed wait/hold intervals. It preserves unknown,
loss and incomplete records; a missing sample is not proof of no contention.
The input is bounded to 16 MiB and presentation to 128 edges, with omissions
reported. Kernel addresses in raw reports remain administrator-only.

An IP hotspot is a candidate, not an owner. A holder/waiter edge describes
observed exclusive ownership overlapping an observed wait, not total business
loss. Holder off-CPU overlap is not additive to wait time or pure spin time.
The prototype does not certify production overhead or full-kernel recall.

``prototype_vm.py`` freezes five owner cases and six actual 60-second periodic
slots with two continuously running container workloads. Readiness precedes
scheduling; every session must finalize, remove its BPF objects and meet
evidence-quality checks. This test is not an OFF/ON performance experiment.
Failure logs and protocol messages must be retained, not retried until green.
