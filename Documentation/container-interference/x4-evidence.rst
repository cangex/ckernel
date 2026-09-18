X4 evidence ledger
==================

Native TCP logical ownership, 2026-09-19
--------------------------------------

Dedicated ARM64 KVM only, eight vCPUs. Kernel a63f83cc2176452a63fa1854514ce0e142863f0e,
tools 3ff8b6eafda3feffe51e1bda5cda79edc4d5a72c. Host kernel unchanged.
Evidence: ``/root/cis-20260916-232524/evidence/x4-native-net-fix1-20260919``;
serial ``x4-net-20260919-023929.log``. Initrd SHA256:
729331b67513a82836fcc044ee0713a148f1a4bbc4fe99024e9be6665500e8e1.

Native TCP socket FDs are inherited into two distinct container roots. They
retain the original VM network namespace; this is deliberate shared-object
testing, not a claim that each socket was created in the receiving container.
A disposable module holds the actual ``lock_sock`` for 30 ms and records
ioctl entry, successful acquire and release brackets separately from CIS.
The module is never loaded on the development host. The fixture deliberately
sleeps while holding the logical lock, not the underlying spinlock.

Shared socket, distinct private sockets and alternating holder cases each
completed three predefined OFF/ON pairs: 18 states, nine captures. Independent
reanalysis passed all states, with 24/24 eligible shared/switch relations and
no private-socket false cross-container edges. This is controlled-fixture
recall, not recall for arbitrary network traffic. Every capture has zero BPF
program recursion misses, valid source barriers and no reported record loss.

Peak CAPTURING observer-process CPU across these captures was 9.12287 ms;
peak combined observer RSS 37,388,288 bytes. These are existing engineering
budget counters, NOT total native entry/background CPU or a complete kernel
memory bill. No production throughput/P99 acceptance is claimed. The earlier
build using host BPF headers failed and is retained in
``x4-native-net-20260919``; the ABI-prefix compatibility revision fixed it.

X4 remains INCOMPLETE. Real backlog/service/skb-release validation, lifecycle
reuse and transfer tests, ordinary application/cost coverage and the remaining
scope limitations must be assessed separately. An accepted logical holder
relationship is not proof of the unique cause of a throughput slowdown.

Backlog first live run, preserved failure
----------------------------------------

``x34-backlog-lifetime-20260919/x4-backlog-20260919-024736.log`` correctly
observed four actual loopback TCP backlog episodes, service on the receiving
container task and three delayed softirq releases. The test incorrectly
required release before recv returned; the final skb was still pending when
the capture ended. This cohort FAILED and is retained.

The native explanation is ``tcp_eat_recv_skb -> skb_attempt_defer_free``:
the skb may be queued on its allocating CPU's softnet defer list, then freed
by ``skb_defer_free_flush -> napi_consume_skb`` on a later NET_RX cycle.
The revised test freezes four held 128-byte transfers plus one ordinary
unheld, payload-verified transfer at +450 ms to exercise deferred draining.
It does not change any global sysctl or force kernel reclamation. Per-episode
release timing remains observed, with delayed release explicitly reported;
the extra transfer does not prove complete systemwide drain. Runtime closure
of this revision is still pending.
Native backlog and deferred release cohort
-----------------------------------------

``x4-backlog-drain-20260919`` used kernel a63f83cc2 and tools 419251efe.
Independent ``net_vm_check.py`` accepted six fixed OFF/ON n=3 states with
four payload-verified TCP transfers per state. A fifth unheld transfer at
the frozen 450 ms offset lets native deferred skb frees drain. The original
failed cohort remains preserved: application recv completion was wrongly
used as a release deadline, whereas native remote-CPU NET_RX deferred frees
can occur later. No kernel behavior or capture budget was changed.

Three captures matched queue entry, service and release-entry episodes.
Maximum combined-process CAPTURING CPU was 9.62383 ms, maximum combined RSS
33,726,464 bytes, with zero per-program recursion misses. Release entry is
not final backend completion, and packet creation/clone ownership remains
unknown. Broader network counterexamples and total cost are still open.
