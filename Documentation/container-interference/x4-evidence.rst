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
