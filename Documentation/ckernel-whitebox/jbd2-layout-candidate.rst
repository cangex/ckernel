JBD2 state-lock layout: bounded experimental candidate
====================================================

Status
------

This is an experimental layout change, not a demonstrated performance fix.
No candidate bare-metal deployment or performance comparison has occurred.
The complete ARM64 Image and modules built successfully. Only LOCALVERSION
differs between the reference and candidate configuration.

The reference kernel tree is 90bda14c1a6dcc2df4ae12c28fa4e0ff82f2fbd8
(snapshot commit 622eeb9a4278d53debcdcdb8f49b816be45f9a15). The candidate
parent is 87eeb94454973e0f31536adc21847a2de8418518; its old W1/W2/W3
experimental behavior changes have already been reverted.

Motivation and limitations
--------------------------

On the fixed no-model Go installation replay, the 24-copy native exploratory
run took 21.22% longer than its own solo mean (three rounds). About 97.6% of
the elapsed increment was in the extraction action. That is a phase-level
observation, NOT a JBD2 loss attribution. Separate PMU/sampling runs showed
increased tar kernel cost and samples near start_this_handle read locking
and unlocking. Sparse samples and PMU skid cannot quantify an instruction's
contribution or prove false sharing.

The change aligns j_state_lock using ____cacheline_aligned_in_smp. It retains
locking, transaction identity, credits, update counts, barriers, commit,
abort, and recovery semantics. Real sharing of the lock remains. It is not
a container-private journal, lock removal, permission bypass, or accounting
exemption.

Prior art: JonasZhou-oc, "[PATCH] jbd2: avoid false sharing with j_state_lock",
2026-09-02, Message-ID 20260902070331.820322-1-jonaszhou-oc@zhaoxin.com,
https://lists.openwall.net/linux-kernel/2026/09/02/544 . This fixed-OLK
experiment adapts that idea; it does not claim novelty or upstream merge.
Results from another kernel/architecture do not establish results here.

Measured build layout
---------------------

In the matched ARM64 builds, j_state_lock moves from offset 72 to 128 and
sizeof(struct journal_s) changes from 1488 to 1600 bytes. This is 112 bytes
of structural growth, not a measurement of allocator or system memory cost.
The source uses a 64-byte SMP alignment. A reported 128-byte L3 line does
not establish the hardware's coherence invalidation granularity.

Candidate Image SHA256:
a5524ea7ef17b0da73ece5e04d24ac3c40729aa13fcbf572f73d97f0ce2ea4cd

Candidate config SHA256:
e30a7211e38fa9ad57e3a73d1547ca745c884558e40cbb0706197874460ef964

The header layout requires a matching full kernel/module set. Never replace
only jbd2.ko in an old-layout running kernel.

Bounded correctness validation
------------------------------

Both reference and candidate ran in disposable ARM64 KVM guests with SELinux
Enforcing and AppArmor disabled. Only each test's own disks/VMs were modified.

* Eight workers, 1024 total create/fsync/rename/hard-link/open-unlinked rounds.
* Disposable ext4 exhaustion, unlink, and successful allocation/readback.
* Deliberate termination of the test VM after a durable marker, followed by
  ext4 journal recovery and marker verification in a new VM.
* Read-only e2fsck checks of the resulting test disks.
* Three fresh-overlay Go replays per kernel, in reference/candidate/
  candidate/reference/reference/candidate order. All six ran the frozen
  six-tool replay and passed the unmodified official two-check evaluator.
  The expected initial missing-Go command failure was retained. Container
  limits were 4 GiB, 128 pids and CPUs 0-3; no OOM was observed.

The filesystem operation fixture is tools/ckernel_whitebox/w3_fs_test.c.
Environment packaging, the ENOSPC fixture, input hashes and guest logs are
retained with the dated experiment delivery, not kernel build products.
These tests are not full xfstests, KASAN/lockdep validation, power-loss-device
verification, or bare-metal performance evidence. VM timings are not used
as optimization results.

Two reference initramfs preparation failures and one Go boot handoff failure
were retained: rootfs relabeling, module-load ordering, and replacement of
the usr-merged /lib symlink. Correcting fixture setup did not disable SELinux
or alter workload grading. Deleted redundant failed disk/initramfs payloads
are identified in the cleanup receipt; their logs and manifests remain.

Bare-metal admission and stopping rule
-------------------------------------

Host deployment requires separate approval, a freshly checked recovery path,
matching Image/modules/initramfs, storage headroom and workload quiescence.
The previous reference-kernel maintenance approval does not authorize this.

Use the unchanged Go task at solo/24 first. Separate OFF and diagnostics;
predeclare reboot-aware paired blocks, baseline repeats, sample count and
statistics before performance runs. Report each kernel's absolute solo and
loaded elapsed times as well as its own elapsed interference ratio. Retain
neighbor/batch completion, CPU and memory costs. The default business gate
is at least 3% improvement with a supporting 95% paired interval, no more
than the predeclared 2% solo/neighbor/batch degradation bound, and at most
5% extra CPU/memory cost. Insufficient intervals are inconclusive.

If layout changes but net business benefit fails the gate, close this
candidate rather than repeatedly trying alignment multiples. Even a positive
business result without direct coherence evidence is a layout-effect result,
not proof that all slowdown came from false sharing.
