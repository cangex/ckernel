Y4 public I/O validation, 2026-09-20
===================================

Status and source
-----------------

PASS_SCOPED: 24 private-file OFF/ON states and 36 deterministic tag API OFF/ON
states pass independent replay both on the development host and locally.
Native ARM64 Image/modules are frozen at b5d90fb8f. Private-file tools/harness
are cac5c0103; the extended tag fixture and tools are
b2bca254337a65ac5a024ff63600de18a9f8a567, tree
51f3ffcb7dddedf43015ac5c4cbbef5dc873fa1e. No host kernel or service was replaced.

Private-file workload
---------------------

Two containers each create, write, fdatasync and verify their own 8-MiB file
in separate directories. Three alternating OFF/ON rounds cover synchronous
and buffered writing on shared or separate scratch devices. Device identities,
private inodes, complete checked contents, successful exit, cgroup resource
errors, source attachment and post-window detachment are independently checked.
Each selected profile window is two seconds. Completed workload timing is kept
separately; it is not automatically a complete-window throughput denominator.

The dedicated VM uses dirty_background_bytes=1 MiB and dirty_bytes=4 MiB.
Each disposable emulated device is limited to 32 MiB/s write service. These
are controlled pressure conditions, not the host policy or a physical-device
performance claim. The two scratch filesystems have different orphan features;
their layout is recorded and is not an isolated causal comparison of devices.

Every synchronous ON state contains 258 request episodes and 512 driver plus
scheduler tag snapshots. Buffered ON states contain 18--52 request episodes,
36--104 tag snapshots and 9--91 positive requested native dirty pauses. All
private-device snapshots map to the correct actor/device; different device
tag pools are not joined. Synchronous cases have no dirty pauses in this cohort.
Neither workload produces a tag pool wait, so ordinary-file tag-pressure
incidence is explicitly NOT_OBSERVED, not inferred from request volume.

Deterministic tag tests
-----------------------

A VM-only test module allocates from two native blk-mq pools of depth four.
It does not read or write a real device. Six cases each run three OFF/ON pairs:
exhaustion, separate pool, available slot, NOWAIT rejection, issue during a
shared-pool wait and issue on a different pool. The issue cases use a zero-data
passthrough command and native request accounting, issue and completion.
Accidental data I/O is rejected. Independently retained API receipts record
queue, tag, task start identity, occupied count and call boundaries.

The shared issue case yields one correctly bound issue snapshot during the
other container's closed wait on the same queue/bitmap. The separate-pool case
does not yield that relation. Three rounds pass each. This validates the
association mechanism, not common-application frequency, complete slot
lifetimes or a unique causal blocking tenant. Existing NOWAIT/no-sleep and
available-slot negatives remain valid. Module unload and source-off checks pass.

Quality, costs and exclusions
----------------------------

All 60 functional states have successful workload/truth results and no accepted
loss, recursion or fabricated blocking tenant. Independent replay uses raw
captures, not the guest's reported PASS. Invalid windows, request reuse, changed
capacity, nonoverlap, duplicate records and unknown writeback accounting have
separate unit negatives. The tag relation is E2 association, not E3 causality.
Writeback-accounted container, dirtying/paused task and worker remain distinct.

Private-file process CAPTURING CPU peaks are 11.164940--14.729800 ms and combined
process RSS peaks are 35,753,984--37,380,096 bytes. These do not include every
native/BPF/background cost and are not Y7 overhead acceptance. Tail latency,
target/bystander degradation and complete source budgets need joint testing.
No claim of complete tag occupancy, all request contributors, device-internal
causes, exclusive dirtier or unique blocker is made. Pauses not closed before
detachment remain uncovered; their absence is not zero waiting time.

Builds, failures and evidence
----------------------------

719 Python tests, 21 owner tests and seven profile tests pass on Linux. Full
ARM64 Image/modules builds pass with the adapter enabled and CONFIG_CIS_OBSERVE
disabled. The disabled vmlinux has no cis_writeback_pause tracepoint. The first
private-file cohort at e48dd75d1 rejected an underscore-containing session nonce
before attaching a collector. Its evidence is retained; admission was not relaxed.

Remote evidence root: /dev/shm/cis-x-20260919/evidence/

* y4-native-b5d90fb8f-20260920: enabled full build, config and hashes.
* y4-io-cac5c0103-20260920: 24 private-file states and raw replay.
* y4-tags-b2bca2543-20260920: 36 native tag API states, fixture and raw replay.
* y4-off-b2bca2543-20260920: disabled full build and hashes.
* y4-io-e48dd75d1-20260920: retained rejected-nonce cohort.

Local evidence/replays are under .codex-tmp/container-interference-20260916/:
y4-private-evidence-20260920, y4-local-recheck-20260920,
y4-tags-evidence-20260920, y4-tags-local-recheck-20260920 and
y4-off-evidence-20260920. Reproduce replay with PYTHONPATH set to
tools/container_interference and y4_io_vm_check.py or tag_vm_check.py, passing
the immutable serial log and a new output directory. The VM manifests record
kernel/initrd hashes, pinned CPUs, disposable devices and all commands.

Y5--Y7 are not accepted by this receipt.
