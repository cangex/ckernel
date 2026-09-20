Y3 selected filesystem validation, 2026-09-20
============================================

Status and source
-----------------

PASS_SCOPED: 24 functional OFF/ON states were independently replayed on the
14 development host and locally. Native adapter Image and modules were built
at 3e68a6a72; tools and VM harness were frozen at
05bd9430fbbaf3d666f5369975cda772d5fe9423, tree
a4d32aac563cf532a76d63568a47aa5a6e2e4d3e. Subsequent changes before this
receipt were userspace/tests only. The host kernel was not replaced.

Four cases, three alternating OFF/ON rounds, two containers, private directories,
96 checked 64-KiB files per actor and a two-second selected window were used.
Cases: shared filesystem, separate filesystems, entirely unselected filesystem,
and shared orphan-file-enabled filesystem. No shared writable directory or file
was needed. Scratch disks have explicit serials; mounted dev_t, superblock magic,
UUID and orphan feature bits are checked before the workload starts.

Results
-------

* Shared legacy filesystem, each ON round: 194 commit-wait checks with positive
  native wait iterations, 12 allocation-group observations, 12 legacy orphan
  adds and 12 deletes. No orphan-file event.
* Separate filesystems: only the selected actor is retained, with 97 commit
  checks and six observations of each legacy/group operation. All 385 native
  source entries from the unselected filesystem are accounted as filtered.
* Entirely unselected filesystem: 770 source entries per ON round, all filtered,
  zero accepted events and no invented shared-resource association.
* Orphan-file case: 194 commit checks, 12 allocation-group observations and 24
  orphan-file operations, with zero legacy orphan-list events per ON round.
* All 12 OFF states have zero change in every native source counter. All idle
  endpoints are disabled. No recursion, loss, resource errors, kernel warnings
  or invented lock holders were accepted. All workloads returned success.
* Nine control negatives/checks pass, including invalid input/FD, non-ext4,
  exclusive immutable selection, nonzero read offset, inherited unprivileged
  FD, generation renewal and revocation with a live no-op probe. A new lease is
  rejected until the old attached probe is detached.

The last test does not claim a filesystem operation was demonstrably in flight
at revocation. That exact race remains unverified; native end generation checks
and the observed revocation protocol are different evidence.

Limits and cost
---------------

Transaction-switch waits did not occur in this cohort: that producer is built
but not runtime-covered by this result. Allocation-group use is not evidence of
group-lock contention. Sampled orphan acquisition wall brackets do not identify
all holders. Journal participation and waiting do not identify a unique blocker.
Read-only image/page-cache contention, complete journal contributor lifetimes
and orphan-add error-cleanup's second lock are not covered. Unknown or unfinished
operations are not converted to zero cost or attributed to another container.

Process CAPTURING CPU peaks range from 9.289060 to 10.107210 ms per session;
combined process RSS peaks range from 31,969,280 to 39,280,640 bytes. These are
partial implementation cost records, not total monitoring CPU or memory, and do
not accept Y7 overhead. BPF/native/worker/background costs and target/bystander
performance require the later joint measurement.

Builds and retained failures
---------------------------

709 Python tests pass on Linux (two Linux-only tests skip on macOS); the separate
21 owner and seven profile tests pass. Full ARM64 Image/modules builds pass with
the new native adapter enabled and with CONFIG_CIS_OBSERVE disabled. OFF symbols
do not contain cis_fs adapter calls in vmlinux, ext4.ko or jbd2.ko. OFF Image SHA256
is baf8c78993d8b5c83fabc1c244a2a9dd909b0488bf236e39be9f4cfde2f90bee.

Failed preparation/runtime cohorts are retained: missing stat header at
b95f1b04b; old formatter at 699fd98a7; read-offset test expectation at 8a951594a;
reversed virtio enumeration at c1fd5777c; host harness variable shadowing at
64e9b66be. None was changed to PASS or mixed into the final matrix.

An isolated e2fsprogs 1.47.2 build, not a host installation, formats newly created
regular scratch image files. Source SHA256 is
08242e64ca0e8194d9c1caad49762b19209a06318199b63ce74ae4ef2d74e63c;
kernel.org HTTPS checksum was verified, detached PGP signature was not.

Evidence and reproduction
-------------------------

Host evidence root: /dev/shm/cis-x-20260919/evidence/

* y3-native-3e68a6a72-20260920: enabled Image/modules, config and hashes.
* y3-image-tools-20260920: isolated formatter source/build/tool hashes.
* y3-filesystem-05bd9430f-20260920: plan, raw serial, 24 states and replay.
* y3-off-05bd9430f-20260920: disabled full build, modules and hashes.

Local downloaded evidence and independent replay are under
.codex-tmp/container-interference-20260916/y3-filesystem-evidence-20260920,
y3-filesystem-local-recheck-20260920 and y3-off-evidence-20260920.
Replay with PYTHONPATH=tools/container_interference and
tools/container_interference/y3_filesystem_vm_check.py SERIAL NEW_OUTPUT.
The isolated host runner and guest init scripts are in
tools/testing/selftests/container_interference/; preparation and VM command,
module/device identities and all source hashes are retained with the evidence.

Y4--Y7 are not accepted by this receipt.
