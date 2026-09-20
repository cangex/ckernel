X0--X7 scoped prototype release, 2026-09-20
=========================================

Result: PASS_SCOPED for the bounded prototype contract documented in
x7-prototype-contract.rst.  The independent final index contains 48 checks
over 45 distinct raw serial files and 31 capability rows.  Three aliases
exercise different contracts on the same data; they are not additional
experiments.  Every check passed its own supported scope.  The aggregate
checker found no missing minimum stage evidence.  This is not full Linux
coverage, strict P1 certification or a production deployment approval.

Final same-kernel rwsem regression
---------------------------------

Tools ``6f83712af0cd05b1dcd2980c7029c778ca78642c`` with Image ``55795f96b``
completed the unchanged ten-case, three-round OFF/ON joint matrix: sixty
states, thirty captures, four rotating container roles and 360000 ordinary
file/VMA operations without errors or timeouts.  All 24 independently
eligible >=1 ms overlap relationships were matched.  The three private
captures had zero E2 edges.  Non-owner, pre-window, abort, trylock, downgrade
and address-reuse cases retained their existing conservative rules.

Peak CAPTURING combined-process CPU was 10.251580 ms; whole-stage process
CPU 114.677930 ms; combined RSS 35897344 bytes.  No CPU guard violation
occurred.  Across target/bystander pairs, arrival-relative P99 differences
ranged from -535330 to +436010 ns.  Offered-load throughput differences were
-0.046389% to +0.055908%; these are not saturation-capacity measurements.
P99 remains record-only, not a passed production tail-latency gate.

Raw serial:
``x7-rwsem-final-6f83712af-20260920/rwsem/x7-rwsem-joint-20260920-112408.log``
under ``/dev/shm/cis-x-20260919/evidence`` on host14.  SHA256:
``6cb2f7639553767ec2e7cec387e6712e0cd250a1fe21bb77476b92a15cb85dbe``.
The built-kernel notes hash is
``3d98cb357de1235e719fc2f3975f3213731df96b2da9636f1de04e8aa4bb70ca``,
also present in the final common/SLUB/mixed/control/routing regressions.

Code and artifacts
------------------

Final reporting runtime was ``6f83712af``.  Offline contract implementation
``2b9649474`` passed 664 Python, 21 owner and seven profile tests on ARM64,
with no skipped tests.  The subsequent offline-only hash-inventory change
``00382e22f`` passed the local 664-test suite with one platform-specific skip;
the same platform test passed on ARM64.  Kernel/probe algorithms were not
changed by these offline acceptance updates.  Full ARM64 Image/modules and
thirteen BPF objects were built earlier for the pinned kernel/tools lineage.

* Image SHA256:
  ``753ac5f59b329afab597e147d6565883881696d09c35a420f9bb160285c6b7d9``.
* vmlinux SHA256:
  ``257a865fb53968abd8c799104aa90f7f5e6a8e4b34965f22134298c7be6bb9df``.
* Config SHA256:
  ``40c51dd99fd375ceeadf5db1cc8f78cd7cff2be15d65f750351118d08d49924d``.

The private delivery directory is named
``CKernel-周期Profile-X7原型交付-20260920`` in the user's project workspace.
It contains the Chinese report, pinned original-file index, independently
replayed coverage JSON/Markdown, commit inventory and publication proof.
Original address-bearing serial files stay administrator-only outside Git.
Reproduce with the supplied input index and a new output directory::

  python3 tools/container_interference/coverage_matrix.py INDEX NEW_OUTPUT
  make -C tools/container_interference check-python

Source references and source hashes are per cohort.  Historical truth tests
are not claimed as runs on a newer kernel.  The new same-kernel joint groups
provide the release-level compatibility/cost screen; they do not create
independent truth for quiet ordinary-application windows.

Protection and limitations
--------------------------

The host stayed on ``6.6.0-ckernel-rmaster-20260904+`` with boot ID
``20bf4ee1-355a-4c77-a494-0c265b05c8d5``.  Final verification found no active
test VM.  Root free space was 4375138304 bytes, above the retained 4 GiB
floor.  One owned historical initrd was preserved byte-for-byte on /home
and its original path became a verified symlink; no evidence was deleted.
No host reboot, Docker restart, global cleanup or automation was performed.

The original 40.600240 ms one-case exception, rejected dense captures,
source-recursion failures and development fixture panic are preserved,
not retroactively accepted.  Guard tests prove rejection/detachment and
continuing work, not valid dense attribution.  Full source/background CPU,
kernel memory, hardware cache-line causes, transformed skb payload ownership,
arbitrary lock holders and firmware-internal blocking remain unproven.
Bounded waits are observed intervals, not proof of a bound on future latency.
