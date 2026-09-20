Original TCP release backend and retained-clone evidence
======================================================

Scope and sources
-----------------

This is a bounded original-TCP-skb prototype, not general packet ownership,
physical reclamation, allocator contention attribution or X7 certification.
The ARM64 Image and modules were built from ``55795f96b``. Image SHA256:
``753ac5f59b329afab597e147d6565883881696d09c35a420f9bb160285c6b7d9``;
vmlinux SHA256:
``257a865fb53968abd8c799104aa90f7f5e6a8e4b34965f22134298c7be6bb9df``.
Config SHA256 remains
``40c51dd99fd375ceeadf5db1cc8f78cd7cff2be15d65f750351118d08d49924d``.
No host kernel, Docker service, quota policy or other branch was changed.

Independent native reference truth
---------------------------------

Tools ``0c9092c24`` completed the frozen 12-state OFF/NET matrix, comprising
ordinary original release and real retained ``skb_clone`` cases, three
alternating rounds and two container requesters per state. It uses a real
TCP repair send queue, not fake observation events or wire-delivery claims.
Independent ioctl observations record the original/child addresses and native
data/fclone reference counts. The launcher explicitly closes its inherited
socket reference before testing the business close. The original closes before
the retained clone is dropped. No packet-payload or clone-child owner is inferred.

All twelve observed originals matched the independent send/close intervals
and container identities: six ordinary releases returned both data and header
backends; six cloned originals retained shared data and their fclone pair.
The latter are not reported as fully freed. All six captures and fixture
unload passed, without kernel warnings. The independent ``net_vm_check.py``
replay passed all twelve states. Raw serial:
``net-release-clone-0c9092c24-20260920/x4-net-txrelease/x4-net-txrelease-20260920-093252.log``;
SHA256 ``5feb4a34b495d49074543578d31323db049e80c156cffe55a4e991e0ea2d95c2``.
Paths here are below ``/dev/shm/cis-x-20260919/evidence/`` on host14.

Combined-process CAPTURING CPU peaked at 9.885510ms, whole-stage process CPU
at 107.017590ms and combined RSS at 35,291,136 bytes. The existing 40ms
CAPTURING guard was not changed. These are not total observer CPU or kernel
memory. The native release callback counter includes non-target entry/end
callbacks; wrappers, interruptions and full asynchronous costs remain unknown.
The backend interval is elapsed wall time, never pure CPU or another tenant's
blocking time. A delayed old end uses its frozen address/time token even if
another requester has reused the address; the parser regression rejects an
end redirected to the new episode.

Fresh-kernel failure, admission, backlog and protection regression
-----------------------------------------------------------------

The following independently replayed serials remain separate fixed cohorts:

* ``net-release-55795f96b-20260920/txadmission/x4-net-txadmission-20260920-091015.log``:
  twelve states, 288 request episodes, all 288 backend returns observed.
  270 returned data/header backends and eighteen retained clone references.
  SHA256 ``7af441c5229c8cb02c9a907e4b40e1d6d2b1f23c53bb42462010b8c89eb2b1bb``.
* ``net-release-55795f96b-20260920/txfailure/x4-net-txfailure-20260920-091054.log``:
  twelve states, 96 request episodes, including 36 actual native allocation
  failures with no invented free. All sixty allocated originals observed
  their release return, with shared references explicitly retained.
  SHA256 ``1e81aee6032728cac68a295098dd9dfe35e7639eff3dc23c475aac4f017e98ab``.
* ``net-release-clone-e2edeaf2a-20260920/x4-backlog/x4-backlog-20260920-091605.log``:
  six states, native backlog/service truth and fifteen original TX backend
  returns; receive-packet ownership remains unknown.
  SHA256 ``9aac9bb790dc6e10ca7eb65c4c2856ed012d0f396704e083ce6cb41e69507d10``.
* ``net-release-clone-e2edeaf2a-20260920/x4-net-guard/x4-net-guard-20260920-091621.log``:
  six states; all three dense captures were rejected and actually detached,
  followed by continued business. No holder or skb episodes were accepted
  from those incomplete captures. Maximum CAPTURING process CPU was
  44.365200ms before cooperative stopping, not a raised 40ms limit or a passed
  dense-profiling performance result. Whole-stage process CPU was at most
  201.295380ms and RSS 39,288,832 bytes. Source quieting was verified.
  SHA256 ``15497e68f16ceb7f8c962aa4fd7e789884e0ebf6efb84f8bdcd361d6b2e36da3``.

Failures retained and explained
------------------------------

The first clone-fixture build referenced a helper absent in this OLK. The
next runtime checked the unsent write queue, but native TCP repair push had
already moved the original to the retransmit tree. A subsequent test retained
the launcher's socket FD, so release legitimately occurred outside the business
close bracket. These failures were not erased or accepted by relaxing checks.

Tools ``8989c4322`` then exposed an actual test-fixture bug: direct cloning of
a queued TCP skb copied the sorted-list links aliased with destination state.
Dropping that clone caused an isolated guest panic in ``dst_release``. The
serial ``net-release-clone-8989c4322-20260920/x4-net-txrelease/x4-net-txrelease-20260920-092601.log``
is retained as FAIL. The fixture now uses native ``tcp_skb_tsorted_save`` /
``tcp_skb_tsorted_restore`` and clears the child's ``dev`` alias, matching
``tcp_transmit_skb``. The complete fixed cohort above was rerun; it did not
reuse successful pieces of the failed matrix. Host boot ID remained
``20bf4ee1-355a-4c77-a494-0c265b05c8d5`` throughout.

Bulk/NAPI/morph release remains entry-only. Clone/GSO/GRO transformations do
not gain payload provenance from shape flags. Source and full cost limitations
remain explicit. New-kernel joint/control regressions and the full original
X0--X7 minimum-contract audit are separate from these scoped passes.
