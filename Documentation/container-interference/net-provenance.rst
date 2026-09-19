Socket creator and acceptor observations
=======================================

Two default-off native boundaries extend the existing selected-cookie network
source without changing socket, queue or permission algorithms:

* ``__sock_create`` after successful protocol creation and
  ``security_socket_post_create``, for ``kern == 0`` only (phase 10).
* ``do_accept`` after protocol accept and optional peer-address copy succeed,
  immediately before returning the new file (phase 11).

They record a task observation inside the active window, not allocation/memcg
ownership or a guarantee that later FD installation succeeds. A passive TCP
child's acceptor is NOT relabeled its creator: physical child allocation may
have happened in softirq before the window. Window-before creation and kernel
sockets remain unobserved. No extra long-lived owner field/map or global owner
lock is introduced. The existing 64 selected-cookie watches and capture budget
remain unchanged; new short-lived sockets can exhaust that bound visibly.

SCM_RIGHTS, inheritance and changes of lock holder do not overwrite observed
creation. Native cookie, namespace and window join the facts; identical reused
addresses with different cookies stay separate. Contradictory creation/accept
records, duplicate origins, IRQ provenance and cookie identity changes reject
the stream. These facts are E2 relationships, not a claim the creator caused a
different container's wait. Current logical owner is still derived separately.

The origin VM plan freezes three alternating OFF/ON rounds of rightsShared,
rightsPrivate and rightsAccept. Creation/accept truth uses independent syscall
time brackets and SO_COOKIE inside the isolated actors. The accepted child is
passed with real SCM_RIGHTS; the recipient may become holder without becoming
creator. Existing pre-window inherited Socket fixtures remain regressions.
The source still cannot infer packet origin, skb allocation provenance, all
TCP locks or GSO/GRO data-buffer ownership from a Socket creator.

The first ``x4-net-origin-20260919-213027.log`` cohort is retained as FAIL.
Its controller publishes a future capture window during preparation; the
old workload created the Socket immediately on startup and waited only before
locking. Creation therefore preceded the actual window (1.380s vs 1.455s),
and the observer correctly reported UNOBSERVED, while 4/4 later lock relations
were captured. The new frozen origin fixture waits before creation, starting
preparation 300ms before a lock schedule at least 500ms into the window. No
timestamps, thresholds or observed records from the failed batch are changed.

Scoped origin runtime evidence
------------------------------

Kernel 172da0a96 Image and full modules built with the unchanged ARM64 config.
Image SHA256:
``e19dcc3efb9c9e33e7c40fe38305b19459d4f8671293049148e550eef583e1d4``.
Tools 7a6592c82 ran ``x4-net-origin-20260919-213550.log`` (SHA256
``41b58a024ed56e204350c6bb49824ee7d445d883885ed28e56878af588fd26d1``).

All 18 OFF/ON states / 9 captures passed independent checks: 18/18 origin
facts (15 user creates, 3 accepts) and 24/24 eligible logical-holder overlaps.
All three private-socket negatives produced no cross-container relationship.
Accepted children retained UNOBSERVED creation; transferred users did not
overwrite the creator or acceptor. Stop/source-off and module unload passed.
The maximum combined process CAPTURING CPU was 9.32107ms; process RSS peak
34,152,448 bytes. These are not total source callback CPU, kernel memory,
production tail-latency acceptance or population-wide attribution recall.
The original 40ms capture gate was retained, without the old 40.60ms exception.

Protocol-boundary follow-up
---------------------------

The earlier source selected family/protocol but did not check socket type.
The new creation boundary exposes why IPPROTO_TCP alone is insufficient:
an AF_INET SOCK_RAW Socket may also use protocol 6. The source now additionally
requires SOCK_STREAM. This narrows the source to its already declared contract,
not a workload or lock-algorithm change. The origin fixture adds real raw TCP
and UDP creations per actor inside the window, obtains independent cookies,
and rejects any corresponding TCP observation. No packet is sent by these
negative sockets. This new boundary requires its own rebuilt-kernel run;
the preceding origin cohort did not exercise these protocol negatives.

The follow-up kernel 6864117ae, tools ca43258a7 cohort
``x4-net-origin-20260919-220904.log`` passed 18 states / 9 captures, 18/18
origin facts and 24/24 eligible holder overlaps. All 36 independently named
raw TCP/UDP cookies were excluded; private TCP sockets still produced no
cross-container relationship. Serial SHA256:
``af198216e03156fceeb15fdd2d8a751fba6e1b5dc77f743aca60b1fa5f9f4851``.
CAPTURING combined process CPU peaked at 9.10725ms, RSS at 34,615,296 bytes.
The 40ms process capture gate was unchanged. Source callbacks, background CPU
and asynchronous kernel memory remain outside those process-only figures.

Kernel Image SHA256 is
``fbe205ea89fa9b80ed96f424fdf87f2edafb503f217d88b95c21196318ee0501``.
The earlier ``net-stream-origin-runtime-20260920`` attempt was refused before
QEMU launch because its immutable Image was in the dedicated memory-backed
build tree. The runner now accepts only its original evidence base or the two
already-authorized scratch roots after resolving symlinks and ``..``. Exact
image hashing, VM exclusion/lock, 4GiB root reserve and host protections remain.
That refused attempt is retained, not relabelled as a runtime success.
