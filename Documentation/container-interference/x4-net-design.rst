X4 selected TCP observation design
==================================

Status: native source hooks and BPF prototype under development, not runtime
accepted. No protocol, socket ownership or queue algorithm is changed.

Native ``sk_cookie`` identifies a socket life. The existing cookie allocator
may allocate a cookie the first time an enabled source observes a socket; that
cost is not zero. A boot-frozen low-bit mask selects whole TCP socket lives,
not arbitrary individual lock events. AF_INET/AF_INET6 TCP only, non-RT.
No struct sock or skb owner field is added. Cookie is not a permission token,
creator identity, container identity, or proof of a blocking party.

``__lock_sock`` supplies the logical ownership wait start. Acquisition is
observed at both native assignments of ``sk_lock.owned``. The inline
``sock_release_ownership`` covers the release-callback early-release branch.
Fast lock/unlock events are distinguished from logical owned=1 episodes.
The initial implementation does NOT measure every ``sk_lock.slock`` spin or
every TCP global lock. Window-before holders remain unknown.

``__sk_add_backlog`` observes an actual queue insertion. ``__release_sock``
observes the callback boundary. The callback may free skb: the post-callback
hook copies only the address, never dereferences it. Queue observation is not
packet creation or proof of its remote sender's container. Service executor,
socket user, and original flow owner are separate concepts.

``skb_release_all`` observes release entry before attached-state release.
The BPF join is restricted to at most 256 observed queue objects. A separate
service map survives an in-callback free, so later address reuse cannot join
an old service end to a new enqueue. Entries outside this release path remain
unclosed; no zero residence time or inferred completion is generated. Clone,
GSO and nonlinear flags are preserved; shared data buffers are not assigned
exclusively to the observed skb. Original allocation and backend free service
cost are not established by this hook and require additional evidence.

Limits and source work
----------------------

At most 64 socket watches, 256 queued skb records and 256 active services.
No hot-path allocation by native hooks, no global owner lock. BPF hash-map and
stack-map synchronization, perf buffers and native socket cookie generation
still cost CPU/memory. The release hook receives all skb release-all entries
while enabled before the BPF bounded address lookup; that non-target work
must be counted. A two-second window does not itself prove low overhead.
Native per-CPU entries, eligible, selected, releases and skipped counters are
exported root-only. Unsupported NMI/recursion invalidates source continuity.
Softirq/hardirq events have no interrupted-task container attribution.

Validation still required
-------------------------

Compile, verifier and runtime checks; shared/private TCP sockets, inherited or
SCM_RIGHTS-transferred descriptors, changing holders, window truncation,
backlog/no-backlog, receive-side pause, CPU throttling, namespace isolation,
socket and skb address reuse, asynchronous release, ring/map pressure and
complete source unload. Tests must distinguish synthetic truth from ordinary
TCP application observations, and must not infer E3 from time overlap.
