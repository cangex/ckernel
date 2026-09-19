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
TCP locks or GSO/GRO data-buffer ownership from a Socket creator. Runtime
acceptance of this extension is pending until build and scoped tests complete.

The first ``x4-net-origin-20260919-213027.log`` cohort is retained as FAIL.
Its controller publishes a future capture window during preparation; the
old workload created the Socket immediately on startup and waited only before
locking. Creation therefore preceded the actual window (1.380s vs 1.455s),
and the observer correctly reported UNOBSERVED, while 4/4 later lock relations
were captured. The new frozen origin fixture waits before creation, starting
preparation 300ms before a lock schedule at least 500ms into the window. No
timestamps, thresholds or observed records from the failed batch are changed.
