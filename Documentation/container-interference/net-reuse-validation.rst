Native Socket address reuse negative
====================================

The frozen matrix has six OFF/NET states: three alternating paired rounds.
Two container actors each create and close eight private native TCP sockets,
40 ms apart, wholly within the usual two-second capture window.  No socket
allocator or reference-count algorithm is changed and no fake CIS events are
injected.  The existing test-only ioctl reads the address while holding a
valid socket reference; userspace records SO_COOKIE and actual create/close
intervals.  Each socket is closed before the same actor creates its successor.

Both actors must observe at least one genuinely reused address with a new
cookie.  A different-address run is not accepted as a reuse test.  The observer
must report all sixteen new identities with the correct creating/using task
and creation bracket, without introducing a wait or old-holder relationship.
No kernel pointer is dereferenced after close.  The native cookie, rather than
a synthetic test generation, remains the observation identity.

This cohort is separate from positive logical-lock recall and from the original
skb-header release token tests.  It does not prove arbitrary protocol lifetime
coverage.  Runtime results must be recorded separately from these definitions;
all failed native-reuse attempts remain visible, not silently retried until a
favorable allocation pattern appears.
