TCP send allocation provenance
==============================

The network specialist additionally observes ``tcp_stream_alloc_skb`` on
boot-cookie-selected TCP stream sockets. It keeps the existing 2s session,
two-target admission, CPU guard and bounded output policy. This is not an
always-on allocator trace and not a new networking algorithm.

The native sequence remains ``alloc_skb_fclone`` then socket memory admission.
A successful backend emits an event before admission; an admitted buffer or
memory rejection closes that same task-start/allocation bracket. Backend
failure is explicit. Rejection may release the buffer before the terminal
event. No object is dereferenced after rejection-triggered free.

Two HASH maps each hold at most 256 pending calls/original headers. Original
requester, native Socket cookie and allocation start identify each episode.
The existing final ``skb_release_all`` entry reports the real executor, which
may differ from the requester or be interrupt context. No releasing ``current``
is assigned as the buffer owner. Duplicate live addresses, nesting, capacity,
loss or source recursion invalidate evidence rather than join approximate
timestamps. An unclosed call or unobserved release remains unknown.

The backend interval includes both the fclone header and initial data backend,
possible descheduling, interrupts and small timestamp-wrapper costs. It is not
SLUB-exclusive CPU, queue wait or a holder/waiter edge. Callback-body CPU is
audited separately; entry filtering, native-cookie generation, release and
remaining background work are not fully accounted by that timer. Max callback
time is a boot high water, not a window maximum. OFF has disabled source keys.

Scope deliberately excludes receive allocation, payload-page origin, clone,
GSO/GRO lineage and final shared fclone/data reclamation. Existing backlog
associations retain unknown packet origin. Sharing a Socket or SLUB cache does
not identify a blocking container. The send API fixture bounds requester,
cookie and call interval independently; it does not provide a population
denominator for skb allocation recall. Original header reuse is separate from
Socket lifetime and packet-data sharing.

Runtime qualification is recorded in the evidence report after immutable
kernel and tool builds. Unit tests alone do not qualify this observation path.
