Original TCP skb release backend observation
===========================================

This extension is a bounded X4 prototype closure, not a packet provenance or
allocator contention detector. It does not claim X7 acceptance by construction.

The existing TCP send allocation entry freezes the requester. At release entry,
the BPF live-address record is removed before the native allocator can reuse
the address. Only ``__kfree_skb`` supplies a stack-local completion token. Its
address and entry timestamp select a bounded 256-entry pending map. The token
survives native free without dereferencing the skb. A newly allocated object at
the same address cannot complete the older episode.

The backend clock begins after the entry observation callback and ends after
head-state, data and header release return. It is elapsed wall time, including
scheduling and interrupts, not exclusive CPU or time blocked by another tenant.
Native return branches separately indicate shared-data reference retention and
fclone-pair retention. Returning to the allocator is not physical page reclaim.
Clone, GSO and nonlinear shape flags do not establish child/payload ownership.

Bulk, NAPI and morph paths retain the existing entry-only scope. An observed
entry, missing end, window crossing, lost record or map overflow must never
manufacture completion. Requester and release executor remain distinct. No
global owner lock, native data ownership change, or new allocation is added.

Net source audit v5 includes all release-end entries and cumulative entry/end
callback body time, including non-target lookups. Wrappers and interrupts remain
outside that measured callback cost. Existing entry-rate, map/output capacity,
40ms capture-process CPU and teardown guards are unchanged. Old protocol-2
records retain their original entry-only interpretation through exact historical
collector contracts.

Required validation: full ARM64 Image/modules and BPF build, real send/backlog,
native allocation/admission failure, explicit retained-clone negative cases,
address reuse, mixed collectors and source-overload cleanup. Parser tests alone
are not runtime evidence of these cases.
