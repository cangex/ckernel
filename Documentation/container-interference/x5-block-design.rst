X5 block-I/O prototype source contract
=====================================

Reuse existing OLK block tracepoints rather than change the block algorithms
or put an observer owner pointer into every request. Initial supported path:
registered-container blk-mq bio-backed submissions. Passthrough commands,
unobserved starts and a worker merely executing another task's work do not
receive invented submitting-container identities. Device occupancy does not
establish which tenant caused another tenant's delay.

Native source facts
-------------------

``block/blk-mq.c:blk_mq_bio_to_request`` initializes sector and bio content,
performs crypto preparation, then calls ``blk_account_io_start`` which emits
``block_io_start`` unconditionally. Use that observed start, current task
identity/generation, boot and capture epoch as an I/O-episode key. A request
address alone is not a generation. ``rq->start_time_ns`` is unsuitable: it can
be zero and ``block/blk-merge.c:attempt_merge`` changes it during merging.

Observe ``block_rq_insert``, ``block_rq_issue``, ``block_rq_requeue`` and
``block_rq_complete``. Completion is partial: the native trace occurs BEFORE
``blk_update_request`` advances the bio/data length. Only matching completed
bytes to the current remaining data supports a terminal data-completion
claim. It is not request-memory free or complete device-backend release.
``block_io_done`` is not a universal terminator: normal completion accounting
is conditional on ``blk_mq_need_time_stamp``. Do not rely on its presence.

``block_rq_merge(next)`` observes the losing request before its bio is cleared.
Close that episode as transferred/unknown, not successfully completed. The
receiving request is not identified by this tracepoint. If an observed request
acquires multiple bios, changes queue/device or is remapped, report composition
or routing changes and do not assign all work to the first submitter. A new
start at an already watched address is a lifecycle defect, never replacement
of the earlier identity. Window-end incomplete episodes remain incomplete.

Bounded capture and output
-------------------------

Default disabled; a short specialist window, at most two targets, fixed request
table and stack capacity, terminal per-program recursion audit, existing CPU,
memory, byte and cleanup budgets. Callbacks in IRQ context do not use the
interrupted task as I/O owner. Preserve the original submission link and report
the completion execution context separately. Default sampling and entry work
must be accounted for, including requests rejected by target filtering.

Report request queue residence, issue-to-completion wall time, partial bytes,
requeues/errors, shared device and observed participants separately. Concurrent
requests from different containers support shared-device occupancy evidence,
not an exclusive blocker edge or lock holder. Tag acquisition before the
observed start, page-cache/writeback origin, merges/splits and lower-device
fan-out require separate coverage; missing stages are not zero latency.

Validation plan
---------------

Use only disposable VM devices with fixed direct-I/O offsets and verified
payload. Compare same vs distinct devices and target/bystander roles; preserve
OFF/ON and rejected captures. Tests must cover partial completion, requeue,
merge, remap, address reuse, missing starts, foreign completion context and
window edges before the report can claim corresponding relationships.
Synthetic tests are parser counterexamples, not a substitute for live I/O.
This document freezes the first source contract; X5 is not implemented or
accepted merely because these tracepoints exist.
