Started block request termination
================================

The ``inflight`` VM fixture supplements, not replaces, the older ``lifecycle``
cohort. It has two cases, ``abort`` and ``drain``, with three fixed alternating
OFF/BLOCK pairs and two container actors on separate disposable memory devices.
No host block device, production driver algorithm or observation hook changes.

Each actor submits one 4096-byte write bio. The real block layer forms a request
and calls the test driver's queue_rq. The driver records the address, bio,
sector and byte count independently, calls blk_mq_start_request, and retains
ownership instead of completing inline. A completion object publishes that
dispatch to the submitting ioctl. After submit_bio returns, the ioctl verifies
that the bio has not completed and the request is still started.

In ``abort`` the driver explicitly terminates its request with BLK_STS_IOERR
without writing data. In ``drain`` it copies the expected bytes and completes
normally. Both use the real blk_mq_end_request and original bio endio. The
job, pages and bio remain alive until endio finishes. No observer record or
synthetic trace call supplies the truth. A per-device test-job mutex protects
only fixture bookkeeping and is not offered as a production contention claim.

The verifier requires the started/pending observations, a terminal-call time
bracket, conserved bytes, exactly one endio, native completion status and the
correct submitter/bio billing identity. The observed service interval must
begin before terminal handling and end within that terminal-call bracket.
Missing, duplicate, pre-submit or wrong-container episodes fail verification.
The full frozen cohort is required, not a chosen successful round.

Production inference remains narrower than fixture truth. The request trace
shows its actual error completion; it does not expose a generic cancellation
intent or distinguish every timeout, cancellation and driver error. In-flight
driver termination does not certify io_uring/AIO cancellation or device-firmware
abort behavior. There is no invented unique blocking container. The separate
``block_inflight`` coverage key rejects a relabelled pre-submit cancellation
cohort. Runtime receipts and costs are recorded separately from implementation.
