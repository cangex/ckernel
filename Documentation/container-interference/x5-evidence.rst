X5 direct I/O lifecycle prototype evidence
=========================================

The source-state v6 kernel at 1eb5bfeda built the complete ARM64 Image and
modules in ``x5-source-audit-20260919``. Host kernel and host storage were
unchanged. ``x5-block-20260919`` built all eleven BPF objects and passed 331
tool unit tests, 21 owner tests and seven profile tests on ARM64. Its first
runtime rejected the independent oracle's incorrect comparison of encoded
64-bit TGID/TID with plain PID. All 16 native request episodes were retained;
no capture-quality or budget threshold was relaxed to fix this test error.

``x5-block-fix1-20260919`` used tools 710d887a2 and the same 1eb5bfeda Image.
Independent ``block_vm_check.py`` accepted all 12 fixed shared/private,
OFF/ON, n=3 states. Six captures correlated 96 of 96 independently verified
pread64/pwrite64 operations with native request start, insertion, issue and
complete byte count. Each operated on disposable virtual block devices at
disjoint offsets. These are real blk-mq paths, without an injected delay or
a rewritten I/O algorithm. No blocking tenant was asserted.

All six captures passed terminal quality, source-state and per-program
recursion audits, with zero recursion misses. Maximum combined-process
CAPTURING CPU was 8.96335 ms; maximum combined RSS was 35,442,688 bytes.
Business-context callbacks, virtual-device backend costs and asynchronous
kernel memory are not completely accounted by those measurements. They are
not total-observer or production performance acceptance.

Parser regression covers partial completion, requeue, merge transfer, remap,
over-completion, address reuse, window truncation and interrupt identity.
The native cohort validates simple direct I/O, not runtime positive examples
of all those transitions. Buffered-writeback origin sets, tag exhaustion,
multi-origin merge ownership and unique device-blocker causality remain
UNVERIFIED/NOT_IMPLEMENTED. X5 is not declared complete by this cohort.

``x5-blkcg-20260919`` used tools 5443b7964 on the same 1eb5bfeda kernel.
All 12 newly frozen states passed independent verification, now also checking
the head bio's real blkcg against the registered container and 4096-byte
payload. This is not inference from the completion worker. Six captures
matched 96/96 operations; maximum CAPTURING process CPU was 8.84622 ms,
maximum combined RSS 39,014,400 bytes, recursion misses zero. Serial SHA256:
990629a3f43c1e5b36b8dcc2b6a3b79d8ce4f880b92806c6fc6523f4897e7f29.
Buffered-writeback and all-bio merge provenance remain outside this cohort.
