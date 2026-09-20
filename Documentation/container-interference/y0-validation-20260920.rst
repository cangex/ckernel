Y0 reduced public-resource profile validation
============================================

Status: PASS_SCOPED, not production performance certification. Y1--Y7 are
separate stages and are not accepted by this receipt.

Frozen tools: f0812a677 (including bcf61250b and b51894070).
Frozen guest kernel: 55795f96bfd626d91090fd7389ddf2771ebaf74c.
Image SHA256: 753ac5f59b329afab597e147d6565883881696d09c35a420f9bb160285c6b7d9.
The host kernel and boot ID were unchanged before/after the run.

Raw evidence on the dedicated development host::

  /dev/shm/cis-x-20260919/evidence/y0-public-f0812a677-20260920

Downloaded evidence and two independent local replays::

  .codex-tmp/container-interference-20260916/y0-evidence-20260920

The archive download manifest hashes every file. Local replay used the frozen
f0812a677 tools, not subsequent Y1 source. Public cohort: 24 states, three
predeclared alternating rounds, 21 two-second captures. Backend comparison:
9 states, three rounds, 6 captures. Both checkers report PASS_SCOPED with no
errors. Four independent containers execute native file and VMA operations;
target and bystander roles rotate. These are fixed offered-load checks, not
saturated throughput acceptance or a representative production population.

Default manual admission rejects owner, fd, sync, rwsem, allocator and net
before worker creation. All six runtime rejections were checked together with
the source-disabled state. Explicit extensions remain available; automatic
routing cannot enable them. The alloc_backend bundle has no maple_context
program or maple_pending map; active/idle source observations and raw records
confirm no Maple observation. Other source keys remain disabled. Every
accepted capture verifies final BPF object absence.

Observed costs, not extrapolated guarantees
-------------------------------------------

In the public cohort, capture-phase controller/worker CPU was 10.636--27.449
ms per two-second window. Combined observed process RSS was 30,277,632 to
34,516,992 bytes. Arrival-relative P99 changes across target/bystander paired
cells ranged from -461,420 to +347,250 ns and remain record-only. Complete
individual results, timeouts, management CPU, kernel thread CPU and memory
gauges are in the verification files. Quiet collectors do not gain positive
resource coverage merely by passing this joint test.

In the matched backend comparison, legacy Maple context callbacks numbered
194120, 193228 and 193936; the backend-only variant recorded zero in every
round. Legacy callback-body time was 48.570, 46.269 and 45.938 ms; this is a
source bracket, not total observer CPU or pure interrupt-off time. Backend-only
capture process CPU was 26.503, 28.097 and 27.625 ms versus 28.206, 28.663 and
27.476 ms with legacy context. There is no uniform process-CPU reduction.
Observed RSS was 30.20--31.36 MB versus 33.50--33.63 MB (decimal); these are
process observations, not complete kernel/BPF memory attribution.

Removing default eligibility does not prove lower idle cost: old collectors
were already unloaded outside sessions. The demonstrated saving is absence
of Maple context work during backend profiling. Allocator/free callback work,
shared buffers, control-plane activity and uncertain asynchronous kernel costs
remain. No whole-system observer-cost or production low-overhead claim is made.

Failures retained
-----------------

The bcf61250b preparation stopped on a test fixture that placed its supposed
out-of-root symlink target inside an authorized TMPDIR. The guard was not
weakened; the negative now targets /boot. The b51894070 cohorts stopped when
the new alloc_backend label produced an invalid underscore-containing nonce.
The harness now constructs and tests valid protocol nonces. Both failed
directories remain alongside final evidence. Neither is counted as a passed
trial, and the frozen three-round matrix was not cherry-picked.

The ARM64 build and 669 Python tests passed, as did the 21 holder tests and
7 profile tests. A local non-Linux platform skip is not an ARM64 runtime pass.
