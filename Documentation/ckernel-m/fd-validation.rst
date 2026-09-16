M5 build, semantic regression and measurement record
===================================================

Source and environment
----------------------

M5 is based on published M4 commit
5ba0bea3c68d3188a62d280e2cbd8c40e96507ea. It adds the default-disabled legacy
files-controller credit protocol; it does not change the misc backend, generic
page_counter algorithm or native files_struct layout. Maple remains disabled.
The host still runs its previous kernel. New images run only in ARM64 KVM
guests on the recorded 14-machine CPU placements. Guest results do not establish
host NUMA or production-container isolation. GCC 10.3.1 and the external O=
build are recorded alongside the exact configurations, module and image hashes.

The per-stage evidence root is
``/home/ckernel-m-through-m6-20260916/evidence``. Final userspace fixtures were
extended after the first image build; ``m5-final-userspace.sha256`` records the
16-case test actually used. This distinction must not be hidden by presenting
an older source archive as the final fixture.

Correctness status
------------------

The complete Image and module links for cumulative M5, FD-only minimum,
Core-only and CKernel-M-off configurations completed. The configuration
sequence exited zero. Cumulative and minimum builds use the diagnostic kernel;
instrumented images are not used to infer performance.

Ordinary and 24 MiB-resident / 48 MiB-cgroup pressure runs each passed 16 cases:
usage, limits, rollback, dup replacement/RLIMIT, inheritance, shared files,
migration, sibling-reserve rescue, limit races, revoke, SCM_RIGHTS, revoke
races, batch exit, ABI/permission errors, fault injection and administrator
disable. The last case verifies compatibility with the preexisting no_acct
control in a fresh guest; that control is never a benchmark optimization.
Each fault run attempted 64 injected allocations: 8 rejected, 56 completed,
and all 64 uninjected recovery attempts succeeded. No SKIP is counted as PASS.

* ``m5-ordinary-20260916_123434.log``: SHA256
  dd01ded6b35fa8b5b10641c418d82b614ad9c542afe64e12c378411b9a0b3ffa.
* ``m5-pressure-20260916_123435.log``: SHA256
  5f4d270ff7365a27b9629a1e73397a3e5fa914c78cb06a50b1bb9b8f552d885a.
* ``m5-minimum-20260916_124921.log``: SHA256
  99a9c69f1d4ceea5f1ff283df0e931b91e6c73e6f6e36782268965a1a9ae2cbc.

The minimum configuration repeats all 16 feature cases under pressure.
Core-only and fully-off configurations run 13 native-reference cases, without
pretending that an absent CKM ABI exercised the feature. The final native
reference log ``m5-native-final-pressure-20260916_122959.log`` has SHA256
c549589acbf8e623f6903632f6ecac3cf5e1640237ac7ebc6bb141723779f8f8.
The cumulative image also passes the M4 security/file regression and subject
KUnit gate, with actual audit delivery and zero lost audit records. Detailed
markers and image/fixture hashes are retained rather than inferred from a
single overall script exit.

The original native fixture expected internal ENOMEM at the syscall boundary;
the real syscall returned EMFILE. That fixture failure remains in the evidence.
Tests were corrected to the native ABI, not by changing native failure behavior.
Three sequential credit-model checks, including 32768 five-event traces,
support the protocol but are not a kernel concurrency proof.

Pressure memory.current was 25165824 bytes after the deliberate touch,
25567232 after tests and 401408 after unmapping plus 500 ms. memory.events
reported zero OOM/OOM-kill. These are snapshots, not proof that every delayed
release completed or that memory overhead is zero.

Performance status and limits
-----------------------------

The separate non-debug kernel completed 180 states and 240 worker observations,
with all three rounds, target-only/bystander-only/pair placements, exchanged
roles and fixed work. The raw log is ``m5-perf-20260916_131418.log``, SHA256
5b6ca321e5d68fafcf629a601b985715c7356f0290731d7cc865a898ba0b9382.
The strict parser checked the complete matrix, worker operations, idle-credit
bounds, feature activity, revoke drain and absence of OOM events. Raw inventory,
foreground CPU, matched workers, global ticks, memory and drain records remain
available in ``analysis-fd/``; the measurement sequence exited zero.

In closed-loop steady pairs, delegated mode versus Core-only improved
throughput by 38.79--53.43%, reduced run-P99 by 30.39--40.00%, and reduced
foreground CPU/operation by 27.96--36.28%. These ranges span the four role and
placement means of three runs, not confidence intervals. Pair-versus-solo
run-P99 grew 57.26--78.26% with Core-only and was unchanged at the recorded
resolution with delegation. This narrow observation is not a zero-interference
guarantee. At equal 20 us arrivals, operation P99 fell 17.28--27.55%, but
arrival-to-completion P99 fell only 0.05--0.74%; service savings must not be
presented as an equally large response-tail improvement.

Exhaustion retained 16.66--31.59% throughput improvement, with P99 decreasing
5.88--46.99%; migration improved throughput 43.41--82.93%. In contrast, revoked
targets lost 3.51--4.53% throughput, increased P99 31.41--37.70%, and used
3.62--4.74% more foreground CPU/operation. Their still-active bystanders gained
32.05--41.41% throughput in the same comparison; this does not prove a harmless
revocation in all workloads. The steady first-operation time rose 3.55--8.44%,
and steady paired maximum latency ranged from 10.01% better to 140.59% worse.
These outliers and cold costs are retained, not filtered as noise.

Logical FD management storage was 400 bytes/instance in the six-vCPU guest,
excluding Core, slab rounding and retained controller structures. Paired
steady memory.current snapshots were 4718592 bytes both at ready and finished
in both modes; drained snapshots were 462848--544768 bytes. Equal coarse
snapshots do not establish zero incremental memory. Mean matched-kthread CPU
was 31.85/60.99 us for the Core foreground/cleanup intervals and 29.33/69.45 us
for delegated mode. Cleanup thus increased in this partial accounting despite
foreground savings. Revoke/drain wall times of roughly 20--40 ms include the
polling interval and cannot be interpreted as raw kernel drain latency.

M5 has a functioning, accounted fast path and passed the recorded semantic
gates. It remains default-disabled: the steady mechanism result is positive,
but revocation/cold/max-latency regressions and broader isolation validation
remain open. This does not accept the separately deferred Maple prototype.

One normal operation is one dup-close pair. The exhaustion operation performs
128 dup calls then 128 closes, with a different fixed workload count. These
units cannot be merged. Roles and CPU placement are exchanged; paced steady
arrivals and closed-loop throughput are separate strata. The cold field times
the first dup-close operation, not complete instance enrollment. Invalidation revokes
the target instance, and migration alternates its permitted CPUs.

Foreground CPU, matched-kthread runtime and global CPU ticks overlap and are
not additive. Worker identity snapshots omit some short-lived work and do not
fully attribute background cost. Cold observations and three run quantiles
are not statistically stable tail guarantees. The 250 ms observation tail
is not complete reclamation. Pressure and batch-exit tail performance remain
additional measurements, not implied by functional pressure/exit tests.
Shared coordination can drain other instances' idle credits or wait behind
their control operations. No bounded-wait or no-cross-container-blocking claim
is supported by the current protocol.
