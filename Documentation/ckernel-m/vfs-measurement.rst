.. SPDX-License-Identifier: GPL-2.0

M3 query-lease measurement protocol
==================================

The vfs_pair probe is restricted to an explicitly disposable guest. It uses a
six-vCPU guest, two worker placements (including separate migration partners),
a separate controller vCPU, separate leaf memory cgroups and preallocated
measurement buffers. Do not run it on the development host.

Modes are native (one shared readonly tmpfs), private (separate readonly tmpfs
mounts without instance association), core (the same private layout with Core
only), and vfs (the same private layout with the query lease). File creation
is outside the operation interval. This does not measure ckm_mount_prepare
copy throughput, and per-leaf memory of the shared case excludes the shared
files charged to the controller. Do not interpret it as total system memory.

Each run records target-only, bystander-only or paired workers; the driver must
run all three and exchange physical placements. Closed-loop runs use exactly
200000 statx calls per worker. The steady fixed-arrival control uses 20000 calls
at a nominal 50000 calls/s. Service latency is separate from latency since the
scheduled arrival, so late dispatch is not silently removed. No arrivals are
dropped. Compare like modes/rates and report the actual overlap interval:
fixed-count closed-loop workers may finish at different times.

The first lookup is recorded separately as a single cold observation, followed
by 64 warmup lookups. It is not a sampled cold-start P99. Exhaust tests 32 files
against a 16-entry cache without changing syscall success. Migration includes
the periodic affinity operation in the sample. Invalidation includes one
RO-to-RW-to-RO transition in the sample; most subsequent calls are native.
These are compound-operation costs, not isolated syscall-service estimates.

The memory snapshots include native per-cgroup current, peak, stat and events.
OOM counters must stay zero. Kernel-thread CPU is the matched PID/start-time
schedstat delta, with disappearing and new threads explicitly reported. It is
not a complete chargeback of all kernel CPU; IRQ, softirq and total system CPU
ticks are reported separately, and worker getrusage records foreground CPU.
The controller, timers and measurement code have costs too. Never subtract
these categories as if they were mutually exclusive.

The post-exit observation is a fixed 250ms tail, not proof that every RCU or
worker callback has completed. Queue backlog, allocation failure injection,
pressure and concurrent batch-exit storms need separate tests before a full
M3 performance/isolation acceptance. The probe does not establish them by
reporting average throughput or successful cache hits.

Performance images must have KASAN/lockdep disabled; diagnostics run separately.
Keep all rounds, failures and pinning manifests, and do not execute performance
measurements concurrently with kernel builds. Guest results are not host-NUMA
isolation claims. A functional default-off prototype may have no speedup.
