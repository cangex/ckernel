======================
CIS implementation v1
======================

Ownership and lifecycle
=======================

registry.c holds one directory FD and six metric FDs per registered root, a
daemon-generation/serial identity, a fixed history and state. BPF roots contains
at most 256 identities. A CO-RE walk starts from the event's task cgroup and
follows at most 32 kernfs ancestors; it never loops over all containers.
Scheduler wait uses the event's task, not the observer or current task.
Perf IP is current-task association, with IRQ ownership explicitly unresolved.

Registration serializes in one control loop. This is not a lock used by business
operations. Administrator requests are admitted at most 32/second to avoid
unbounded registration bursts; this may delay management, not container syscalls.
Host mount identity, root overlap, deleted FDs and generation are
checked. The fixed OLK cgroup-v2 hierarchy rejects rename; identity is still the
cgroup ID, not its path. Migration can race sampling: observations inside the migration boundary are
not assigned a pre/post ordering that the evidence cannot support. Begin/end
intervals retain the begin identity; PID reuse also includes task start time.

Unregister removes the target/root maps, exports unfinished records, closes FDs
and rebuilds the bounded userspace lookup index. No BPF maps or programs are
pinned. A diagnostic start timestamp prevents a stale in-flight entry from a
previous window being accepted in a subsequent window. Empty roots stop active
diagnostics. Deleted roots are retired on a metrics tick; off mode performs no
background lifecycle polling and requires explicit unregister or daemon exit.

Hot and cold paths
==================

Ambient producers use read-only identity lookup, CPU-local statistics and
per-CPU perf output buffers. Local atomic updates tolerate nested interrupt
contexts; they are not a host-global counter. The initial shared ring buffer
was replaced because it introduced a common producer synchronization point.

The consumers, symbol lookup, state machine and report generation run in the
host daemon. Symbols have a bounded allocation; module symbols are intentionally
not cached without lifecycle tracking. Unknown names remain numeric addresses.
The control loop scans a fixed maximum of 256 registered slots only on userspace
wakeups, never in a business kernel event.

Diagnostics have at most two targets. Lock/reclaim in-flight state uses a
bounded hash map (1024 entries); work lineage uses a separate 128-entry map;
the stack map has 256 entries of at most 64 IPs. These maps have kernel hash
bucket/allocator synchronization. They are residual shared observer mechanisms,
not proof of zero observer contention. No lock holder index is maintained.

The ARM64 synchronous-event guard rejects hardirq, active softirq and NMI for
lock/reclaim and work submission attribution. BH-disabled task context is not
confused with executing softirq. Ambient perf IP retains explicit IRQ ambiguity.

Resource and configuration handling
===================================

Resource reads are phase-staggered. Every five seconds, effective CPU/node sets,
cpu.max and memory.max are fingerprinted; a changed fingerprint stops the old
diagnostic, resets learning and advances the root epoch. Missing configuration
is reported as partial, not assumed unchanged. Ancestor constraints and changes
not represented in these files are a known coverage gap, not a claim of complete
resource-policy versioning.

The warmup and anomaly state machine freezes learning during persistent
deviation, uses absolute and relative pressure thresholds, and fairly rotates
pending targets. A demand/phase change remains an E0 anomaly until direct
evidence distinguishes it from contention. There is no application-specific
model or hidden application hook.

Background work and global re-entry
===================================

Reading cgroup counters, PMU interrupts, per-CPU buffer consumption, stack
deduplication, map updates, kallsyms loading, report writes and final map/FD
release still use ordinary shared kernel facilities. Probe detach can wait for
existing execution. File output can invoke shared allocation/writeback. Moving
work to the daemon does not remove these costs; measure observer and bystander
CPU, memory and latency together.

No kernel algorithm or task_struct change is needed in this prototype. The
fixture module is isolated-test-only and never a production collector.
