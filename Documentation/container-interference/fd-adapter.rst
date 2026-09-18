Selected files_struct lock adapter
==================================

The X1 adapter observes ``files_struct->file_lock`` only. Driver fields named
file_lock, POSIX file locks and other spinlocks are not this resource.
``CONFIG_CIS_OBSERVE_FD`` defaults off and requires non-RT SMP CIS observation.
With it compiled in, the separate ``cis_fdlock_state`` tracepoint remains
disabled until an administrator attaches ``fd.bpf.o``. ``owner.bpf.o`` enables
only mutex/lockref, not FD probes; the FD object enables no mutex/lockref probes.
No lock algorithm or files_struct layout changes. With observation configured
out the wrappers reduce to the original lock pair; with it configured in but
inactive the static-key checks remain, without BPF callbacks.

Source coverage
---------------

The selected wrappers replace all direct acquisition/release operations in
fs/file.c, fs/legacy-filescontrol.c, fs/misc-filescontrol.c, fs/locks.c,
fs/proc/fd.c and io_uring/openclose.c. Initializing a new table emits RESET
before publication. Both destruction paths emit RETIRE before allocator free.
init_files is static and does not need a synthetic allocation event.
The source audit must be repeated if any new user or alternate API is added;
a same-named function does not prove this adapter covers it.

WAIT precedes the original spin_lock; ACQUIRE follows it; RELEASE_BEGIN
precedes spin_unlock. WAIT is an attempt, including uncontended operations.
Only overlap with a separately closed observed ownership interval can
identify a blocker. Release-before-unlock is a conservative lower bound.
Already-held objects have no fabricated owner snapshot. A watch epoch is a
capture discriminator, not the object's allocation generation. RESET/RETIRE,
missing acquisition, source recursion, loss and window truncation prevent
unsupported interval joins. Task/IRQ context filtering remains in force.

The callback performs no dynamic allocation, new central locking or stack
walk itself. Existing bounded BPF maps and WAIT stack samples still cost CPU
and cache traffic. FD watches use the same explicit 64-event closed-prefix
limit as lockref; this is incomplete-window coverage, not dropped events
presented as a complete window. Existing total entry, memory and session
guards are not relaxed. Timing includes instrumentation and is wall time,
not spin cycles. Full source/background costs remain unaccepted.

The monotone source membership bitmaps are independent: 8KiB for owner and
8KiB for FD, rather than the previous shared 8KiB gate. They admit false
positives but never identify an owner. The root-only ``cis_sources`` debugfs
file exposes point observations of both switches for isolated control tests;
it is not an atomic acknowledgement of a profiling session.

Interpretation and acceptance
-----------------------------

Each actor carries cgroup identity plus PID/TGID/start identity. Same-TGID
threads are reported separately from cross-container relationships. Ordinary
containers have different FD tables; equal call chains are not shared locks.
Cross-container sharing requires actual same-object evidence, for example a
deliberate CLONE_FILES control, not an inferred connection through page_counter.

The combined-source adapter passed the basic and lifetime cohorts listed in
x-series-progress.rst, but regressed the existing high-rate file bridge.
Those passes alone do not certify the independent-source revision at fc90add6a.
Its fresh kernel has now passed exact source-switch observations, 15 FD
windows, existing owner bridge, specialist and periodic functional tests.
See the ledger for the separate cost batch failure. Dense FD collection can still
exceed the unchanged entry-rate limit and must stop, not certify partial data.
Three fixed high-rate windows verify this PARTIAL stop, actual source disable,
object removal and continued container progress. About 4.4 million entries
arrived before each approximately one-second check, despite the 200000/s
policy. This is a reactive safety limit, not a hard entry or CPU ceiling.
The associated ten-case crash suite passed cleanup, not interrupted-data
completeness. None of these passes certifies dense profiling performance.
No complete eligible-event recall or total observer-cost acceptance is granted.
The adapter does not complete X1 rwsem reader-set or generic spinlock ownership.
