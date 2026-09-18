Selected files_struct lock adapter
==================================

The X1 adapter observes ``files_struct->file_lock`` only. Driver fields named
file_lock, POSIX file locks and other spinlocks are not this resource.
``CONFIG_CIS_OBSERVE_FD`` defaults off and requires non-RT SMP CIS observation.
With it compiled in, the existing ownership tracepoint remains disabled until
an administrator attaches the bounded owner collector. No lock algorithm or
files_struct layout changes; disabled calls optimize to the original lock pair.

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

Interpretation and acceptance
-----------------------------

Each actor carries cgroup identity plus PID/TGID/start identity. Same-TGID
threads are reported separately from cross-container relationships. Ordinary
containers have different FD tables; equal call chains are not shared locks.
Cross-container sharing requires actual same-object evidence, for example a
deliberate CLONE_FILES control, not an inferred connection through page_counter.

This source adapter is IMPLEMENTED, not runtime accepted. Required evidence
includes a new full kernel build, OFF smoke, actual FD operations, private
tables, shared tables, switching, destruction/reuse and truth/quality checks.
It does not complete X1 rwsem reader-set or generic spinlock ownership work.
