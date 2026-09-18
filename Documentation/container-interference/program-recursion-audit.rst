BPF runtime recursion gaps
==========================

Native source recursion counters and perf output losses are not sufficient.
The fixed OLK raw tracepoint dispatcher has a per-program, per-CPU active
counter; nested invocations of the same program are skipped and recorded in
``bpf_prog_info.recursion_misses``. A different raw-tp program can execute
while another is suspended. Neither an empty perf-loss counter nor filtering
observer stacks proves that all producer events reached the program.

The worker now queries every freshly loaded program after producer detach and
the existing source callback barrier, before object teardown. Each query is
preserved as ``terminal_program``. A missing counter or any recorded miss makes
the new session partial/invalid, independently of native recursion counters.
This reads a terminal counter; it does not enable global BPF runtime timing.
Historical receipts without this field remain explicitly unaudited rather
than receiving an inferred zero. Runtime validation of the new audit is pending.

Allocator release observation may run in an interrupt while a different
process-context allocation probe is suspended. However, an already active
release probe at ANY execution level cannot be reentered on that CPU; it
reports a native source gap. This is a correctness guard, not loss recovery.
Future work must use separate context programs or a correctly bounded source
mechanism before claiming coverage of these overlaps.
