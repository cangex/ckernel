Allocator node-lock observation boundaries
=========================================

Earlier captures have NODE_WAIT before spin_lock_irqsave, NODE_HELD after
acquisition, and NODE_DONE after spin_unlock_irqrestore.  The HELD-to-DONE
duration includes unlock and may include post-unlock scheduling.  Old data
must not be reinterpreted as an exact held interval or used to invent a holder.

An appended NODE_RELEASE stage, number 21, records the selected allocation
path immediately before unlock.  The old stage numbers, event layout and
end-of-call marker remain unchanged.  Bounded BPF admission, source sampling,
recursion checks and ordinal/capacity rejection still apply.  The extra event
does not acquire a new global lock, allocate memory or collect a new stack.

For new complete sequences the reader partitions:

* WAIT to HELD: acquisition bracket, including source overhead;
* HELD to RELEASE: an inner interval known to execute while holding the lock;
* RELEASE to DONE: release observation and unlock, potentially scheduling.

These intervals must use the same lock address.  Missing, duplicate or
changed-object boundaries reject the call.  Nested slow/partial intervals
are not added again to the exclusive partition.  Mixed old/new sequences in
one call are rejected rather than silently treating old boundaries as new.

The inner bracket excludes acquisition-side observer execution before HELD
and includes some observer execution before RELEASE; it is neither complete
hold time nor application work alone.  Its actor is the allocation executor.
This patch is a prerequisite for a selected-node-lock relation, not complete
SLUB lock holder coverage.  Other allocation/free/shrink users, object
lifetimes, sampling gaps and source completeness still need explicit handling
before a competing-container statement is accepted.

New Image/module and runtime evidence are required.  Passing old captures or
unit fixtures alone does not validate this newly inserted kernel event.

Runtime evidence, 20260919
-------------------------

Kernel and tools cfd2b935d49078e04a0a600d79b9d48c5f706d4c, tree
9176397b1df6f735c2c00fc9202243cdffd90c95, built a complete ARM64 Image and
all configured modules successfully.  This returns to the frozen non-fault
configuration; FAILSLAB remains disabled in this kernel.

Image SHA256:
``0f662f8aeb8016eab80819557051bb1751dff35a1aa6288f54a576be01a35927``.
BTF ELF SHA256:
``6a21f28db4ddce65de66746f990fcb6180181440690c3a9ccd557b65e32d75e5``.
Config SHA256:
``a4442c97080c31d049a2ceef073709dddd6cbb4d2c3b0403b86354697c68904f``.
Both earlier normal/fault kernels and their BTF inputs remain hash-identical.

The new four-container cohort is
``/root/cis-20260916-232524/evidence/allocator-lock-joint-20260919``;
serial ``x7-joint-20260919-181014.log`` has SHA256
``701c9b950d397eeab80684a228aaddc5e06238e389692db127b3291e655c2c0d``.
Independent ``joint_vm_check.py`` replay returned PASS_SCOPED, no errors,
33 states and 30 captures.  All 198,000 fixed-offered-load operations completed
with no timeouts.  This remains the ten-collector file/VMA matrix, not a
selected-rwsem positive or a full application attribution denominator.

The three allocator captures contained 17, 12 and 8 complete new node-lock
sequences respectively: 37 WAIT/HELD/RELEASE/DONE groups.  The report now
separates their inner held and unlock brackets without promoting them to
blocking-container relations.  Release recursion skips were zero in all
three rounds.  Old failure, placement and lifetime serials also replay with
the new reader, retaining their original boundary semantics.

Maximum combined-process CAPTURING CPU was 27.53136 ms, below the unchanged
40 ms protective limit.  Maximum combined RSS was 38,592,512 bytes.  The
maximum P99 absolute increase across the matrix was 331,700 ns; allocator
bystanders reached a 214,490 ns increase.  These remain record-only tail
results, not an accepted low-tail-latency result or unexplained hardware
attribution.  Offered-load throughput deltas were -0.02398% to +0.02816%, not
saturated throughput.  Complete kernel/background cost remains unproven.

Local regression has 400 tests: 399 pass and one platform-specific skip.
The same new kernel/tools also passed 36 lifetime states / 18 captures:
240 selected calls and 744 release entries, including private-cache,
cross-CPU release and RCU callbacks.  Maximum combined CAPTURING CPU was
10.29846 ms and combined RSS 39,071,744 bytes; release recursion skips were
zero.  ``allocator-lock-lifetime-20260919/x3-fixture-20260919-181923.log``
has SHA256 ``f8581b23b1326ac490481ef8fab58071e9296f447350e35c0bf3560c006d9b40``.

The same kernel/tools passed fresh control and recovery checks with
``x0_check.py``:

* ``allocator-lock-control-20260919/x0-control-20260919-182234.log``:
  15 checks / 13 captures, all scope audits pass.  SHA256
  ``e6d48298f72e92c10cfddb87151bde76e223e89df3d058c3a5f88b39534cf667``.
* ``allocator-lock-fault-20260919/x0-fault-20260919-182618.log``:
  uncertain cleanup remains FAULTED and rejects a new capture.  SHA256
  ``6257509f4d9ce317d7c8f1d657580dae1e5f2b8480c7f2d48558426de289d7bd``.
* ``allocator-lock-crashes-20260919/x0-crashes-20260919-182806.log``:
  15 process-fault cases / 15 captures, cleanup and recovery pass.  Thirteen
  intentionally interrupted captures remain BLOCKED for attribution because
  complete terminal scope counters are absent; they are not successful
  attribution samples.  SHA256
  ``54fe8ed983aa0297af60dc24fb81e31f1e675b854263c1678ea5a7f82f10f35d``.

The result validates a needed source boundary, not full SLUB holder/lifetime
coverage or X7 completion.  Natural pressure, partial bulk rollback, the
selected-lock participant closure and remaining networking/I/O cases remain.
