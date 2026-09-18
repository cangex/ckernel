X7 joint native-operation cohort, 2026-09-19
==========================================

``x7-joint-20260919`` froze tools e842d7098 and kernel 1eb5bfeda. Four
containers performed ordinary open/fstat/read/close or VMA map/protect/free
operations without injected kernel delays. CPU pairs were shared within
each workload pair; target/bystander roles rotated by round. Management
used a separate virtual CPU. This is an eight-vCPU isolated KVM result,
not a host or bare-metal NUMA result.

The v1 matrix is fixed to OFF and ten collectors, three alternating rounds:
33 states, 30 captures. New adapters do not retroactively change its matrix
or fit extra captures into its 32-session permit. Each actor had 1500
scheduled arrivals at 2ms intervals. Latency includes arrival backlog; the
100ms timeout threshold was predeclared. Throughput is completion at that
offered rate, not saturated throughput.

Independent replay passed all 33 states, source/role bindings, exact scoped
source switches, complete capture windows, ordinary operation correctness
and object cleanup. There were zero operation errors and zero timeouts.
Maximum combined-process CAPTURING CPU was 22.11098ms, below the unchanged
40ms guard. Maximum combined RSS was 41070592 bytes. Business-context BPF
CPU and all kernel asynchronous memory are not separately complete; these
process measurements are not total monitoring-cost acceptance.

Per-actor P99 across all states ranged from 66760ns to 6320660ns. The raw
arrival samples, paired OFF changes, whole-VM CPU categories and cgroup
memory snapshots are retained. P99 is record-only; this cohort makes no
one-percent throughput or two-percent latency claim. VM CPU snapshots
include business and background, not observer-only overhead.

Scheduler, counter and allocator adapters produced relationships on these
ordinary operations. Quiet owner, FD, sync, network and block captures do
not count as positive resource coverage. Without complete native-operation
truth no precision/recall population is invented.

Serial SHA256:
c12f68e112f3533b3895ea9a299802920a211c4ba1aeabaa16cee8761ef42e21.

The independent checker initially rejected its own mutable collector list
after rwsem development began, then exposed a numeric-only parser losing
the workload mode. Fixes freeze the v1 matrix and validate the explicit
native mode string. No recorded timing, workload, guard, series or result
was changed. All failed verifier attempts are retained. Scoped joint PASS
does not complete X7 while mandatory per-resource coverage remains open.
