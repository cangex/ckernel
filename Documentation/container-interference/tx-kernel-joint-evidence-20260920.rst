Four-container regression after TCP adapter changes
==================================================

The isolated ARM64 guest used Image/source ``5c2bf8603`` from the native TCP
failure report and tools ``d4a30a079``. No fault injection or kernel fixture
delay was active. The host kernel and boot ID were unchanged. Source and
build hashes, the two initrds and all failures from earlier development are
retained. This is VM prototype validation, not bare-metal NUMA acceptance.

Evidence directory is
``/dev/shm/cis-x-20260919/evidence/tx-kernel-joint-d4a30a079-20260920``.
The common serial ``common/x7-joint-20260920-072718.log`` has SHA256
``ed235772fd91e7e737328e1070f5c4155dd50e6ea15a403a4d5e45973540c458``.
The SLUB serial ``slub/x7-joint-20260920-073458.log`` has SHA256
``103d1d35ab8838d30d1868e14e02c3515c688c264b27d4f29f84e1c0e3e55ce3``.
Both replayed independently through ``joint_vm_check.py`` as PASS_SCOPED.

The common frozen matrix contains 33 states: OFF and ten collectors, three
alternating rounds, with 30 captures. A separate six-state OFF/SLUB matrix
has three captures and a separate bounded permit. Four active containers
perform file/file/VMA/VMA operations, with target and bystander roles rotating.
Every actor completes 1,500 offered operations per state. Totals were 198,000
and 36,000 operations, with zero errors/timeouts and full capture coverage.
The load is fixed-rate, not saturated throughput.

Maximum combined CAPTURING process CPU was 28,834,320ns in the common cohort
and 10,892,660ns for SLUB, below the unchanged 40ms guard. Combined whole-stage
CPU peaks were 167,797,860ns and 116,481,120ns; combined RSS peaks were
35,545,088 and 36,888,576 bytes. Source quieting and object removal passed.
These process/RSS numbers are not total observer CPU or kernel memory.

For common collectors, paired target P99 changes ranged from -597,650ns to
+414,990ns and bystander changes from -463,370ns to +342,380ns. For SLUB the
ranges were -403,720ns to +138,880ns and -219,670ns to +246,040ns respectively.
All samples and absolute values are retained; P99 remains record-only, not
production acceptance. Fixed-rate completion-rate changes must not be sold
as saturated-throughput overhead or improvement.

Management-cgroup bookend CPU ranged from 12,006us to 1,191,892us for common
collectors and 10,878us to 155,647us for SLUB. The largest value was allocator0.
This includes the test harness, snapshots and independent in-harness report
analysis, and cannot be substituted for live-controller-only cost. Matched
kernel-thread CPU ranged 0..5 ticks and 0..6 ticks; new/gone tasks and scan
limitations are retained. Total asynchronous observer cost and exclusive
kernel memory remain unknown, not zero.

The common guest reported native perf interrupt-cost warnings and reduced
its maximum sample-rate ceiling as far as 30,750. Those warnings remain in
the raw serial. No setting was raised to hide them, and this cohort makes
no zero-disturbance or production monitoring claim.

Ordinary scheduling, counter participation and allocation stage records were
observed. Quiet owner/FD/network/block/SLUB adapters do not gain contention
positive coverage from this test. Resource-specific independent truth and
negative cohorts are still required. This closes fresh-kernel coexistence
and cost regression for this frozen layout, not all X7 requirements.
