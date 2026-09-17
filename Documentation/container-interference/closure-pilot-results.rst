Closure pilot results (2026-09-18)
=================================

P1 and P2 remain unaccepted. The dedicated VM completed eight tracked
diagnostic cells and a separate, predeclared five-pair warm cost batch.
No positive periodic run or fabricated acceptance receipt was used.

The tracked pilot used source 55c674b6c, two container workloads, two-second
windows and 2000 requests/second. The default timer-slack target P99s were
75.80/60.74/56.31/56.26 us for OFF/IDLE/IP/owner. The reversed-order 1-ns
diagnostic control gave 33.46/9.28/9.15/6.36 us. These are single observations
with extra tracing, not slowdown estimates. They show that the arrival-wait
component needs examination; they do not explain all variation or justify
changing acceptance timer slack. Sparse IP output is not proof of coverage.

Observed cgroup charge peaks were 11.00-14.80 MiB for IDLE, 25.11-25.86 MiB for
IP and 25.11-25.61 MiB for owner. These are charged-memory high-water marks,
not complete global observer memory. Tail cgroup task CPU was zero in the
fixed observation interval, not a proof of zero workqueue/RCU CPU.

The untraced cost batch used source 3f37c4e1b, default timer slack and 4096
identical pre-window operations in every mode. All 80 workload results and
five pairs were retained. The parser verifies warmup ends before the common
window; this version-2 protocol is separate from historical cold batches.
The diagnostic-window P99 target of a 2% upper bound was declared beforehand.

Target/bystander 95% slowdown upper bounds were:

* IDLE throughput: 2.461% / 2.474%, insufficient for the 1% bound.
* IP throughput: 2.480% / 2.471%, within this batch's 3% bound.
* Owner throughput: 4.096% / 4.160%, insufficient for the 3% bound.
* IDLE P99: 43.312% / 43.341%, insufficient for the 2% bound.
* IP P99: 48.323% / 48.812%, insufficient for the declared 2% bound.
* Owner P99: 46.702% / 46.098%, insufficient for the declared 2% bound.

These are uncertain upper bounds, not deterministic regressions. The first
OFF throughput differed substantially from later rounds in both containers.
It was not deleted. Negative mean slowdowns are not profiler speedups. Warmup
alone did not resolve drift; unexplained variation is not labeled hardware.

Kernel Image SHA256 remained
4f11956a64c706d378fc2b0730f59d3f08efa4fec8430173282f0fe38a21d625,
from runtime kernel source fe4afbc314b4b01090e6dadddbbea7e5f99b7087. New tools
were compiled in the isolated ARM64 environment; kernel call sites did not
change. Raw address-bearing evidence remains outside the public repository.

Next work is bounded host/guest scheduling alignment for task-owned vCPUs,
a predeclared OFF/OFF repeatability experiment, and concrete JIT/perf/deferred
resource bounds. None of these is implicitly marked complete by this report.
