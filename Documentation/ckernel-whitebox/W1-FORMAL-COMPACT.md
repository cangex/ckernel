# W1 isolated-VM business result

Matched kernels, one shared 52-vCPU guest, 12 containers, unchanged official checks.
These are not bare-metal NUMA results. No host kernel was changed.

| Workload | Formal paired blocks | Baseline interference | W1 interference | Change pp | Absolute loaded time | Correct copies |
|---|---:|---:|---:|---:|---:|---:|
| CORE Excel extraction | 5 | 8.38% | 9.16% | +0.79 | +0.78% | 130/130 |
| Go installation | 12 | 534.59% | 511.90% | -22.69 | +0.11% | 312/312 |

Interference is mean loaded target duration / own-config mean solo duration - 1.
Go solo changed from 2.476402493s to 2.571075073s; the reduced ratio is NOT an
improvement in loaded business time. Its paired loaded 95% interval is
[-0.60%, +0.82%]. CORE paired loaded interval is [+0.20%, +1.37%].

Neither workload establishes the predefined 3% business improvement. Neither
establishes the complete bystander 2% guardrail: the worst-copy interval extends
above that bound. Correctness here means workload checks, not complete kernel
lifecycle verification. Host/backend cost attribution remains incomplete.

No 24/48 expansion or combination is justified by these results. Separate bounded
resource diagnosis observed reduced inode-hash slowpath intervals in CORE; the Go
candidate trace lost records and cannot supply exact totals. No lock-cost fraction
is inferred from elapsed time. Minimal per-copy calculation inputs are retained.
