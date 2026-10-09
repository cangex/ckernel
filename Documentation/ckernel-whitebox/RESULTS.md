# Whitebox bounded experiment decisions

All numbers below are isolated ARM64 KVM results, not bare-metal NUMA. No host kernel was changed.
Interference = 100 * (mean loaded target duration / same-variant mean solo duration - 1).
A reduced interference ratio is not a benefit if solo became slower. Workload correctness is not exhaustive kernel correctness.

| Patch | Workload | Copies | Blocks | Baseline % | Candidate % | Change pp | Loaded time change % | Decision |
|---|---|---:|---:|---:|---:|---:|---:|---|
| W1 | core | 12 | 5 | 8.38 | 9.16 | +0.79 | +0.78 | NET_BENEFIT_NOT_ESTABLISHED |
| W1 | go | 12 | 12 | 534.59 | 511.90 | -22.69 | +0.11 | NET_BENEFIT_NOT_ESTABLISHED |
| W2 | go | 12 | 5 | 521.72 | 528.53 | +6.81 | -1.44 | NET_BENEFIT_NOT_ESTABLISHED |
| W3 | core | 12 | 5 | 9.97 | 8.88 | -1.09 | -1.15 | NET_BENEFIT_NOT_ESTABLISHED |
| W3 | go | 12 | 12 | 530.37 | 512.49 | -17.88 | +1.71 | COST_TRANSFER_OR_REGRESSION |

## Stage disposition
- W1: inode-hash mechanism reduction observed; formal business benefit not established.
- W2: context/churn/reload checks passed; formal Go business benefit not established. No measured paired cache-lock reduction claimed.
- W3: live shared buffer mapping lock identified; file operations and guest recovery checks passed; formal benefit not established. No paired lock-reduction total claimed.
- W4: insufficient evidence for a safe removable journal/writeback/block coordination; no behavior patch admitted.
- W5: CORE/Go cross-load testing performed as listed. No qualifying patch, so no 24/48 or combination matrix; not mislabeled PASS.
- W6: authorized bounded candidate evaluation closed with negative/insufficient-evidence decisions, not successful interference elimination.

## Remaining limits
Guest policy is Enforcing; shared MCS categories are not per-container MCS isolation. Guest clock correction was confined to filesystem correctness fixtures.
W3 fs-r1/r2 rejected early-epoch fixture output; fs-r3 crash exit-only gate was insufficient and superseded by fs-r4 recovery+read-only checker diagnostics.
KASAN/lockdep, comprehensive reclaim/allocation fault injection, all-filesystem lifecycle and physical power-loss testing are not completed.
Host/backend cost attribution and whole-VM memory guardrails are incomplete. Formal intervals and per-copy data are retained; no P99 is inferred from a few trajectories.
No bare-metal patch result exists. Experimental patches are retained in history and reverted, not enabled as production defaults.

W3 experiment: 158f90e7149011f87404fde8afb05704b15bfa05; restore: cc7ecab3727cac1823235e7d63cbf117b6f93705.
Earlier W1 experiment ccad5bf8942eb358c04a26b50924ba8541911a15; W2 experiment 55765ad1fc8a73fd663ed0db9278a81a705ad107.
The kernel source tree after all three reverts equals the fixed pure baseline; later changes are validation tools and documentation only.
