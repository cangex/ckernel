# Validation record

## Current scope

This is a source-delivery candidate. No host kernel deployment is authorized
by this record. The source is based on old CKernel, not the observer kernel
used in recent workload measurements.

- Local filesystem tests: 21 passed (logic/mocks, not ext4 fault injection).
- Source contract checks: 5 passed (not kernel runtime correctness).
- Full ARM64 build and isolated guest checks: pending at this commit.
- Restricted AppArmor policy reload/credential/SCM_RIGHTS regression: pending.
- Maple hotplug, allocation failure and exhaustive RCU/GFP tests: pending.
- New delivery kernel + filesystem groups combined workload performance: NOT_RUN.

## Historical findings retained

The 2026-09-11 audit reproduced stale VFS lookup after overmount and bypass of
files-controller limits. It also identified path-based AppArmor allow shortcuts
and socket-hook shortcuts that did not establish original security semantics.
This candidate quarantines those activation paths, rather than claiming their
algorithms have been repaired. Experimental self-signal and Maple code remain
off by default. Remaining legacy mechanisms need independent qualification.

## Existing filesystem performance, NOT this combined kernel

The Go four-loop-ext4 experiment used eight paired blocks, 64 accepted states
and 1360 copies on a SELinux-Enforcing observer-modified OLK host with AppArmor
inactive. The native arm used the original overlay; the grouped arm bound the
fresh slot directory at /usr/local/go. This changes filesystem/access paths as
well as grouping, and is not a pure-lock causal intervention.

| Copies | Native slowdown vs own solo | Grouped slowdown vs own solo |
| --- | --- | --- |
| 12 | 2.8368% | -0.3459% |
| 24 | 15.5797% | 2.7265% |
| 48 | 84.7223% | 14.3556% |

Native solo 2.319049 s; grouped solo 2.274262 s. Below-5% interval support
exists at 12/24, not 48. All-slot noninferiority remains unresolved at 48.
Full-system/lifecycle net benefit is not certified. One post-business control
failure was retained and excluded; no exit status was rewritten as success.
These numbers do not validate AppArmor, Maple or their combination. The
CPU/NUMA placement experiments are a separate intervention, not part of this
filesystem implementation. All workloads are finite no-model tool replays.
