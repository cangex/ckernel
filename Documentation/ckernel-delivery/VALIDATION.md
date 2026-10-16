# Validation record

## Current scope

This is a source-delivery candidate. No host kernel deployment is authorized
by this record. The source is based on old CKernel, not the observer kernel
used in recent workload measurements.

- Filesystem tests: 24 passed locally and on ARM64 Linux (logic/mocks).
- Source contract checks: 5 passed (not kernel runtime correctness).
- Full ARM64 build and isolated guest checks: pending at this commit.
- Restricted AppArmor policy reload/credential/SCM_RIGHTS regression: pending.
- Maple hotplug, allocation failure and exhaustive RCU/GFP tests: pending.
- New delivery kernel + filesystem groups combined workload performance: NOT_RUN.

## Owned filesystem integration

The delivered lifecycle tools passed a bounded native ARM64/container test with
SELinux Enforcing: two separate 128 MiB filesystems, each with four workers and
128 files, hard links/rename/read checks, explicit fsync, bounded ENOSPC,
stopped-container reference refusal, clean unmount/fsck/remount persistence,
bad entrypoint, exit 17 preservation, and injected pre-mount failure recovery.
The final check found no test containers or loop devices. The host boot and
security state were unchanged. This is not crash/power-loss qualification or
new workload performance evidence.

The first run failed closed during cleanup: a process mountinfo read returned
EINVAL. Its failure and original manifest were retained. The narrow repair
accepts this error only when the process exposes no mount namespace; a live
namespace or permission error still refuses cleanup. Recovery of the original
owned volumes and one fresh integration run then passed. No forced/lazy unmount
or foreign-resource cleanup was used.

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
