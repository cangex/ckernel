# Validation record

## Current scope

This is a source-delivery candidate. No host kernel deployment is authorized
by this record. The source is based on old CKernel, not the observer kernel
used in recent workload measurements.

- Filesystem tests: 24 passed locally and on ARM64 Linux (logic/mocks).
- Source contract checks: 5 passed (not kernel runtime correctness).
- Full ARM64 Image and all 1709 modules: PASS.
- Diskless two-vCPU ARM64 KVM checks: PASS for the delivery release below.
- Restricted AppArmor policy reload/credential/SCM_RIGHTS regression: pending.
- Maple hotplug, allocation failure and exhaustive RCU/GFP tests: pending.
- New delivery kernel + filesystem groups combined workload performance: NOT_RUN.

## Full build and isolated guest

Build source: `479913fec41693a95bad0ab8670e5152168e2fea`. Later delivery commits
change filesystem user-space tools, selftest packaging and documentation, not
the kernel sources compiled here. Toolchain: GCC 10.3.1, GNU ld 2.37, pahole 1.17.
The exact tested configuration is `arm64-validation.config` alongside this file.

Final kernel release: `6.6.0-ckernel-delivery-20261016+`.
Module vermagic: `6.6.0-ckernel-delivery-20261016+ SMP mod_unload modversions aarch64`.

| Artifact | SHA256 |
| --- | --- |
| .config | 97054039dbaaaa672b0bc9b30084975deb2c6d9d57396f8ae6a7ed39ff4cbbf1 |
| arch/arm64/boot/Image | da5734f9ace4f9b328dbb5d93896d6680b927d775a4bde0f98847fe702ea641b |
| drivers/ckernel/ckernel.ko | 3b623a9916c414d6fd3c35917a5c76a81078ce1ad637ca46a40c400c6b88c35b |

The first full build and guest smoke passed but inherited the observer release
suffix from the starting configuration. Those artifacts were preserved before
rebuilding with a distinct delivery suffix. The second full compilation passed;
its post-build checker rejected the upstream-added `+`. This failure remains
recorded. Review of `scripts/setlocalversion`, clean tracked source, exact config
hash, release and matching module vermagic established the normal non-tag SCM
suffix. A separate finalizer tested those already built artifacts without
restarting the failed service or overwriting its failure record.

Both guest runs used two vCPUs, 2 GiB RAM, no network and no host disks. The final
run exited zero with `DELIVERY_GUEST_END failures=0`. It checked:

- All seven quarantined parameters reject nonzero activation.
- Mask zero leaves Maple/self-signal inactive; unavailable feature requests fail.
- Unmediated self-signal cache: 9 hits; this is not a restricted-policy test.
- Two-CPU Maple smoke: 1778 stock hits and 1808 returns, not a performance result.
- Native fallback preserves overmount lookup and ancestor FD limits, both with
  and without an initialized CKernel context (13 opens followed by EMFILE).
- CKernel module unload succeeds after these finite cases.

The guest selected AppArmor; the host remained SELinux Enforcing with AppArmor
disabled and boot ID `e48d768b-1963-4b23-bad2-8db17de398cd` unchanged. No host
kernel/module installation or reboot occurred. Artifacts and small runtime
records remain under `/root/ckernel-delivery-20261016`, including
`release-r2-failure.json`, `release-final.json`, and `guest-r2/result.json`.

This was not a warning-free build: retained warnings include unused scheduler,
Hisilicon KVM/sys_regs variables/functions, memcontrol misleading indentation,
and a 4112-byte frame in the quarantined legacy `ck_check_path`. Other build
configurations, restricted-policy transitions, exhaustive concurrency/fault
tests and combined business performance are not certified by these checks.

## Owned filesystem integration

The delivered lifecycle tools passed a bounded native ARM64/container test with
SELinux Enforcing: two separate 128 MiB filesystems, each with four workers and
128 files, hard links/rename/read checks, explicit fsync, bounded ENOSPC,
stopped-container reference refusal, clean unmount/fsck/remount persistence,
bad entrypoint, exit 17 preservation, and injected pre-mount failure recovery.
The final check found no test containers or loop devices. The host boot and
security state were unchanged. This is not crash/power-loss qualification or
new workload performance evidence.

Tested filesystem source: `c559c84d414208fe6938cee92abf06e8c6974a3d`.
Records: `fs-smoke-r2/result.json`, `fs-r1-recovery.json`, and `fs-tests-r2.json`
under the same remote delivery root. Filesystem logic is unchanged in later
documentation/selftest-packaging commits. All 24 filesystem tests and 5 source
contract checks were rerun locally before final publication.

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
