# Whitebox experimental validation helpers

`make check` runs parser/statistics unit tests without starting workloads.
`make` builds user-space correctness fixtures; it does not run them. The W2
fixture reloads the unchanged SELinux policy and relabels test files. The W3
fixture sets the guest wallclock and can run until its own VM is killed.
Run these fixtures ONLY in a disposable, dedicated SELinux-Enforcing VM,
never directly on a shared host. No fixture authorizes host reboot.

The branch records experimental patches followed by explicit reversions when
business net benefit is not established. A compiled patch or a lower lock
count is not a production approval. See Documentation/ckernel-whitebox.

The runners expect frozen private test assets under
`/root/ckernel-whitebox-20261009`, build directories under `/home`, ARM64 KVM,
the recorded container images, original replay/checker files and a matching
SELinux policy. They are experiment reproduction tools, not a portable
benchmark installer. There are no SSH credentials in this directory.

Performance runs use one shared 52-vCPU/52GiB guest, fixed host CPUs0-51,
management48-51 and four logical CPUs per business copy. They do not model
multiple independent VM kernels as container contention. Persistent ext4
and separate OverlayFS writable workspaces are preserved. No detailed
tracer is loaded in OFF runs. Official scoring starts after all timed
business work completes. Tests are no-model tool replays, not full agents.

For a frozen pair, run the corresponding run_w*_matrix.py with workload,
`--mode pilot --stamp <new-name>`, then analyze_matrix.py with
`--freeze-formal`. Use that saved plan exactly once with `--mode formal
--formal-plan <path> --stamp <new-name>`. Existing outputs are not overwritten.
Do not extend sample count in response to a p-value. Use each variant's own
solo duration and also inspect absolute loaded/solo durations and per-copy
guardrails; ratio reductions caused by a slower solo are not improvements.

Crash verification uses a durably written marker, abrupt termination of only
the owned guest, recovery boot using the same tested Image, durable read,
clean remount and read-only fsck. This is not physical-device power loss.
Both exit status and checker diagnostics matter. KASAN/lockdep, allocation
fault injection and exhaustive reclaim/lifecycle coverage remain separate
gates, not inferred from this fixture.
