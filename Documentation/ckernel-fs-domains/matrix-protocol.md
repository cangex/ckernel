# Matched Go filesystem grouping experiment

## Scope

Only the accepted Go installation tool replay is executed. The host currently
runs `6.6.0-wb-mmuobs-20261011`; this is an observation kernel, not unmodified
OLK. SELinux remains Enforcing. No kernel behavior patch or host reboot is part
of this experiment. `/usr/local/go` is a direct bind in every arm. The download
and other paths retain their existing container layout.

All arms use freshly created, fully allocated regular-file loop-ext4 images on
the same root filesystem/physical disk. This is not an independent-block-device
claim. The common outer filesystem, device and hardware remain shared.

## Conserved budgets

Compare 1, 2, 4 and 24 filesystems. Each arm has 18 GiB gross blocks, 787968
actual inodes, 384 MiB journal blocks and zero reserved percentage. Formatting
uses 4-KiB blocks, 256-byte inodes and fully initialized inode tables/journals.
Actual usable space and metadata overhead are measured, not assumed equal.
Every actual layout must pass `geometry()` before a business sample is taken.

24 slots retain their frozen CPU/NUMA/memory limits. Small groups each include
both NUMA sets, and group assignment rotates across blocks. Each state resets
all business workspaces and filesystems. No global cache drop, sleep-as-load,
workload reduction, model use or evaluator modification is allowed.

## Pilot and formal separation

Pilot: three fixed blocks, all four arms, each with solo and 24-copy states.
Pilot observations assess capacity, correctness, timing and variability only.
Formal execution requires a separate admitted `formal-freeze-r1.json`, written
after the independent pilot is reviewed. The proposed formal order uses eight
balanced blocks (64 states), with within-block solo/loaded order alternating.
Any inability to resolve the small 2%/5% cost margins is reported as unresolved;
sample counts are not increased in response to significance.

Formal primary comparisons are each split arm against shared-1, paired by block.
Use paired log-ratio Student intervals, 95% familywise across the three arms
(two-sided 98.3333% interval for each primary comparison). Report arithmetic
solo/loaded means and `100*(loaded/solo-1)` separately. All per-slot times,
batch makespan and copy correctness remain visible.

Retention requires at least 3% primary business improvement with an interval
supporting improvement, plus predeclared 2% noninferiority and 5% resource-cost
checks. Target improvement alone is not a net-benefit PASS. Per-slot and
background/memory evidence gaps must not be hidden by an aggregate average.

## Measurement boundaries and limits

Official scoring is performed only after every copy has finished measured
business. The formal collector watches the existing sixth action in each
container's `/replay-results/actions.json`, through its observed PID root, and
stops without waiting for the later `done.json`. The replay and all commands
remain byte-identical. Snapshots record their own monotonic intervals; cgroup CPU and
host/disk/kernel-thread counters are not treated as exactly instantaneous.
Memory/space sampling is 200 ms and therefore does not establish exact peaks.
The pilot's full kernel-task scan caused up to 0.733 seconds of end-snapshot
delay and 184--266 ms of sampler CPU. It is removed from the proposed formal
OFF protocol rather than filtering its samples. Formal host CPU totals and
phase counters include unrelated services and do not uniquely attribute
background work; a separate diagnostic would be required for that ownership.
The first lighter collector still waited for `done.json`, so its timing admission
failed. Source inspection located `end = monotonic_ns()` before shell/server
shutdown and archive hashing, while the entry copies evidence and writes
`done.json` only afterwards. Thus the old cost window included 0.256--0.462 s
of post-business work. No replay-duration sample is rewritten as a result.
The second timing admission uses the preexisting action file and must pass the
original 50-ms sampler-CPU / 150-ms ending-offset limits before formal execution.
Pilot task CPU remains historical, with the timing limitation.

The same bounded summary collection is present in every performance arm. No
perf/BPF detailed collector is loaded in these OFF runs. Its thread CPU and
timing boundaries are recorded. Creation/mount, business, official scoring,
drain/unmount/fsck/deletion are separate phases; setup and teardown are not free.

Failures, rejected preparations and cleared data remain indexed. Current
evidence: systemd STDOUT denial before Python; inode rounding refusal before
business. Neither is a successful performance sample.
