Y1 boundary-only public-resource configuration view
==================================================

The periodic session controller invokes resource_topology.collect through its
existing asynchronous boundary snapshot operation. No source probe, process
watcher, per-syscall hook, hot-path map or central event lock is added. Topology
cost is included in preparation/verification CPU and source support hashes.
Historical records without this observation remain UNOBSERVED.

Each selected container has a pinned registration cgroup FD and generation.
The read budget is 32 cgroups, depth 8, eight tasks, 128 mount rows per task,
32 ancestors, 256 reads, 256 KiB and 25 ms between cooperative checks. The
thread CPU, bytes, reads and monotonic endpoints are saved. These are work
bounds, not a guarantee that an individual procfs/sysfs call cannot overrun.
Partial reads never certify a complete or stable configuration.

The view records actual ancestor identities and available quota/cpuset
configuration, task start times and cgroup membership, mount/network namespace
identities, task CPU/NUMA allowance, and mount filesystem/device information.
Mount options are allowlisted; remote sources and arbitrary options which may
contain credentials are not retained. Per-task namespace interface names stay
namespace-local: two private ``lo`` devices never become one host NIC queue.
CPU/node ranges remain intervals, not a container-times-all-CPU allocation.

For block-backed mounts, sysfs device/queue paths and diskseq are recorded when
available. These are configuration handles, not kernel request_queue addresses.
Stacked-device dependencies, overlay lower layers and veth/NIC peers are marked
unresolved. They are not guessed from names. Later specialists must establish
observed resource use and object lifetimes before attributing contention.

Every task association is checked before and after its read. Every session
compares full topology fingerprints at the boundaries. Registration generation,
task exit/recreation, cgroup or namespace movement, affinity and visible mount
configuration changes invalidate the association. A deleted pinned cgroup is
unknown, not a newly created group at the same pathname. Restart does not load
old topology as current state.

Survey reference epochs include the topology fingerprint. Changed or partial
topology prevents an automatic comparison against an earlier reference; direct
PSI/counter/IP facts remain available. This conservative loss of automatic
comparison coverage is explicit, not reported as absence of interference.
An image or workload-phase change which is not visible here still requires an
explicit epoch notification. Eight-task/cgroup/mount limits must be considered
when interpreting the covered container population.

Equal endpoint fingerprints only prove equal endpoint observations. They do
not exclude changes and reversal within the interval, demonstrate continuous
device lifetime, prove a mount was accessed, or identify a holder or blocker.
Shared candidates are explicitly CONFIGURATION_ONLY, never E2. Two private
directories on one filesystem may share its backend; this does not show they
contend on the same directory inode. A shared read-only layer need not cause
interference. All missing, truncated and raced observations remain visible.

The disposable-VM test covers separate private tmpfs and network namespaces,
common cgroup ancestry, affinity changes, migration into a descendant cgroup,
mount-namespace replacement, unregister/reregister generation, task exit and
same-path cgroup recreation. The joint cohort then exercises the live session
integration with IP and backend-only collectors under four containers. Pure
parser and budget tests supplement, but do not replace, this runtime evidence.
