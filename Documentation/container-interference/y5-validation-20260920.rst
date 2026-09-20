Y5 public transmit queue validation, 2026-09-20
==============================================

Status and frozen inputs
------------------------

PASS_SCOPED: ten administrative checks, 24 private-flow OFF/ON states and
six source-protection OFF/ON states pass in the dedicated ARM64 KVM guest.
Independent raw-log replay passes both on the development host and locally.
The enabled full Image/modules are 9c67feafa. Traffic tools are 725679c5f;
source-protection tools are 74dd3ac2d. Kernel source equivalence excluding
tools is recorded for both cohorts. The 14-machine host kernel, networking,
Docker, running containers and boot identity are unchanged.

Control and interpretation
--------------------------

The administrative lease pins a host-network-namespace device, transmit
queue and qdisc with a monotonic generation. Strict arguments reject overflow,
negative values and extra fields. Invalid socket/device/queue, concurrent
selection, selection mutation and inherited-fd misuse are rejected. A native
qdisc change or replacement invalidates the lease. Revocation with a no-op
probe still attached cannot grant a new lease. Equal qdisc handles on distinct
devices do not merge their identities. All devices are removed after closing
leases; the test module unloads successfully.

One qdisc BPF program uses five maps, no stack map, socket watch or per-packet
lifetime map. Native sampling is one in 16 per CPU and event class. The native
entry audit covers filtering/sampling before BPF. Sampling does not represent
complete packet counts. Admission samples carry zero serviced packets; service
points describe only the original head, not wire completion. Missing acquisition
time on a NOLOCK or early-drop path is not a zero-duration proven lock wait.

Traffic observations
--------------------

Two containers have separate PID/mount identities, cgroups and newly created
private UDP sockets. Direct cases explicitly join the guest host network
namespace after entering their own cgroups. Forwarding cases use two separate
network namespaces and guest routing. Controlled virtual egress uses TBF at
2 Mbit/s, an 8192-byte burst and 65536-byte limit. Each actor sends 1000 checked
1024-byte datagrams at 1000/s. The disposable sink validates contents and
destination, records duplicate/invalid packets and retains UDP losses. This
is not a zero-loss application throughput test or a physical NIC benchmark.

Three alternating OFF/ON rounds cover sharedDirect, separateDirect,
sharedForward and unselected. The frozen target is one exact transmit queue.

* Shared direct traffic: 125--127 admission and 19--21 service samples; both
  registered executors and socket-accounting roots participate in one queue.
* Separate direct traffic: 62--63 admission and 18--19 service samples; only
  the actor using the selected queue is attributed. No false shared relation.
* Forwarded traffic: 124--125 admission and 18--19 service samples. All
  142--144 samples retain unknown executor/socket origin instead of assigning
  a softirq or host task to either container. Queue pressure is visible, but
  container-to-packet provenance is NOT PROVIDED for this path.
* Unselected traffic: zero accepted samples from the unrelated queue. Native
  filtering remains counted. OFF states have zero native callbacks.

Backlog observations occur in every selected traffic state. They establish
point-in-time pressure, not per-container occupancy, a particular lock holder,
an exclusive blocker or an E3 causal relationship. Exact-root socket accounting
is supported; descendant, retired and transformed packet accounting can remain
unknown. TC class/filter-only administration is frozen for this scoped contract.

Protection and costs
--------------------

Six independent high-rate OFF/ON states keep traffic running for four seconds.
All three ON captures stop with ENTRY_RATE_LIMIT, retain PARTIAL quality and
publish no accepted queue relations. Native entries before detachment are
182351, 178442 and 175612, with measured intervals proving the unchanged
200000-entry/s limit was exceeded. Both senders continue after detachment
(3,582,556--3,618,208 operations per actor). Every native audit counter remains
unchanged after source detachment while that traffic continues. OFF states
also have zero native callbacks. This is PASS_PROTECTION_ONLY, not coverage
acceptance of an over-budget recording.

For the normal 12 ON traffic sessions, observed CAPTURING process CPU peaks
are 4.985490--6.019750 ms, combined process RSS peaks 32,083,968--39,530,496 bytes,
and whole observer-process CPU 96.994300--124.815420 ms including preparation.
These values do not include all in-business native/BPF or asynchronous kernel
costs. No Y7 low-overhead, target/bystander throughput or tail-latency acceptance
is inferred. Preparation is not hidden inside an active-window-only claim.

Builds and retained failure
--------------------------

735 Python tests, 21 owner tests and seven profile tests pass on Linux. Enabled
and CONFIG_CIS_OBSERVE-disabled full ARM64 Image/modules builds pass. The
disabled build contains neither the qdisc tracepoint nor native helper symbols.
The initial traffic harness stopped before traffic because the minimal guest
lacked /var/run; that failed cohort is retained. The guest setup was fixed,
not the workload, coverage requirements or budget thresholds.

Evidence and replay
-------------------

Remote evidence root is /dev/shm/cis-x-20260919/evidence/:

* y5-control-9c67feafa-20260920: full enabled build and control VM.
* y5-capture-0125055a4-20260920: tools/BPF build and unit regressions.
* y5-queue-9e554a431-20260920: retained pre-traffic guest failure.
* y5-queue-725679c5f-20260920: 24 flow states and raw replay.
* y5-guard-74dd3ac2d-20260920: six protection states and raw replay.
* y5-off-725679c5f-20260920: disabled full build and hashes.

Local copies/replays under .codex-tmp/container-interference-20260916/ are
y5-control-evidence-20260920, y5-control-local-recheck-20260920,
y5-queue-evidence-20260920, y5-queue-local-replay-20260920,
y5-guard-evidence-20260920, y5-guard-local-replay-20260920 and
y5-off-evidence-20260920. Set PYTHONPATH=tools/container_interference and run
y5_control_check.py, y5_queue_check.py or y5_queue_guard.py with the immutable
serial log and a new output directory. VM manifests bind source, Image,
initrd, fixed CPUs and commands. Y6 and Y7 are not accepted by this receipt.
