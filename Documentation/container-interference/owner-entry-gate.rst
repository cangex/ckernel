Experimental owner entry gate
=============================

This bounded prefilter is disabled by default. The dedicated VM may boot with
``cis_observe.wait_gate=1``. It is not container identity filtering, a new lock
algorithm, or completed low-cost acceptance.

BPF owner watches are created only at WAIT. The gate admits every WAIT and
remembers a hash of (object address, resource kind) in an 8-KiB monotone bitmap.
Other phases are admitted if that bit is present. Collisions admit extra events;
they cannot drop a phase of an object already remembered. There is no deletion
while any probe is registered, so RESET/RETIRE and non-target-holder transitions
of a watched address still pass. First-WAIT boundary races retain the existing
snapshot/unknown limits, not a reconstructed pre-window history.

The bitmap resets in the tracepoint's first-registration callback under the
tracepoint registry mutex, before enabling the tracepoint. The tracepoint core
synchronizes the prior probe generation before publishing the new one. Old
in-flight writers after reset can only add false positives. Additional consumers
do not reset it. Long-lived consumers can saturate the filter and lose its cost
benefit; they do not broaden attribution. The parameter is read-only after boot.

This removes never-waited objects from the expensive callback path, including
irrelevant retirement during an interrupted callback. It does NOT pardon any
remaining recursion. Skipped, filtered, BPF lock entries, scheduler entries,
target WAITs, watched events and outputs have different meanings; do not add
overlapping counters or rename filtered entries as complete kernel coverage.

No allocation or management lock is taken on the filtered path. A first bit
insertion uses an atomic bitmap update and barrier; subsequent tests are reads.
The bitmap is host-shared, not an isolation claim. Its cache-line traffic and
the per-CPU filtered counter must be included in new cost measurements. Kernel
and BPF entry overhead remains even when output is empty. Existing entry guards
still stop genuine target storms and false-positive saturation.

Required regression includes a registered non-target holder, private objects,
address reuse, owner switches/preemption, WAIT abort and cross-window cases.
Fixture delays are opt-in: ``enable_dentry_delay=1`` is only for dentry ground
truth. Ordinary session/latency tests leave that callback unregistered.
No historical latency PASS may be transferred to this new kernel or fixture.

Session workers also read quiescent producer counters before attachment and
after synchronous detach. BPF's last observed skip counter cannot detect a
skip after its final callback. The producer delta is a separate required owner
receipt field; either positive delta rejects completeness. Missing debugfs,
an active unrelated consumer, counter regression or changed possible-CPU set
rejects this audit rather than assuming zero. The diagnostic stack/address
option remains off in cost runs: base per-CPU counters exist independently.
Boundary reads cost preparation/drain CPU and are not free or in-window I/O.
Snapshot v3 explicitly calls ``tracepoint_synchronize_unregister()`` after
links close and before BPF terminal map/ring consumption. In this OLK,
``bpf_probe_unregister`` merely unregisters; last-link close by itself is not
a grace-period barrier. Reads fail while another owner consumer is active.
The worker rejects older snapshot versions. Waiting time is bounded only by
the existing cooperative controller timeout, not an RCU hard-time guarantee.
Admission additionally binds the full boot-command-line hash. Matching Image
notes alone cannot distinguish gate-on, gate-off and diagnostic-counter modes.
Changing these boot flags invalidates acceptance even on the same Image.
