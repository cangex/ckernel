Mixed-source X7 prototype cohort
===============================

This is a bounded, independently checked coexistence test, not a whole-kernel
coverage or production performance claim. Four registered roots each run 1500
ordinary file or VMA operations at a fixed offered rate. The complete ordinary
workload interval must contain the two-second diagnostic window.

Two roots additionally use native TCP logical socket locking through the
existing test-only fixture. Two other roots perform direct I/O on disposable
VM virtio disks. Each of the sixteen read/write operations must overlap an
independently timed native socket holding interval. Processes merely existing
at the same time are insufficient. Actor pairs rotate across three rounds.

The precommitted matrix is shared/private x three rounds x OFF/IP/NET/BLOCK:
24 states and 18 captures. Round two reverses collector order. Each collector
has its own window; this does not authorize concurrent production collectors.
The existing 40ms CAPTURING process-CPU guard and admission limits are unchanged.

``mixed_vm_check`` replays raw samples with the existing network and block
analyzers, then compares them with independent ioctl brackets, socket cookies,
direct-I/O completion checks and timestamps. Shared sockets must have the exact
four logical holder/waiter relations. Private sockets cannot acquire unrelated
holders. Sixteen block request episodes must match their actual submitter and
bio billing root. Sharing a disk never proves a unique blocking container.
Network source counters must stay quiet in OFF, IP and BLOCK modes.

Business arrival-relative latencies, throughput at the fixed offered rate,
per-root and management CPU/memory, whole-VM gauges and matched kernel-thread
CPU are retained. P99 is record-only. Bookends include unrelated work, miss
some short-lived threads, and do not isolate all observer memory or CPU.

The runtime harness and verifier are separate entry points. Passing unit tests
does not establish runtime acceptance; preserve failed preparations and guest
runs, bind evidence to source/kernel hashes, and replay the full fixed matrix.
