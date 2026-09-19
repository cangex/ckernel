Network event-pressure protection evidence, 2026-09-20
====================================================

Tools ``d4a30a079ae7086eebac13d3526e1d3c17bc2058`` ran against the same
``5c2bf8603`` fault-capable guest Image documented in the TCP failure report.
No failslab parameter or TCP budget was enabled for this cohort. Host kernel
and boot ID remained unchanged; only the existing isolated VM fixture ran.

Remote evidence is
``/dev/shm/cis-x-20260919/evidence/net-guard-cpu-d4a30a079-20260920``.
Serial ``x4-net-guard-20260920-071933.log`` has SHA256
``2b8e4700efd089684ff9644b563f7e49b124b3b35404598f328dfe1a4621341f``.
Independent ``net_guard_check.py`` replay passed all six fixed states:
three alternating OFF/NET pairs. Two actors used different private Socket
cookies with no injected hold time and continued for eight 500ms buckets.

All three NET captures remain PARTIAL with CANCELLED worker receipts and
``COMBINED_PROCESS_CPU_CAPTURING`` controller budget reasons. First detected
CPU violations were 41,521,750ns, 42,007,350ns and 42,103,750ns against the
unchanged 40,000,000ns limit. Phase peaks were 41,847,070ns, 42,338,540ns and
42,428,570ns. This is cooperative stopping, not a hard-real-time 40ms bound
and not reuse of the historical 40.60ms waiver.

Native source selections were respectively 423,470, 483,680 and 432,794.
Reported output losses were 404,353, 462,419 and 413,634; received records
were 423,500, 483,711 and 432,826. The rejected windows emitted no accepted
Socket or TX relationships. Loss counters do not identify every output
failure's errno or prove a unique queueing cause. Dense profiling is NOT
ACCEPTED, even though safe rejection and cleanup passed.

The source-off observations occurred 372,606,420ns to 374,193,300ns after
window start. This includes the planned business start offset and subsequent
controller/cleanup observation; it is not an anomaly-detection latency.
After these observations, each same actor completed more than ten million
additional fixture operations. All bucket errors and exits were zero.
Native source counters did not advance after detach, and OFF was quiet.
Fixture unload and guest exit were zero; no kernel warning was accepted.

Maximum whole-worker CPU was 154,581,500ns and peak RSS was 21,908KiB.
These do not include all source callback, management or background costs.
The active bursts can substantially perturb work before the guard cancels;
this test establishes rejection and continued progress, not low overhead.

The earlier b229e3fd8 run remains an incomplete failed cohort. Its verifier
did not recognize the real controller cancellation protocol. The corrected
verifier requires the independent fixed-limit first-violation record and
has negative tests for arbitrary cancellation and forged below-limit cost.
All three final rounds were rerun, not selected from that earlier attempt.
