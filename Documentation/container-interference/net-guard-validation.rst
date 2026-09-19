Dense network collection protection
===================================

Two containers each repeatedly use the native logical lock on one private
TCP socket through the disposable-VM fixture, with zero injected hold time.
Each executes eight half-second buckets, reporting cookie, operations and
errors. This is deliberate event pressure, not ordinary network throughput.

The frozen cohort is OFF/NET, three alternating rounds. No sampling rate,
map capacity, CPU guard, output limit or entry threshold is changed. A NET
window must be rejected with independently checked entry-rate, worker-CPU,
output-capacity or actual ring-loss evidence. A completed-looking dense
capture cannot pass this protection test. Safe stop is not dense profiling
acceptance, and any rejected window must produce no Socket or TX relations.

After source switches and program removal have been verified, the same
business processes must continue making successful operations. Native source
counters are sampled at detach and after business completion, and must not
advance. OFF must remain source-quiet. Original errors, process CPU, source
entry work, container CPU and memory snapshots are retained. Neither this
fixture nor two private socket cookies establishes all metadata capacities,
production overhead, packet-delivery correctness or a cross-container cause.
