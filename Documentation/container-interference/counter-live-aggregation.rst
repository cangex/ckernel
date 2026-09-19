Selected-counter live aggregation
=================================

The administrator may pass ``objects`` (one to eight aligned addresses)
with a manual ``counter`` request. The immutable selection and two target
identities are read back before ARM. No extra kernel hook or sampling
policy is enabled. The existing per-CPU call sampler and 64-step cap still
apply; counts describe observed sampled updates, not population totals.

At each selected actual update, the BPF program updates a per-CPU bucket
for selected address, target and operation. There are at most 96 buckets
per CPU and 512 possible CPUs; preparation shrinks the table to the
selected capacity (one unused bucket without selection). There is no
per-update shared global counter, map insertion, ancestor walk or stack
capture added by aggregation. Target call entry retains the existing
bounded stack sample. Kernel source callbacks and BPF entry still cost
CPU; map memory and export are included in the resource inventory.

Each bucket separates native usage additions, subtractions, limit reversal,
rollback, protection propagation and underflow correction. It records
object initialization generation, source sampling shift, observed depths,
timestamps and a histogram of call-entry-to-update elapsed wall time.
That histogram is not individual atomic latency, cycles, exclusive service
time or a sum suitable for computing total interference. The existing
complete-call report provides separate whole-call duration and stack data.

The source's nonrecursive process-context callback guard protects local
updates. Once all producers are detached, userspace reads and combines the
CPU buckets. Generation disagreement, zero generation, sampling disagreement
or quantity overflow taints the bucket. It cannot produce an E2 relation.
Other generations in different target/operation buckets remain separate.
The analyzer independently reconciles every count, quantity, time boundary
and histogram against raw step records. Missing selection, terminal audit,
bucket, raw events or invalid capture quality fail acceptance.

Shared counter updates are participation evidence, not holder/waiter
relations, cache-line contention, or proof that one container caused
another's slowdown. Unknown and host actors outside the two-target set are
not silently included as known participants. Address selection is only a
candidate filter; actual initialization generation supplies lifetime proof.
This first mode aggregates source-sampled calls, not all updates to a
selected ancestor. A future full-population mode needs a separate source
budget and must not inherit this mode's acceptance.
