X6 specialist routing and normalized explanations
=================================================

Implementation contract, not runtime acceptance
-----------------------------------------------

``diagnosis_status``, ``diagnosis_offer`` (a retained IP session),
``diagnosis_run`` (a candidate ID) and ``diagnosis_auto`` (an explicit boolean)
use the existing administrator-only control socket. There is no second worker
channel. A queue request is admitted through Controller.start, the same
host interval, source-bound permit, session count and resource guards as a
manual capture. No quotas, workloads or CKernel optimization are modified.

The queue has at most eight candidates, a five-minute source age, a
180-second target/collector cooldown, and two automatic starts per permit
ledger. Queued work cannot bypass a draining or faulted session. A specialist
must yield the next automatic slot to ordinary IP profiling. Last-served
target order breaks ties; waiting and sample age are recorded independently.
Expired/unregistered/epoch-changed candidates are discarded. Queue contents
and automatic enablement are not restored after restart; admission/cooldown
counts persist before worker spawn. Changed source binaries require new
permit binding. Configuration changes invalidate old survey epochs.

Automatic routing is default off and prototype-only. It requires an actual
current-source, quality-accepted earlier session for that collector; merely
having a BPF file is insufficient. Normal valid hotspots can produce manual
suggestions. Only a valid survey with observed rate deviation can be selected
automatically. Neither case upgrades a hypothesis into a root cause.

Counter, allocator, network, block, FD and generic-lock paths now route to
their own collectors rather than the mutex owner adapter. Exact cache/socket
selection and supported contexts still apply. A route to an adapter is not a
promise that the hinted object was sampled or that a causal result will follow.

``unified_report.py RECORD RAW NEW_OUTPUT_DIRECTORY`` writes private JSON and
Chinese Markdown. It keeps holder/waiter, common updates, allocation phases,
backlog and request episodes as distinct relation types. It retains raw hashes,
source identity, quality, detailed specialist results, unknowns and clocks.
No nested intervals are added into total interference, and no report produces
E3 without a separate controlled experiment. Output is capped at 128 relations;
omitted counts are explicit. CLI analysis occurs after capture, not in hot paths.

Unit tests exercise source/capability binding, shared admission budget,
cooldown, fairness, stale epochs, restart counts and false relation promotion.
Native queue routing, automatic interleave and failure recovery still require
their own isolated VM evidence. This implementation does not close X1--X5
coverage gaps or establish production performance acceptance.
