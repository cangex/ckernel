Periodic owner identity universe
===============================

An owner session has at most two diagnostic targets but up to 256 registered
container identities. These are different sets. Selecting one waiter must not
erase the identity of an already registered non-target lock holder.

Protocol 2 snapshots the registered roots at admission and includes their
IDs, generations and target roles in the durable record and configuration
digest. The controller pins each cgroup FD and rejects registration mutation
while admission, capture or cleanup is active. The worker inherits and
revalidates these FDs; missing, deleted, overlapping or invalid roots reject
the session. IP-only sessions still receive only selected targets.

Only selected roots receive BPF target deadlines. Identity-only roots do not
start PSI, IP or lock diagnostics. Their identity can appear as an actor or
holder of an object watched because a selected target waited on it. The
existing bounded ancestor lookup is unchanged; there is no hot scan over
all registered containers. Unregistered or unresolved holders remain unknown.

The bounded root map is populated before the 100 ms ARM lead interval. Stack
export and watch cleanup run for diagnostic targets, not once per registered
holder identity. Preparation, inherited FDs, registration validation and map
memory are not free: include them in whole-session CPU/memory acceptance.
There is no claim that a 256-root registry has the same setup cost as one root.

Regression: register both roots, select only the waiter, then require an E2
edge to the registered non-target holder. Run with the optional WAIT gate off
and on. Such an edge is an observed participation relation, not an E3 causal
claim. Root deletion/recreation and unknown-identity cases remain separate
identity lifecycle tests.
