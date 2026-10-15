Recovery boundary
=================

Each mutating step writes and fsyncs an intent, executes, reads back its
postcondition and durably commits. A failed or interrupted step leaves the
intent unresolved. The manifest and DM metadata are not atomically committed.

General recovery is observational and fail-closed. It checks registered
backing and live mapping identities, incomplete branch states, pending intents
and boot identity. It never retries a non-idempotent create_snap/delete/format
message on the strength of a path or PID. Unknown ownership stays quarantined.

A narrow reconciler handles a registered branch whose private namespace was
lost: it requires the same boot, no pending effect, verified pool/mapping
identity, no remaining mounts/containers/FDs/mmaps, zero device open count and
a successful filesystem check before removing the mapping and sealing results.
Namespace inode numbers can be recycled; their equality is not liveness proof.
Normal host-visible mounts may propagate on the existing shared host root.
Only same-device, full-root, same-target mirrors in the registered propagation
group are accepted for a normal host unmount. No foreign namespace is entered;
surviving references still prevent mapping removal. Global propagation is not
changed. Docker cannot consume the tested proc-root private-namespace alias.

This is deliberately NOT full automatic crash recovery acceptance. A later
qualified reconciler must distinguish applied versus unapplied thin messages
with trustworthy inactive/held metadata evidence before resuming. User-space
model tests verify refusal and record durability, not real power-failure safety.
Pool exhaustion, corrupt metadata and power loss belong only in an isolated VM.
Until those tests and deterministic reconciliation are complete, T3 remains
NOT_RUN/PARTIAL and performance acceptance must not be promoted to PASS.
