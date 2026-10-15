# Task filesystem branches (experimental)

This is a user-space composition of native dm-thin and ext4, not a new
filesystem or kernel hot-path change. Only immutable templates and the pool
can outlive tasks. Each new request allocates a monotonically new thin ID,
random branch identity, mapping generation and independently mounted ext4.
Deleted request IDs cannot be recycled into new tasks.

Status: experimental control implementation, normal and container integration,
and an event-acknowledged Go correctness-admission adapter. See the verification
record for executed revisions. Crash/pool-exhaustion VM acceptance and formal
performance/net-benefit acceptance are NOT_RUN. Recovery can reconcile an
unmounted, fully unreferenced registered branch after filesystem checks; it
quarantines ambiguous thin metadata operations rather than replaying them.
This limitation still blocks complete T3 recovery acceptance and T5 promotion.

## Safety

The CLI accepts a new private control directory, never a physical disk or
existing LV. Files are exclusively created and actually preallocated. Their
inode/device identities, loop backing, DM UUID/table/generation and mount
identity are checked. A single local control lock serializes lifecycle
requests; no per-file/syscall RPC is introduced. All control and waiting costs
must remain in lifecycle measurements.

Normal unmount synchronizes writes. There is no force/lazy unmount, disabling
SELinux, skipped flush or global cache drop. Discard is not passed through to
the host filesystem. Thin deletion can reclaim pool mappings but does not
release the pool's reserved backing capacity. Final explicit pool destruction
checks inactive metadata and removes only registered files.

## Tests

`make test` runs unprivileged identity, budget, intent and lifecycle-model tests.
Models are not filesystem concurrency/crash proofs. The explicit native test is
`PYTHONPATH=tools/ckernel_taskfs python3 tools/testing/selftests/ckernel_taskfs/integration_owned.py NEW_ABSOLUTE_DIRECTORY --execute-owned-files`.
It creates a 4GiB data file and 64MiB metadata file, refuses active containers,
and retains the owned state on failure. Do not use this on a host without the
explicit authorization and capacity checks described in the project protocol.

`taskfsctl.py inspect ROOT` is local/read-only. Other commands use the real
Linux backend and require root. `gc` defaults to inspect-only;
`gc ROOT --destroy-owned-pool` additionally requires all task branches DELETED.

The manifest records identities and intended effects, but JSON and DM metadata
are separate transactions. A surviving intent is not evidence that a kernel
operation happened or did not happen. No exactly-once guarantee is claimed.
