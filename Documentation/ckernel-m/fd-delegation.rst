Bounded FD credits on the legacy files controller
================================================

This default-off prototype has isolated ARM64 correctness evidence. It is not
an accepted general isolation mechanism; see fd-validation.rst for build,
runtime and performance status separately.
CONFIG_CKERNEL_M_FD and CKM_FEATURE_FD are independent of Maple and security.
It supports one explicit instance per non-root legacy files cgroup. The misc
FD backend and an administrator-disabled legacy controller are unsupported.
Enrollment errors do not change ordinary Linux FD allocation semantics.

Ownership and conservation
--------------------------

The accounting owner remains files_struct->files_cgroup, not the closing
task. No fields are added to files_struct or files_cgroup. An enrolled task
can use its instance pool only if that pool's exact native counter matches
the files_struct counter and the default-cgroup/lifecycle checks pass. A
cross-owner close uncharges natively. Shared files_struct/file_lock semantics
remain unchanged. Fork bulk charges and failed allocations keep native
rollback rules.

Native page_counter usage is U + R: native charged FD slots plus idle credits.
U includes slots temporarily reserved by alloc_fd before a successful open or
FD install; native failure rollback returns those slots. It is not solely a
count of fully installed file objects at every intermediate instruction.
At most 64 credits are idle in one pool. A successful native batch charge
legally reserves them through ALL ancestor limits. Consuming an idle credit
moves R to U; returning a live credit moves U to R. A full pool performs the
ordinary native uncharge. Unlimited groups are still charged and reported.
New state and per-CPU statistics use GFP_KERNEL_ACCOUNT. Idle credits are
not real descriptors or extra open files. Native file objects and memory
charges remain separate and unchanged.

Pools hold their original css until destruction. Tasks pin the instance.
After revocation, the pool stops, releases R and leaves the cold registry;
remaining live descriptors continue to hold their native files/cgroup
ownership and are uncharged by native close. No asynchronous release guesses
the owner from current. No additional pool RCU grace period is needed: the
hot path is reached through a task-held instance and registry readers hold
the cold control lock. Final state destruction happens after task references.

Preventing false resource failures
---------------------------------

Optional batch allocation failure is never a final rejection. Exact native
allocation is attempted. ALL failed native allocations, including requests
by unbound sibling groups, freeze/drain idle credits from every registered
pool and retry exact n. The retry runs while refills are excluded. Concurrent
genuine live usage can still exhaust the limit as in the original controller.
Successful unbound operations do not acquire the registry lock.

files.usage and group migration also freeze/drain R before observing or
moving native live usage. Limit changes retain a nested freeze across the
original page_counter_set_max call. That function can cond_resched, so the
control spinlock and disabled interrupts MUST be released during the call.
Other exact native operations can proceed; refills and pool registration
respect the freeze until its last holder completes. The native limit-write
behavior, including ignoring page_counter_set_max's error, is not repaired
incidentally. Concurrent native snapshot/update limitations remain native.

The preexisting irreversible no_acct control first drains/stops these pools.
It is never used as an optimization or counted as successful M5 validation.
Existing native races/semantics of that administrator knob are not broadened
into an application permission or accounting bypass.
Registration rechecks an irreversible disable flag under the coordination
lock, closing the gap between initial eligibility and registry publication.

Coordination costs and remaining tests
--------------------------------------

Local successful operations take only an instance pool trylock. On contention
they use native charging. Empty pools, failed exact allocations, statistics
reads, limits, migration, registration and retirement enter explicit shared
coordination. Lock order is files->file_lock, control_lock, pool->lock; control
code never acquires file_lock. Only non-sleeping page-counter operations are
performed while these spinlocks are held. Statistics/limit operations can
drain other instances' idle credits and cause their later refill work.

The registry is bounded by Core's 256 live instances, but neither hierarchy
walk time nor wait time is proven bounded. Failure rescue may wait under
file_lock. Refill and drain still update shared ancestors. Final Core work
still uses system workqueues. These are explicit residual interference,
not a claim of independent-kernel isolation or of a new file_lock algorithm.

The sequential model's conservation/false-failure counterexample is only a
design check. Kernel tests cover sibling reserves, real limit
failure, limit updates, truthful usage, fork/shared files, rollback, migration,
cross-instance use, fault injection and exit under KASAN/lockdep. Performance
must separately measure target/bystander tails, foreground/background CPU,
memory, refill/rescue/drain counts and equal-arrival-rate behavior. Correctness
test success does not demonstrate complete background attribution or bounded
control-path wait time.
