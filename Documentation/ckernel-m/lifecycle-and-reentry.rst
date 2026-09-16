Lifecycle locality and shared-path reentry
=========================================

This table describes implementation boundaries, not blanket performance
acceptance. M2 remains an independent, default-disabled performance prototype.
All domain switches remain default disabled. A normal application syscall
must retain native permission, sharing, accounting and failure semantics.
Only explicit enrollment has the new ABI's resource/admission errors.

Ownership is not execution placement
-----------------------------------

Core instance handles/tasks/mm/object loans pin the instance independently.
Revoke stops eligibility; final release follows the last reference rather than
the last visible business process. CPU and NUMA placement choose where work
runs; they do not identify a transferred file/socket's owner. Asynchronous
release uses recorded ownership. Core control permission requires the initial
user namespace's administrator capability, not knowledge of a cookie.

Independent containers still share one address space, native allocators,
cgroups/ancestors, policy infrastructure, RCU and workqueues. This is not
Multikernel fault isolation. Semantically shared files, files_structs, sockets,
pipes and security/ancestor-limit updates remain shared. Hardware contention
requires separate evidence and cannot explain an unexplained regression by
default.

Lifecycle coverage
------------------

.. list-table:: Local state and remaining coordination
   :header-rows: 1
   :widths: 15 40 45

   * - Stage
     - Local or recorded state
     - Shared/native remainder
   * - Core creation
     - Explicit instance, feature selection, accounted management and placement
     - Cold instance-count/cookie atomics, allocator, cgroup/objcg references
   * - File preparation (M3-A)
     - Explicitly authorized private tmpfs contents, native memory charges
     - Copy/init/mount cost; no automatic privatization of shared writable data
   * - File use (M3-B/C)
     - Up to 16 terminal dentry loans on a registered read-only tmpfs
     - Native traversal, search/LSM/getattr, mount refs, independent struct file
   * - Security use (M4)
     - Eight immutable label roots, recorded file loan owners, self qualification
     - Native policy/deny/audit, stale-label refresh, subject merge, other LSMs
   * - FD use (M5)
     - Up to 64 legally charged idle credits, local consume/return trylock
     - file_lock stays process-shared; exact counter owner and ancestors native
   * - Socket use (M6)
     - 64 recorded original owners, local send/receive qualification lookup
     - Mediated rules/transfer fallback; native protocol, queues and packet memory
   * - Invalidation
     - Stop new local loans, preserve existing references and in-flight semantics
     - Mount pins, newest-label protocol, limit update freeze, native policy/RCU
   * - Return/reclaim
     - Recorded owner, accounting conservation and bounded inventories
     - Final dput/label put, ancestor uncharge, SLUB, RCU and shared Core workers

Shared reentry audit
-------------------

The listed code identifiers are the audit entry points. A bounded loop or pool
does not establish a time bound; native hierarchy depth, contention, scheduling
and grace periods can extend waits.

.. list-table:: Trigger -> context -> shared object -> wait -> affected scope
   :header-rows: 1
   :widths: 17 14 24 22 23

   * - Trigger / evidence
     - Context
     - Shared object
     - Wait or coordination
     - Scope / limit
   * - ckm_create_instance, domain init
     - Management task
     - SLUB/percpu allocators, memcg, native references
     - GFP_KERNEL_ACCOUNT may allocate, reclaim or sleep
     - Other allocator/memory users; Core caps 256 live instances, not time
   * - ckm_revoke_work / ckm_release_work
     - System worker
     - Shared workqueue, cgroups and domain backend teardown
     - Queue delay, native release and RCU waits
     - Workers and memory users; explicit background attribution still needed
   * - VFS cold pin install/remove, kill callback
     - Enrollment, remount, unmount, Core worker
     - fs_pin global pin_lock, s_umount, dentry/RCU backend
     - Short pin update, pin-kill completion, final dput outside local rwsem
     - Same mount and backend users; never cache 16 entries as a time guarantee
   * - VFS loan miss/contention or ordinary traversal
     - Business task
     - Native lookup, mount ref and d_lockref
     - down_read_trylock miss falls back; native path may contend
     - Real shared path/object users; retained tmpfs data separately bounded
   * - M4 label learn/replace/use across subjects
     - Business task
     - Native label refs/set, file context lock, policy and audit
     - Local trylock fallback, reference updates, native merge and RCU
     - Same policy/object users; 8 roots do not bound retained policy bytes
   * - M4 policy replacement/revoke/file close
     - Administrator, task or worker
     - Native newest-label protocol, recorded token registry, RCU/workqueue
     - Native updates and recorded reference release; cold registry mutex only
     - Policy-dependent subjects and backend workers; no audit isolation
   * - M5 empty local inventory/refill
     - FD allocating task
     - control_lock and ancestor page_counter
     - Spin coordination, up to 64-credit legal charge or exact native retry
     - Other refills/control operations, possibly while holding native file_lock
   * - M5 true or reservation-induced exact allocation failure
     - Any allocating task, including nonparticipant
     - control_lock, registered pools and ancestors
     - Freeze/drain idle reserves and retry exact while refills excluded
     - Up to 256 live-instance pools; preserves elasticity, not bounded latency
   * - M5 usage read, limit update, cgroup migration, admin disable
     - Reader, administrator or moving task
     - Same shared control path and counters
     - Drain idle reserves; release spinlock/IRQ across sleeping set_max
     - Can force later refills in otherwise independent instances
   * - M5 revoke/full inventory/cross-owner close
     - Worker or original native FD context
     - Original css, ancestor counters, eventual Core work
     - Uncharge, remove registry, css release; no no-account shortcut
     - Ancestor-sharing users and backend work; live descriptors stay native
   * - M6 clone/free without current owner
     - Native clone, softirq or final free context
     - RCU instance registry and original owner's local buckets/lock
     - Read-only scan up to 256 instances; free takes owner local spinlock
     - Includes nonparticipating socket close; explicitly measured separately
   * - M6 record retirement and final state release
     - RCU callback then Core worker
     - Native RCU, credentials/labels, registry mutex and allocator
     - Grace period, root release, synchronize_rcu outside local lock
     - Shared callback/work queues; 64 records are not a latency guarantee
   * - Maple empty/full/mismatch/migration (M2, paused)
     - Allocating task or recorded retirement context
     - Native SLUB, cpuset/mempolicy, objcg and RCU
     - Preserve original flags/policy/charge, native fallback and final release
     - M2's own reentry report and unaccepted performance results remain valid

Exhaustion and next stages
-------------------------

The compatibility path keeps native elasticity: optional VFS/security/socket
inventory misses fall back; Maple allocation goes native; FD reservations are
reclaimed before a final resource rejection. A strong-budget mode with fixed
precharged resources, admission, different failure behavior or restricted
elasticity is NOT implicitly enabled by these prototypes. Such a mode needs
separate review of the application contract and all ancestor limits.

Future work may address ownerless socket lookup cost, policy/reference update
frequency, instance-attributable bounded refill/reclaim queues and remaining
allocator access. Changes to generic object layout, protocol state, permission
semantics, quota elasticity, or shared-object behavior require separate design
approval. Do not start them merely because four hook groups exist.

Acceptance must retain target and bystander observations for cold start, steady
reuse, exhaustion, migration, invalidation, pressure and batch exit. Foreground
CPU, matched-kthread CPU and total CPU ticks overlap and are not additive.
Snapshots after a fixed delay do not prove complete reclamation. KVM evidence
does not establish bare-metal NUMA isolation. See each stage's validation file
for completed measurements and explicit gaps.
