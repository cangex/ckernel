# W2 draft: best-effort hit promotion

Status: isolated experiment, not accepted for deployment. Baseline diagnosis
bound the actual cache_lock and observed contention across business copies.
No authorization shortcut is introduced. Formal Go net benefit was not established.

Fixed OLK sidtab.c:558 put holds cache_lock with IRQs saved for LRU update or
miss insertion; :603 get copies a cached string under RCU and then calls put.
services.c:1267 entry_to_string handles ENOENT with the existing conversion path.
security_sid_to_context_core retains the policy RCU reference across both lookup
and promotion. No caller contract or returned context is changed.

The draft changes only post-copy successful-hit promotion: try the same cache
lock once; if busy, omit LRU refresh. If acquired, reload entry->cache under that
lock; promote only a still-present entry. A hit evicted before promotion is not
reinserted from the copied output. Cold insertion, eviction, slot limit, invalid
contexts, allocation failures and policy teardown retain the original paths.

Safety rationale: output was copied under RCU before optional maintenance.
No old cache pointer is carried across RCU unlock. The caller's outer policy RCU
section keeps the SID table and entry alive. Every list mutation still uses the
original lock. No new state, memory budget, background worker or permission
decision is introduced. Cache-disabled compilation must remain supported.

Costs/risks: each hit still attempts an atomic lock operation; stale recency can
cause more evictions/conversions and cold-path contention. This is not a claim
of read-only hits or eliminated shared cacheline traffic. Accept only if real
Go work improves without shifting cost to solo, neighbors or memory/CPU.

Tests before acceptance: source/call-site audit, full ARM64 builds, exact context
output under repeated hits and cache churn, concurrent eviction, policy reload,
invalid context/denied access preservation, allocation-failure behavior where
supported, and unchanged official business checks. Unperformed cases must remain
explicit gaps; local source tests alone do not establish kernel correctness.

Completed: matched full ARM64 build; 16-thread context hit/churn/unchanged-policy
reload and native invalid-context roundtrip checks on both variants; all 130
formal Go copy checks. Five paired formal blocks: loaded mean -1.43718%, paired
95% interval [-3.14706%, +0.29436%], below the frozen 3% improvement requirement.
Interference 521.71761% -> 528.52608% uses each variant's own solo, not a cycles
ratio. No W2 paired cache-lock reduction is claimed. Allocation fault injection,
cache-disabled builds and KASAN/lockdep remain open; broad approval is not inferred.
