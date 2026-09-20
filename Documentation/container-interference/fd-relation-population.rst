Independent FD overlap-relation population
=========================================

Frozen oracle, before the new relation cohort
-------------------------------------------

The relation measured by the FD adapter is an acquisition-attempt wall
interval overlapping an observed inner ownership interval. It is deliberately
not pure spinning, a causal blocking duration or a counterfactual throughput
loss. Independent truth can enumerate this same conservative relationship
without using captured events to select the denominator.

For every successful fixture call wholly inside the capture window, take its
outer attempt interval [begin, acquired). For every other-task call on the
same files_struct and lock, take its inner hold [acquired, release_begin).
Every positive overlap is an eligible ordered pair. Do not threshold by
duration, use prefix reach, or exclude unobserved calls. Reuse lifetimes are
separated by non-overlapping independent call brackets and verified retirement.

The fixed maximum is 256 calls and 4096 audited output relations. Enumerate
truth pairs first; every measured edge must match one unique pair by task,
cgroup, object and time. Duplicate edges cannot increase coverage. Private
objects with zero pairs are valid negatives with ratio null, not 100 percent.
The native syscall case has no complete independent oracle: ratio remains
UNAVAILABLE_NATIVE. Any omitted audit output rejects the correctness result.

The predeclared overlap capture threshold is 90 percent, as in the original
X7 selected-closable-relation requirement. ``true_blocking_recall`` remains
null: the outer attempt includes possible pre-lock scheduling and observer
overhead. Meeting this threshold only supports this explicitly named E2
overlap relation. No stronger causal or spin-time interpretation is permitted.

The next new cohort repeats unchanged basic threads/private/native and
lifecycle cross/reuse, three rounds, 16 calls per thread. Its plan embeds
``cis-fd-relation-population-v1`` before any capture. Earlier raw records may
be replayed retrospectively, including ratios below 90 percent, but do not
become predeclared acceptance and must not have their historical status erased.
The default 128-item summary stays bounded; fixture verification examines
all relations up to the separate 4096 audit ceiling and fails above it.

New predeclared cohort result
-----------------------------

Producer a0fd55644d065d2337aa9567fb07565b1e6457a3 ran basic and lifecycle in that
fixed order, with 9 and 6 captures respectively. All 659 ARM64 tool tests
passed before execution. Kernel Image remains the same 5c2bf8603 build as the
prefix-128 cohort. The FD BPF object and native fixture module were byte-equal
to that guarded cohort; no kernel or workload change was made.

Each of three rounds independently passed the predeclared 90-percent overlap
capture threshold: shared tables 62/62, explicit cross-container CLONE_FILES
31/31, and retirement/reuse 248/248. Private tables had zero eligible pairs and
zero observed edges, reported VALID_NEGATIVE rather than 100 percent. All
complete fixture calls remained in the denominator and were captured. The
native syscall case is still UNAVAILABLE_NATIVE. No false holder, wrong
container, duplicate relation or cross-lifetime relation passed validation.

The new basic peak CAPTURING process CPU was 11.44101ms; lifecycle peak was
23.43022ms, both below the unchanged 40ms limit. Whole-process CPU through
report peaks were 119.66404ms / 132.15962ms, combined RSS peaks 36,544,512 /
36,499,456 bytes. Full source/background CPU and kernel memory remain unknown.
All objects were absent and the host kernel/boot identity unchanged afterwards.

Raw evidence on host14 is under
``/dev/shm/cis-x-20260919/evidence/fd-relations-a0fd55644-20260920``; the local
copy is ``fd-relations-evidence-20260920`` in the handover directory:

* basic/x1-fd-20260920-084001.log:
  7cfccb2d933e82a47b8ac0b806f4f9af31d11958cc6e82b19267fd75140308c0
* lifecycle/x1-fd-20260920-084048.log:
  303ba28203e48cff9faa666379dd286a089660bafdaf8f74a9e87522bfc4af3e

Legacy prefix-64 replay reports 20/31 cross-container and 142/248 reuse
overlaps, below threshold, explicitly RETROSPECTIVE_REPLAY. It is not erased
or relabelled as successful new acceptance. The new ``fd_relations`` coverage
key refuses call-only, retrospective, zero-positive or below-threshold input.
This closes the selected E2 overlap-population check, not pure spin or causal
blocking recall. Do not repeatedly treat those stronger, unmeasured claims as
already proven by this narrower pass. X7 still requires its remaining explicit
minimum coverage and negative/joint evidence; this receipt alone cannot close it.
