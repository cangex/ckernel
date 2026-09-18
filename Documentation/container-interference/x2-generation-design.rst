X2 native counter generation and source audit
============================================

Development design, runtime validation recorded separately. The prototype
objective remains X7; this extension does not certify allocator/network/I/O.

Object identity
---------------

The fixed OLK page_counter users (memcg, hugetlb cgroup and legacy files
cgroup) initialize counters with page_counter_init before publication.
CONFIG_CIS_OBSERVE_COUNTER adds one u64 in the read-mostly part of the
counter, assigned during that initialization. A boot-global sequence is
used only on initialization, not on charge/uncharge or every event.
Saturation at S64_MAX assigns zero forever rather than reusing a cookie.
Generation zero, old protocol or uninitialized external users stay UNKNOWN.

The key is (boot, counter address, initialization generation). The caller's
native object-lifetime guarantee protects reading the field during a native
counter operation. An initializer is not allowed to race an in-flight use.
This does not track final destruction time, extend object lifetime, prove
all updates were observed or provide a lock owner. Within one boot, two
observed updates with the same nonzero key prove that they accessed the
same initialized counter. They do not prove simultaneous access, cache-line
contention or causality. No E2 edge may be built across different generations.

This avoids an observer owner-index lookup/lock on every update and supports
objects created before probe attachment. The cost is one u64 payload per
counter (aligned structure/embedding size must be measured), one global
atomic sequence operation per initialization, and three read-mostly field
reads per emitted step. No extra reference or reclamation path is installed.
Configuration off removes the field and initializer call. Binary KABI
compatibility with the original distribution is not claimed for this
experimental kernel; out-of-tree modules must be rebuilt.

Protocol and audit
------------------

Counter record protocol 2 carries leaf/object/parent generations. Readers
retain protocol 1 support without retroactively upgrading old evidence.
Generation changes within one native operation are rejected. Parent and
leaf identities are checked against independent ioctl truth in the VM.

The root-only cis_counter_audit debugfs file reports per-CPU source entries,
eligible calls, selected calls, trace steps and capped steps. Entries include
unsupported IRQ/recursive calls before rejection. These are source totals,
not target-only BPF totals. Snapshots are non-atomic; a stopped tracepoint
does not prove every previously started operation has finished. Deltas
bracket a controlled session, do not measure CPU time, and do not replace
terminal BPF loss or recursion checks. Five unsigned longs per possible
CPU and the sequence word are added; all original recursion/gate state also
remains part of observer memory.

Address reuse test
------------------

The dedicated root-only counter fixture can reinitialize a fixed slot at
the same addresses. A fixture-only rwsem excludes operations during reset;
normal runs take a shared read side and remain concurrent. Reset refuses
outstanding usage and returns before/after generations independently of
the trace stream. The test runs one container before reset and the other
after, requiring no cross-generation shared-object edge. This lock is test
coordination, not a new production page_counter lock.
