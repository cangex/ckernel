Native TCP failure and recovery evidence, 2026-09-20
==================================================

Scope and immutable inputs
--------------------------

Both cohorts ran in separate disposable ARM64 KVM guests on host 14. Host
kernel and boot ID stayed unchanged. They are not production throughput or
NUMA acceptance. Source for the new kernel and tools was
``5c2bf8603b60c963d6a56cb0123a9403c9d87e69``. Image SHA256 is
``f33288dea75f1f3dac43a9605dd2350ff083485aa725fa77fe4d58863ebbe969``;
configuration SHA256 is
``40c51dd99fd375ceeadf5db1cc8f78cd7cff2be15d65f750351118d08d49924d``.
The separate fault build completed Image and all modules; the final source
revision rebuilt Image and the unchanged fixture module. Required fault
capabilities were added only to this guest configuration.

Remote evidence is under
``/dev/shm/cis-x-20260919/evidence/net-tx-process-5c2bf8603-20260920``.
The native failslab cohort serial is
``txfailure/x4-net-txfailure-20260920-070443.log`` with SHA256
``e4ed6dd101c3807e9b8c0b88304bb9dcc756cec112ea45a7efe9856984640348``.
The memory-admission cohort serial is
``txadmission/x4-net-txadmission-20260920-070520.log`` with SHA256
``d0f4981cb066c092a1672eae9291f097c02019ee2382237bda92773cc1fa5605``.
Both full raw serials independently replayed through ``net_vm_check.py``
with PASS, twelve fixed OFF/NET states and six captures each.

Observed results
----------------

The failslab cohort matched all 96 eligible send-allocation episodes in its
six NET windows. Thirty-six were actual native allocation failures with no
invented skb/release; sixty were unmarked successful sends with verified
payload receipt and observed original-header release. Same-socket recovery
and an unmarked private-socket bystander were both tested, three rounds each.

The admission cohort matched all 288 eligible episodes. Each of the six
pressure actors had thirteen actual memory-admission rejections and eight
successful same-socket recovery sends after restored-budget acknowledgement.
The three normal-budget controls had no failed sends or rejections. Rejected
headers were released before the rejection terminal. This is TCP_REPAIR
queue acceptance, not wire delivery. The 4MiB management seed and zero TCP
budget are explicit VM-only pressure, not a measured interfering container.

Neither cohort produced a fabricated Socket-holder or allocator-blocker
relationship. Source counters were quiet in OFF and all programs and maps
were removed after capture. Native control values were restored exactly;
both fixture unloads and guest exits were zero. No source-recursion gap,
ring loss, rejected event or kernel warning was accepted.

Maximum worker armed-capture process CPU was 1,240,330ns for failslab and
1,450,180ns for admission, below the unchanged 40ms capture guard. Maximum
whole-worker CPU was respectively 93,571,460ns and 111,996,810ns; peak RSS
was 19,668KiB and 19,664KiB. These are not total observer costs: callback,
source, management, background CPU and shared kernel memory require separate
accounting. No throughput/P99 production claim follows from these fixtures.

One admission capture recorded 49 TX source beginnings: 48 admitted
process-context episodes and one explicitly filtered IRQ-only beginning.
All other captures had no such filtered beginning. True nested trace count
was zero throughout. IRQ-only allocation attribution is unsupported, not
silently assigned to the interrupted task.

Failures retained and remaining scope
------------------------------------

Earlier cd8e9ee42 setup failed because the old guest lacked failslab.
The e66c85177 fault setup then exposed a merged fclone cache; the admitted
pressure run was rejected for an undifferentiated recursion counter.
Diagnostic-only 2872e338b separated that count into one IRQ-only beginning
and zero true recursion; its failure checker also raised a real schema
KeyError. All old failures remain failures. The final run uses explicit
process-only admission plus separately counted IRQ exclusions, unchanged
true-recursion rejection, a narrowly unmerged native fault cache, and
checkers tested against the actual report parser.

Receive/clone/GSO/GRO origins, complete final data-buffer release, production
memory-pressure incidence and allocator lock holders remain unproven here.
These cohorts add two bounded failure paths to X4/X7, not full X7 completion.
