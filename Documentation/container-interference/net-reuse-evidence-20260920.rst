Native Socket address reuse evidence
====================================

Tools ``22c9c682bd9d7209546096e122dcba20431aaa0f`` and the unchanged
``55795f96b`` Image completed the predeclared six-state OFF/NET matrix in
one isolated ARM64 VM.  All 655 Python tests, 21 ownership tests and seven
profile tests passed on ARM64.  The native workload built with -Werror;
no kernel or fixture algorithm changed.  No retry or allocator manipulation
was used to manufacture reuse.

Each of the two container actors created/closed eight private TCP sockets
per state.  Each actor actually reused the same native address seven times,
with distinct SO_COOKIE values, so all six states exercised fourteen
independent close-before-create boundaries.  The three captured states
matched all 48 newly created Socket identities and their exact independent
creation/usage actors.  No false wait or old-holder relationship was accepted.
OFF states had no active CIS source.  Raw replay by net_vm_check.py passed;
source detachment, fixture unload and absence of kernel warnings passed.

Peak combined-process CAPTURING CPU was 9.516150 ms; whole-stage process
CPU peaked at 108.657760 ms and combined RSS at 34107392 bytes.  The 40 ms
guard is unchanged.  These are not complete source/background costs or
production performance acceptance.

Remote serial below ``/dev/shm/cis-x-20260919/evidence``:
``net-reuse-22c9c682b-20260920/x4-net-reuse/x4-net-reuse-20260920-105800.log``.
SHA256 ``28321f7f36715397bfff0c1f6557399485dc6b9245804bc9ac365910bf342ac7``.
The host remained ``6.6.0-ckernel-rmaster-20260904+``, boot ID
``20bf4ee1-355a-4c77-a494-0c265b05c8d5``.  Final root free space was
4378996736 bytes, above the preserved 4 GiB floor.  No VM was left running.

This is a bounded native TCP identity negative, not a positive contention
recall test, general protocol coverage or an skb-payload ownership proof.
