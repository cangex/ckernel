CKernel filesystem-domain experiment
====================================

This branch contains experimental userspace lifecycle and measurement tools.
It does not change ext4/JBD2 behavior, define a new on-disk format, or claim
that the same-filesystem domain candidate is safe to implement yet.

The comparison keeps the accepted Go installation trace, its official
evaluator, CPU/NUMA slots, image and security settings fixed. Every arm binds
the installation output to an owned loop-ext4 filesystem. One shared
filesystem, two/four groups and one filesystem per container are compared.
All loop files still share a host filesystem and physical device.

Running tests
-------------

From ``tools/ckernel_fs_domains``::

  python3 -m unittest test_fs_domain test_go_fs_matrix test_admission_protocol

The abstract admission-protocol tests are illustrative counterexamples, not
proof of kernel concurrency correctness or crash consistency. The lifecycle
smoke test must run only on the explicitly prepared isolated test host. It
creates new regular-file filesystems; it cannot format a physical device.

Measurement order
-----------------

1. Review source/input hashes, the observation kernel identity, topology,
   storage capacity and task-owned runtime resources.
2. Run lifecycle and official single-copy admission before performance work.
3. Run ``qualify_geometry.py``; reject any unequal actual gross/inode/journal
   budget before starting business. Actual usable space need not be identical
   and is separately reported.
4. Run ``go_fs_matrix.py pilot --tag NEW_UNIQUE_PILOT``. It executes three
   predefined blocks, each with all four arms and solo/24-copy states.
5. Review correctness and measurement coverage; freeze a separate formal
   protocol. The formal entry refuses without that authorization artifact.
6. Run the independent, predefined formal order, then analyze paired results.
   Do not extend the sample count in response to significance.

The paths and identities in these scripts deliberately identify the frozen
development-host experiment. They are not an unattended installer for an
arbitrary host. Reusing elsewhere requires a new reviewed environment freeze.

Lifecycle safety and limitations
-------------------------------

Images have exclusive creation and recorded device/inode/size identity.
Mount UUID, loop backing, namespace mounts and container references are
checked. Normal teardown drains, unmounts, detaches, checks ext4 and removes
only owned images. It never uses forced/lazy unmount or global container
cleanup. Manifests retain failures for explicit recovery.

The manager is a prototype: an abrupt host crash between image allocation
and manifest publication is not a fully transactional cleanup protocol.
The integration test covers orderly failure recovery, not a complete storage
fault-injection campaign. No source-level or VM correctness claim is made for
the unimplemented same-filesystem transaction-domain mechanism.

Performance results are not approval to deploy a new host kernel. Persistent
state, cold setup/drain, usable-space loss and incomplete background ownership
must remain visible alongside the measured installation time.
