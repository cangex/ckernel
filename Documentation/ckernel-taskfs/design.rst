Task filesystem branches
========================

Base: b71a71be141748d31e9dcda1ebe7847ad92a1cc7.  Runtime is the explicitly
identified 6.6 observation kernel, not an unmodified OLK deployment.

Data dependency graph::

    Go /usr/local/go -> task ext4 -> task thin mapping
                                      |
    inactive immutable template ------+--> owned thin-pool
                                               |
                                     owned data/metadata loop files
                                               |
                                      host filesystem / physical disk

Independent ext4 journals do not imply independent thin metadata, host journal,
global VFS, SELinux cache, memory service or physical storage. The control plane
has no role in each file operation. A sealed template has no active writable
mapping; each child has a distinct ext4 UUID for tool compatibility. Branch
identity remains the registered random ID plus generation, never the UUID alone.

Native mechanism references are Documentation/admin-guide/device-mapper/
thin-provisioning.rst and drivers/md/dm-thin.c at the fixed source version.
Official online references, checked during T0:

* https://docs.kernel.org/admin-guide/device-mapper/thin-provisioning.html
* https://www.kernel.org/doc/html/latest/filesystems/journalling.html
* https://www.kernel.org/doc/html/v6.6/filesystems/overlayfs.html

Online descriptions are not runtime-version or correctness certification.
The prototype preserves native zeroing and uses no_discard_passdown and
error_if_no_space. It polls both data and metadata occupancy rather than relying
on a single low-water notification. Logical reservations include each live
branch's full capacity and the template, without speculative CoW savings.
