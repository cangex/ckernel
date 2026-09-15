.. SPDX-License-Identifier: GPL-2.0

=====================
Instance core contract
=====================

M1 provides a host-authorized, fd-owned instance context. It does not
change syscall permission decisions, FD limits, files or sockets. Without
a later allocator feature, all operations use native resource handling.

CREATE on /dev/ckernel-m validates the UAPI version, exact size, reserved
fields and budgets, then returns a CLOEXEC instance fd. Host-initial
user-namespace CAP_SYS_ADMIN is required for all ioctls. BIND and REVOKE
must be called as ioctl(fd, command, 0UL), with an explicit zero argument.
Cookies are observable identities, never standalone authorization.

The launcher holds the instance fd in a supervisor, forks a child, binds
that child, then execs its program. A single handle closed by exec would
prematurely revoke the instance. A task cannot hot-rebind; shared mm/files
and multithreaded binders are rejected. The cgroup and allowed CPU range
are captured at CREATE. Cross-cgroup binding is rejected rather than
silently associating a different resource owner.

Successful task duplication inherits one reference. free_task releases
that reference once, including later fork failure unwind. Successful new
mm initialization provides the hook for allocator ownership; __mmput
releases it after exit_mmap, not at lazy-TLB-delayed __mmdrop. Node-owned
references, when implemented, survive independently through RCU callbacks.

ACTIVE -> REVOKING -> DRAINING -> DEAD is monotonic. Last task release or
last control-handle release starts revoke. No new optimization borrowing
is allowed thereafter. Ordinary syscalls are not cancelled. Work, mm and
allocator references delay final release; asynchronous does not mean free
of latency or shared-path costs. No dynamic module unload is supported.

The Maple feature bit is reserved in the M1 ABI but unsupported until its
separate implementation/config option is present. Other domain features
and the old CKernel protocol are deliberately absent.
