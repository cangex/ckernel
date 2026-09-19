TCP Socket FD transfer evidence, 2026-09-19
==========================================

The dedicated ARM64 KVM used kernel
99d53547065a4fb62a132ed17acaaebbe77ab785 and tools
b286e55eb8138b7dd3b7bc78cfca2a8901cb3a20. Image SHA256 is
af526b4faad7e366cc41cb8b1c3e4d2d5599242394d95c7e8b5f8af9307e31f2.
The host kernel, runtime and other containers were not changed.

Container zero creates a real TCP Socket and passes it through
SCM_RIGHTS over a UNIX seqpacket channel. Container one verifies the
received SO_COOKIE before either using that Socket, or closing it and
creating its own private Socket in the private negative case. Creator,
recipient, used-cookie and native acquisition timings are independently
recorded by the fixture. A bounded native lock_sock fixture creates the
known hold/wait relationship; it is not ordinary application latency.

``net-rights-20260919`` ran two cases, three alternating OFF/ON rounds:
12 states, six captures. Independent replay accepted all states. The
shared case captured all 12 predeclared eligible relationships while
alternating the holder between the two containers. The private case did
not invent cross-container ownership merely because an FD had earlier
been received. Maximum combined-process CAPTURING CPU was 9.08348ms;
maximum combined RSS was 36966400 bytes. These are process measurements,
not complete kernel/observer cost. Tail latency is recorded, not certified.

Raw serial SHA256:
b60e3eb25254af043d8f57a0fd8fa10afd2ac1938d09e966d60c6d15032aa4de.
Reproduce analysis with ``net_vm_check.py`` on the raw
``x4-net-rights-20260919-100708.log`` and a new output directory.

The observer still reports creation owner as UNOBSERVED. The fixture's
knowledge of who created the Socket is not copied into runtime attribution.
This proves only the supported logical-lock relationship across actual FD
transfer, not all TCP locks, skb allocation origin, shared protocol queues,
or a unique cause of application slowdown. X4 and X7 remain incomplete.
