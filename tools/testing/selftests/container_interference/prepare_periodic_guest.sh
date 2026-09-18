#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Prepare a NEW guest from the verified P1 guest; does not start a VM.
set -euo pipefail
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    printf 'usage: bash %s SOURCE VMLINUX_BTF P1_GUEST OUTPUT_PARENT [P1_RECEIPT]\n' "$0" >&2
    exit 2
fi
test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
source=$(realpath "$1")
btf=$(realpath "$2")
base=$(realpath "$3")
parent=$(realpath "$4")
test -f "$base/usr/bin/python3"
# session_launch enters this rootfs before executing /workload.
test -f "$base/container-root/workload"
test ! -e "$base/profile/p1-admission.json"
test "$(df -PB1 / | awk 'NR==2 {print $4}')" -gt 4294967296
test "$(df -PB1 "$parent" | awk 'NR==2 {print $4}')" -gt 4294967296
make -C "$source/tools/container_interference" VMLINUX_BTF="$btf"
make -C "$source/tools/container_interference" check-python
make -C "$source/tools/testing/selftests/container_interference" LDFLAGS=-static
dest=$(mktemp -d "$parent/p2-guest.XXXXXXXX")
mkdir "$dest/root"
cp -a "$base/." "$dest/root/"
mkdir -p "$dest/root/profile"
cp "$source/tools/container_interference/"*.py "$dest/root/profile/"
cp "$source/tools/container_interference/"{session-worker,session-residue} "$dest/root/profile/"
cp "$source/tools/container_interference/bpf/cis.bpf.o" "$dest/root/profile/"
cp "$source/tools/container_interference/bpf/"{ip,owner,sched,reclaim,sync,fd,counter,allocator,net}.bpf.o "$dest/root/profile/"
cp "$source/tools/testing/selftests/container_interference/periodic_vm.py" "$dest/root/profile/"
cp "$source/tools/testing/selftests/container_interference/periodic_vm_init.sh" "$dest/root/init"
cp "$source/tools/testing/selftests/container_interference/session_launch" "$dest/root/"
cp "$source/tools/testing/selftests/container_interference/workload" "$dest/root/container-root/"
cp "$source/tools/testing/selftests/container_interference/sync_workload" "$dest/root/container-root/"
cp "$source/tools/testing/selftests/container_interference/fd_workload" "$dest/root/container-root/"
cp "$source/tools/testing/selftests/container_interference/fd_cross_workload" "$dest/root/"
cp "$source/tools/testing/selftests/container_interference/storage_vm.py" "$dest/root/profile/"
cp "$source/tools/testing/selftests/container_interference/identity_vm.py" "$dest/root/profile/"
chmod 755 "$dest/root/init"
if [ "$#" -eq 5 ]; then
    test ! -e "$dest/root/profile/p1-admission.json"
    install -m 600 "$5" "$dest/root/profile/p1-admission.json"
fi
(
    cd "$dest/root"
    find . -print0 | cpio --null -o -H newc > "$dest/p2.cpio"
)
sha256sum "$dest/p2.cpio"
printf 'P2_GUEST=%s\n' "$dest"
