#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# This file is an initramfs /init, never a host launcher.
set -eu
test "$$" -eq 1
export PATH=/bin:/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /sys/kernel/tracing /sys/kernel/debug /run
mount -t cgroup2 none /sys/fs/cgroup
mount -t tracefs none /sys/kernel/tracing
mount -t debugfs none /sys/kernel/debug
echo '+cpu +memory +pids +cpuset' > /sys/fs/cgroup/cgroup.subtree_control
touch /cis-disposable-vm
status=0
if [ -f /profile/p1-admission.json ]; then
    /usr/bin/python3 /profile/periodic_vm.py --p1-acceptance /profile/p1-admission.json || status=$?
else
    /usr/bin/python3 /profile/periodic_vm.py || status=$?
fi
echo "CIS_PERIODIC_VM_EXIT=$status"
for file in /tmp/periodic-evidence-*/result.json /tmp/periodic-evidence-*/controller.log; do
    [ -f "$file" ] || continue
    echo "CIS_PERIODIC_FILE $file"
    cat "$file"
done
sync
poweroff -f
