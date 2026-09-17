#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
export PATH=/bin:/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /run
mount -t cgroup2 none /sys/fs/cgroup
echo '+cpu +memory +pids +cpuset' > /sys/fs/cgroup/cgroup.subtree_control
touch /cis-disposable-vm
/usr/bin/python3 /profile/idle_cost_vm.py
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
for f in /tmp/idle-cost-evidence/* /tmp/idle-cost-evidence/records/periodic/state.json; do
    [ -f "$f" ] || continue
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
sync
poweroff -f
