#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
export PATH=/bin:/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /sys/kernel/tracing /sys/kernel/debug /run
mount -t cgroup2 none /sys/fs/cgroup
mount -t tracefs none /sys/kernel/tracing
mount -t debugfs none /sys/kernel/debug
echo '+cpu +memory +pids +cpuset +io' > /sys/fs/cgroup/cgroup.subtree_control
echo 1 > /proc/sys/kernel/sched_schedstats
touch /cis-disposable-vm
mode=$(cat /profile/block-fixture-mode)
case "$mode" in requeue) number=1;; partial) number=2;; merge) number=3;; merge-scheduler) number=4;; *) poweroff -f; exit 90;; esac
if ! insmod /cis_block_fixture.ko disposable_vm=1 test_mode="$number"; then
    echo CIS_PROFILE_VM_EXIT=91
    poweroff -f
    exit 91
fi
/usr/bin/python3 /profile/block_vm.py --fixture "$mode"
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/block-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
rmmod cis_block_fixture
echo "CIS_BLOCK_DEVICE_UNLOAD=$?"
sync
poweroff -f
