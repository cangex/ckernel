#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /sys/kernel/tracing /sys/kernel/debug /run
mkdir -p /var
test -e /var/run || ln -s /run /var/run
mount -t cgroup2 none /sys/fs/cgroup
mount -t tracefs none /sys/kernel/tracing
mount -t debugfs none /sys/kernel/debug
echo '+cpu +memory +pids +cpuset' > /sys/fs/cgroup/cgroup.subtree_control
touch /cis-disposable-vm
if ! insmod /sch_tbf.ko; then
    echo CIS_PROFILE_VM_EXIT=91
    poweroff -f
    exit 91
fi
/usr/bin/python3 /profile/y5_queue_vm.py
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/y5-queue-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
rmmod sch_tbf
echo "CIS_QUEUE_DEVICE_UNLOAD=$?"
sync
poweroff -f
