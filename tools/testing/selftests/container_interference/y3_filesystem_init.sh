#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
export PATH=/bin:/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /sys/kernel/tracing /sys/kernel/debug /run /fs0 /fs1
mount -t cgroup2 none /sys/fs/cgroup
mount -t tracefs none /sys/kernel/tracing
mount -t debugfs none /sys/kernel/debug
echo '+cpu +memory +pids +cpuset +io' > /sys/fs/cgroup/cgroup.subtree_control
echo 1 > /proc/sys/kernel/sched_schedstats
touch /cis-disposable-vm
for module in virtio_blk mbcache jbd2 ext4; do
    if ! insmod /$module.ko; then
        echo CIS_PROFILE_VM_EXIT=91
        poweroff -f
        exit 91
    fi
done
if ! mount -t ext4 /dev/vda /fs0 || ! mount -t ext4 /dev/vdb /fs1; then
    echo CIS_PROFILE_VM_EXIT=92
    poweroff -f
    exit 92
fi
/usr/bin/python3 /profile/y3_filesystem_vm.py
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/y3-filesystem-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
umount /fs0 && umount /fs1 && rmmod ext4 && rmmod jbd2 && rmmod mbcache && rmmod virtio_blk
echo "CIS_FILESYSTEM_UNLOAD=$?"
sync
poweroff -f
