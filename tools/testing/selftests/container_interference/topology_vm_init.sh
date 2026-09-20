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
echo '+cpu +memory +pids +cpuset' > /sys/fs/cgroup/cgroup.subtree_control
echo 1 > /proc/sys/kernel/sched_schedstats
touch /cis-disposable-vm
/usr/bin/python3 /profile/topology_vm.py
status=$?
if test "$status" = 0; then
    /usr/bin/python3 /profile/joint_vm.py --group topology
    status=$?
fi
echo "CIS_PROFILE_VM_EXIT=$status"
# Derived explanations are reproducible from the raw records and source hash.
# Avoid serializing multiple copies of every raw fact in this small VM.
find /tmp/topology-evidence /tmp/joint-evidence -type f ! -name '*-explanation.json' | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
sync
poweroff -f
