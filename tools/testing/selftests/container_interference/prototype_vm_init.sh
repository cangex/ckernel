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
insmod /cis_fixture.ko isolated_vm=1
cp -a /dev/cis-fixture /container-root/cis-fixture
if test -f /profile/costs-mode; then
    /usr/bin/python3 /profile/prototype_vm.py --costs
elif test -f /profile/bridge-mode; then
    /usr/bin/python3 /profile/prototype_vm.py --bridge
elif test -f /profile/specialists-mode; then
    /usr/bin/python3 /profile/prototype_vm.py --specialists
else
    /usr/bin/python3 /profile/prototype_vm.py
fi
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/prototype-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
sync
poweroff -f
