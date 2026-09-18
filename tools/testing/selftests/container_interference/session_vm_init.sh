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
for test in logic_test budget_test metrics_test; do /$test; done
/usr/bin/python3 /profile/session_vm.py $(cat /profile/test-arguments)
status=$?
if [ "$status" -eq 0 ] && [ -f /profile/storage_vm.py ]; then
    /usr/bin/python3 /profile/storage_vm.py
    status=$?
fi
if [ "$status" -eq 0 ] && [ -f /profile/identity_vm.py ]; then
    /usr/bin/python3 /profile/identity_vm.py
    status=$?
fi
echo "CIS_PROFILE_VM_EXIT=$status"
for f in /tmp/session-evidence/controller.log /tmp/session-evidence/*-*.log /tmp/session-evidence/*-result.json /tmp/session-evidence/identity-requests.jsonl /tmp/session-evidence/records/* /tmp/session-evidence/identity-records/*; do
    [ -f "$f" ] || continue
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
sync
poweroff -f
