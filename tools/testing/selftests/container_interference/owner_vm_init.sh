#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Dedicated disposable initramfs only; never run on a shared host.
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
failed=0
echo CIS_OWNER_VM_BEGIN
uname -a
for test in logic_test budget_test metrics_test identity; do
    /$test || failed=1
done
if insmod /cis_fixture.ko isolated_vm=1; then
    cp -a /dev/cis-fixture /container-root/cis-fixture
    for scenario in fixture-shared fixture-private fixture-reuse fixture-preempt dentry-shared dentry-private; do
        CIS_TEST_OWNER=1 /fleet 2 ip "$scenario" 3 0 > "/tmp/owner-$scenario.log" 2>&1 || failed=1
    done
    CIS_TEST_FAST_ALERT=1 /fleet 2 ip dentry-auto 3 0 > /tmp/owner-dentry-auto.log 2>&1 || failed=1
    rmmod cis_fixture || failed=1
else
    echo CIS_FIXTURE_LOAD_FAIL
    failed=1
fi
for scenario in cpu-compete quota bench; do
    CIS_TEST_FAST_ALERT=1 /fleet 2 ip "$scenario" 3 0 > "/tmp/fast-$scenario.log" 2>&1 || failed=1
done
for f in /tmp/owner-*.log /tmp/fast-*.log /tmp/observer-*.jsonl; do
    echo "CIS_FILE $f"
    cat "$f"
done
echo "CIS_OWNER_VM_FAILURES=$failed"
sync
poweroff -f
