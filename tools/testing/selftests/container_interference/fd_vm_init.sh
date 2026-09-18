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
if test "$?" != 0; then echo CIS_PROFILE_VM_EXIT=90; poweroff -f; exit 90; fi
# session_launch chroots into an independent root; prepare only its test devices.
if ! (mkdir -p /container-root/dev &&
      cp -a /dev/cis-fixture /container-root/dev/cis-fixture &&
      cp -a /dev/null /container-root/dev/null &&
      test -c /container-root/dev/cis-fixture && test -c /container-root/dev/null); then
    echo CIS_PROFILE_VM_EXIT=91
    poweroff -f
    exit 91
fi
if test -f /cis-fd-lifecycle; then export CIS_FD_SUITE=lifecycle; fi
/usr/bin/python3 /profile/fd_vm.py
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/fd-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
sync
poweroff -f
