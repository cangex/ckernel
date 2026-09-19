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
touch /cis-disposable-vm
if ! (insmod /cis_slub_fixture.ko && mkdir -p /container-root/dev &&
      cp -a /dev/cis-slub-test /container-root/dev/ && cp -a /dev/null /container-root/dev/); then
    echo CIS_PROFILE_VM_EXIT=91
    poweroff -f
    exit 91
fi
/usr/bin/python3 /profile/slub_vm.py
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/slub-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
rmmod cis_slub_fixture
echo "CIS_SLUB_FIXTURE_UNLOAD=$?"
sync
poweroff -f
