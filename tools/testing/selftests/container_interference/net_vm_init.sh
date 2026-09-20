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
if ! (insmod /cis_net_fixture.ko && /bin/busybox ifconfig lo up &&
      mkdir -p /container-root/dev && cp -a /dev/cis-net-test /container-root/dev/); then
    echo CIS_PROFILE_VM_EXIT=91
    poweroff -f
    exit 91
fi
case " $(cat /proc/cmdline) " in
    *" cis_net_test=quota "*) /usr/bin/python3 /profile/net_vm.py --quota ;;
    *" cis_net_test=txrelease "*) /usr/bin/python3 /profile/net_vm.py --txrelease ;;
    *" cis_net_test=guard "*) /usr/bin/python3 /profile/net_guard_vm.py ;;
    *" cis_net_test=txadmission "*) /usr/bin/python3 /profile/net_vm.py --txadmission ;;
    *" cis_net_test=txfailure "*) /usr/bin/python3 /profile/net_vm.py --txfailure ;;
    *" cis_net_test=capacity "*) /usr/bin/python3 /profile/net_vm.py --capacity ;;
    *" cis_net_test=origin "*) /usr/bin/python3 /profile/net_vm.py --origin ;;
    *" cis_net_test=backlog "*) /usr/bin/python3 /profile/net_vm.py --backlog ;;
    *" cis_net_test=rights "*) /usr/bin/python3 /profile/net_vm.py --rights ;;
    *) /usr/bin/python3 /profile/net_vm.py ;;
esac
status=$?
echo "CIS_PROFILE_VM_EXIT=$status"
find /tmp/net-evidence -type f | sort | while read -r f; do
    echo "CIS_FILE $f"
    cat "$f"
    echo
done
echo CIS_FILES_END
rmmod cis_net_fixture
echo "CIS_NET_FIXTURE_UNLOAD=$?"
sync
poweroff -f
