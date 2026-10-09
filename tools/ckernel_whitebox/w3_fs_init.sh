#!/bin/sh
export PATH=/bin:/sbin:/usr/bin
failures=0
mount -t proc proc /proc || failures=1
mount -t sysfs sysfs /sys || failures=1
grep -q ' /dev devtmpfs ' /proc/mounts || mount -t devtmpfs devtmpfs /dev || failures=1
mkdir -p /run /tmp /sys/fs/selinux /sys/kernel/security
mount -t securityfs securityfs /sys/kernel/security || failures=1
mount -t selinuxfs selinuxfs /sys/fs/selinux || failures=1
/sbin/load_policy -i || failures=1
/sbin/setfiles -F /etc/selinux/targeted/contexts/files/file_contexts /bin /sbin /lib /lib64 /usr /tests /init /dev /run /tmp || failures=1
test "$(cat /sys/fs/selinux/enforce)" = 1 || failures=1
echo W3_LSM
cat /sys/kernel/security/lsm
echo
mode=
epoch=
for arg in $(cat /proc/cmdline); do
    case "$arg" in w3mode=*) mode=${arg#w3mode=};; w3epoch=*) epoch=${arg#w3epoch=};; esac
done
case "$mode" in clean|crash|verify) ;; *) failures=1;; esac
if test "$failures" = 0; then
    /tests/w3-fs-test "$mode" "$epoch" >/dev/console 2>&1 || failures=1
fi
test "$(cat /sys/fs/selinux/enforce)" = 1 || failures=1
echo "W3_GUEST_END failures=$failures"
sync
mount -o remount,ro / || echo W3_REMOUNT_FAILED
poweroff -f
