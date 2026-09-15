#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
if [ "${CKM_ISOLATED_GUEST:-}" != 1 ]; then
    echo 'Refusing host execution: run inside the dedicated VM with CKM_ISOLATED_GUEST=1.' >&2
    exit 4
fi
fail=0
for test in lifecycle fd vfs lsm maple_lifecycle cgroup topology faults private_tree vfs_lease_contract; do
    rc=0
    "$(dirname "$0")/$test" || rc=$?
    case "$rc" in 0) echo "PASS $test";; 4) echo "SKIP $test";; *) echo "FAIL $test rc=$rc"; fail=1;; esac
done
exit "$fail"
