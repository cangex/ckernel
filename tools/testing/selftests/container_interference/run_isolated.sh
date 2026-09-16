#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
if [ "${CIS_ISOLATED_VM:-}" != 1 ]; then
    echo 'Set CIS_ISOLATED_VM=1 only inside a dedicated disposable VM.' >&2
    exit 4
fi
test "$(id -u)" = 0
test -d /container-root
./baseline
if test -x ./identity; then ./identity metrics; fi
