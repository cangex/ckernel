#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
export CIS_QUEUE_GUARD=1
exec /bin/sh /profile/y5_queue_init.sh
