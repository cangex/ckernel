# SPDX-License-Identifier: GPL-2.0
CFLAGS += -O2 -Wall -Wextra -pthread
LDLIBS += -pthread
COMMON_TESTS := lifecycle fd vfs lsm maple_lifecycle cgroup topology faults
TEST_GEN_PROGS := $(COMMON_TESTS) private_tree vfs_lease_contract vfs_lease vfs_stress vfs_open_lease
TEST_PROGS := run_isolated.sh
TEST_FILES := profiles/open-deny.profile
include ../lib.mk
$(COMMON_TESTS): $(OUTPUT)/%: %.c common.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< common.c $(LDLIBS) -o $@
