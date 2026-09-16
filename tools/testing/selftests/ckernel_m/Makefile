# SPDX-License-Identifier: GPL-2.0
CFLAGS += -O2 -Wall -Wextra -pthread
LDLIBS += -pthread
COMMON_TESTS := lifecycle fd vfs lsm maple_lifecycle cgroup topology faults
TEST_GEN_PROGS := $(COMMON_TESTS) private_tree vfs_lease_contract vfs_lease vfs_stress vfs_open_lease security_cache
TEST_GEN_PROGS += fd_delegation
TEST_GEN_PROGS += socket_identity
TEST_PROGS := run_isolated.sh
TEST_FILES := profiles/open-deny.profile profiles/security.profile profiles/security-replace.profile
TEST_FILES += profiles/security-reload-initial.profile profiles/security-legacy.profile
TEST_FILES += profiles/features.nopolicydb profiles/README.rst
TEST_FILES += profiles/network.profile profiles/network-legacy.profile
TEST_FILES += profiles/network-reload-initial.profile profiles/network-replace.profile
include ../lib.mk
$(COMMON_TESTS): $(OUTPUT)/%: %.c common.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< common.c $(LDLIBS) -o $@
