# SPDX-License-Identifier: GPL-2.0
CFLAGS += -O2 -Wall -Wextra -pthread
LDLIBS += -pthread
TEST_GEN_PROGS := lifecycle fd vfs lsm maple_lifecycle cgroup topology faults
TEST_PROGS := run_isolated.sh
include ../lib.mk
$(TEST_GEN_PROGS): $(OUTPUT)/%: %.c common.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< common.c $(LDLIBS) -o $@
