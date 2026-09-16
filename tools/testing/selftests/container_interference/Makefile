# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror
LDLIBS += -pthread
TEST_GEN_PROGS := workload baseline
all: $(TEST_GEN_PROGS)
%: %.c common.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< common.c -o $@ $(LDLIBS)
run_tests: all
	sh ./run_isolated.sh
clean:
	rm -f $(TEST_GEN_PROGS)
.PHONY: all run_tests clean
