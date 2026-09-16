# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror
LDLIBS += -pthread
TEST_GEN_PROGS := workload baseline identity fleet entry_workload entry_storm
TEST_GEN_PROGS_EXTENDED := logic_test budget_test
.PHONY: all clean run_tests
all: $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED)
$(TEST_GEN_PROGS): %: %.c common.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< common.c -o $@ $(LDLIBS)
run_tests: all
	./logic_test
	./budget_test
	./baseline
logic_test: logic_test.c ../../../container_interference/baseline.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
budget_test: budget_test.c ../../../container_interference/budget.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -Wl,--wrap=fopen -o $@
clean:
	rm -f $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED)
