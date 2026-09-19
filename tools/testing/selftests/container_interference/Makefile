# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror
LDLIBS += -pthread
TEST_GEN_PROGS := workload baseline identity fleet entry_workload entry_storm session_launch sync_workload fd_workload fd_cross_workload counter_workload counter_mem_workload allocator_workload allocator_fixture_workload net_workload net_backlog_workload block_workload diagnosis_workload joint_workload rwsem_workload
TEST_GEN_PROGS_EXTENDED := logic_test budget_test metrics_test fast_test recursion_snapshot_test
TEST_GEN_PROGS += allocator_placement_workload
TEST_GEN_PROGS += allocator_failure_workload
.PHONY: all clean run_tests
all: $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED)
$(TEST_GEN_PROGS): %: %.c common.c common.h ../../../container_interference/include/cis.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< common.c -o $@ $(LDLIBS)
sync_workload: fixture/uapi.h
fd_workload: fixture/uapi.h
fd_cross_workload: fixture/uapi.h
counter_workload: ../../../../include/uapi/linux/cis_counter_test.h
allocator_fixture_workload: ../../../../include/uapi/linux/cis_alloc_test.h
allocator_placement_workload: allocator_fixture/placement_uapi.h
allocator_failure_workload: ../../../../include/uapi/linux/cis_alloc_test.h
net_workload net_backlog_workload: net_fixture/uapi.h
rwsem_workload: rwsem_fixture/uapi.h
run_tests: all
	./logic_test
	./budget_test
	./metrics_test
	./fast_test
	./recursion_snapshot_test
	python3 owner_test.py
	python3 profile_test.py
	./baseline
logic_test: logic_test.c ../../../container_interference/baseline.c ../../../container_interference/include/cis.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@
budget_test: budget_test.c ../../../container_interference/budget.c ../../../container_interference/include/cis.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -Wl,--wrap=fopen -Wl,--wrap=clock_gettime -Wl,--wrap=getrusage -o $@
metrics_test: metrics_test.c ../../../container_interference/counters.c ../../../container_interference/include/cis.h ../../../container_interference/include/cis_metrics_schedule.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -Wl,--wrap=clock_gettime -o $@
fast_test: fast_test.c ../../../container_interference/include/cis_trigger.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
recursion_snapshot_test: recursion_snapshot_test.c ../../../container_interference/include/cis_recursion_snapshot.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
clean:
	rm -f $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED)
