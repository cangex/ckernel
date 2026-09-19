# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
PYTHON ?= python3
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror
LDLIBS += -lbpf -lelf -lz
CORE = registry.c counters.c baseline.c budget.c report.c capture.c symbols.c fast.c
HEADERS = $(wildcard include/*.h)
BPF_OBJECTS = $(addprefix bpf/,$(addsuffix .bpf.o,cis ip owner sched reclaim sync fd counter allocator net block rwsem slub))
all: cisd cisctl session-worker session-residue $(BPF_OBJECTS)
session-residue: cleanup.c
	$(CC) $(CFLAGS) $(LDFLAGS) cleanup.c -o $@ $(LDLIBS)
session-worker: session_worker.c $(CORE) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) session_worker.c $(CORE) -o $@ $(LDLIBS)
cisd: cisd.c $(CORE) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) cisd.c $(CORE) -o $@ $(LDLIBS)
cisctl: cisctl.c include/cis.h
	$(CC) $(CFLAGS) $(LDFLAGS) cisctl.c -o $@
bpf/vmlinux.h:
	test -r "$(VMLINUX_BTF)"
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@
bpf/%.bpf.o: bpf/%.bpf.c bpf/cis.bpf.c bpf/rwsem_collect.h bpf/writeback.bpf.h bpf/maple.bpf.h bpf/net_tx.bpf.h bpf/vmlinux.h include/cis_event.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_arm64 -Wall -Werror -c $< -o $@
clean:
	rm -f cisd cisctl session-worker session-residue $(BPF_OBJECTS) bpf/vmlinux.h bpf/vmlinux.h.tmp
check-python:
	$(PYTHON) -m unittest discover -s ../testing/selftests/container_interference -p 'test_*.py'
	$(PYTHON) ../testing/selftests/container_interference/owner_test.py
	$(PYTHON) ../testing/selftests/container_interference/profile_test.py
.PHONY: all clean check-python
