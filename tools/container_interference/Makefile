# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror
LDLIBS += -lbpf -lelf -lz
CORE = registry.c counters.c baseline.c budget.c report.c capture.c symbols.c fast.c
all: cisd cisctl session-worker session-residue bpf/cis.bpf.o
session-residue: cleanup.c
	$(CC) $(CFLAGS) $(LDFLAGS) cleanup.c -o $@ $(LDLIBS)
session-worker: session_worker.c $(CORE) include/cis.h
	$(CC) $(CFLAGS) $(LDFLAGS) session_worker.c $(CORE) -o $@ $(LDLIBS)
cisd: cisd.c $(CORE) include/cis.h include/cis_event.h include/cis_trigger.h include/cis_metrics_schedule.h
	$(CC) $(CFLAGS) $(LDFLAGS) cisd.c $(CORE) -o $@ $(LDLIBS)
cisctl: cisctl.c include/cis.h
	$(CC) $(CFLAGS) $(LDFLAGS) cisctl.c -o $@
bpf/vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@
bpf/cis.bpf.o: bpf/cis.bpf.c bpf/vmlinux.h include/cis_event.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_arm64 -Wall -Werror -c $< -o $@
clean:
	rm -f cisd cisctl session-worker session-residue bpf/cis.bpf.o bpf/vmlinux.h bpf/vmlinux.h.tmp
.PHONY: all clean
