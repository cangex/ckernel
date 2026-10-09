# SPDX-License-Identifier: GPL-2.0-only
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror
PYTHON ?= python3

.PHONY: all check clean
all: w2-context-test w3-fs-test
w2-context-test: w2_context_test.c
	$(CC) $(CFLAGS) -pthread $< -lselinux -o $@
w3-fs-test: w3_fs_test.c
	$(CC) $(CFLAGS) $< -o $@
check:
	$(PYTHON) -m unittest discover -s . -p 'test_*.py'
clean:
	rm -f w2-context-test w3-fs-test
