# SPDX-License-Identifier: GPL-2.0
PYTHON ?= python3
.PHONY: test
test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s ../testing/selftests/ckernel_taskfs -v
