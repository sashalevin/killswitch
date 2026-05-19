# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Standalone selftest for the killswitch OOT module.
#
# Usage:
#   make            # build the helper test programs
#   sudo make check # run the full end-to-end test

CFLAGS := -O2 -g -std=gnu99 -Wall
PROGS  := cve_31431_test cve_43284_test

.PHONY: all check clean

all: $(PROGS)

cve_31431_test: cve_31431_test.c
	$(CC) $(CFLAGS) $< -o $@

cve_43284_test: cve_43284_test.c
	$(CC) $(CFLAGS) $< -o $@

check: all
	./killswitch_test.sh

clean:
	rm -f $(PROGS)
