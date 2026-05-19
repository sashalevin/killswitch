# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Builds ks-bpf-load, the userspace helper called by killswitch's
# engagebpf verb.  Requires libbpf headers + library on the host.

CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDLIBS  ?= -lbpf -lelf -lz

DESTDIR ?=
SBINDIR ?= $(DESTDIR)/usr/sbin

PROGS := ks-bpf-load

.PHONY: all clean install

all: $(PROGS)

ks-bpf-load: ks-bpf-load.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(PROGS)

install: all
	install -d $(SBINDIR)
	install -m 0755 $(PROGS) $(SBINDIR)/
