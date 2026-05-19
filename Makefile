# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Out-of-tree build for the killswitch module.
#
# Usage:
#   make                              # build against /lib/modules/$(uname -r)/build
#   make KDIR=~/linux                 # build against a custom kernel tree
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=~/linux   # cross-build
#   sudo make install                 # modules_install + depmod
#   make clean
#
# Build artifacts: killswitch.ko, test_killswitch.ko

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)

.PHONY: all modules tools clean install modules_install tools_install help

all: modules tools

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools:
	$(MAKE) -C tools

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C tools clean

install: modules_install tools_install

modules_install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) INSTALL_MOD_DIR=extra/killswitch modules_install
	-depmod -a

tools_install: tools
	$(MAKE) -C tools install

help:
	@echo "Targets:"
	@echo "  all              build killswitch.ko, test_killswitch.ko, ks-bpf-load"
	@echo "  modules          build the kernel modules only"
	@echo "  tools            build the userspace helper (ks-bpf-load)"
	@echo "  install          modules_install + tools_install (helper -> /usr/sbin/)"
	@echo "  clean            clean both"
	@echo "Variables:"
	@echo "  KDIR=<path>      kernel build tree (default: running kernel headers)"
	@echo "  ARCH, CROSS_COMPILE   for cross-builds"
