# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Out-of-tree build description for the killswitch module.

obj-m += killswitch.o
obj-m += test_killswitch.o

killswitch-y := ks_main.o
killswitch-$(CONFIG_X86)   += arch/x86/error_inject.o
killswitch-$(CONFIG_ARM64) += arch/arm64/error_inject.o
