// SPDX-License-Identifier: GPL-2.0
/*
 * arm64 implementation of ks_override_function_with_return().
 *
 * Verbatim port of arch/arm64/lib/error-inject.c with the symbol
 * renamed so this module-local copy never clashes with the in-tree
 * override_function_with_return when the host kernel happens to have
 * CONFIG_FUNCTION_ERROR_INJECTION=y.
 *
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 */

#include <linux/kprobes.h>
#include <linux/ptrace.h>

#include "../../ks_internal.h"

void ks_override_function_with_return(struct pt_regs *regs)
{
	/*
	 * 'regs' represents the state on entry of a predefined function in
	 * the kernel/module captured on a kprobe.  When kprobe returns from
	 * exception it will override the end of the probed function and
	 * directly return to the predefined function's caller.
	 */
	instruction_pointer_set(regs, procedure_link_pointer(regs));
}
NOKPROBE_SYMBOL(ks_override_function_with_return);
