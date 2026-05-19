// SPDX-License-Identifier: GPL-2.0
/*
 * x86 implementation of ks_override_function_with_return().
 *
 * Verbatim port of arch/x86/lib/error-inject.c with the symbols
 * renamed so this module-local copy never clashes with the in-tree
 * just_return_func / override_function_with_return when the host
 * kernel happens to have CONFIG_FUNCTION_ERROR_INJECTION=y.
 *
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 */

#include <linux/linkage.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

#include <asm/ibt.h>

#include "../../ks_internal.h"

/*
 * This is a 1:1 copy of arch/x86/lib/error-inject.c, with the symbols
 * renamed so the module never clashes with the in-tree just_return_func
 * if the host kernel happens to have CONFIG_FUNCTION_ERROR_INJECTION=y.
 *
 * The function is reached by setting regs->ip from a kprobe pre-handler,
 * so on IBT kernels it must begin with ENDBR64.  Using ASM_RET picks
 * up RETHUNK / SRSO mitigations when those are configured.
 */

asmlinkage void ks_just_return_func(void);

asm(
	".text\n"
	".type ks_just_return_func, @function\n"
	"ks_just_return_func:\n"
		ASM_ENDBR
		ASM_RET
	".size ks_just_return_func, .-ks_just_return_func\n"
);

void ks_override_function_with_return(struct pt_regs *regs)
{
	regs->ip = (unsigned long)&ks_just_return_func;
}
NOKPROBE_SYMBOL(ks_override_function_with_return);
