/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 */
#ifndef _KS_INTERNAL_H
#define _KS_INTERNAL_H

struct pt_regs;

/* Provided per-arch in arch/<arch>/error_inject.c */
void ks_override_function_with_return(struct pt_regs *regs);

#endif /* _KS_INTERNAL_H */
