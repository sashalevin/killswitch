// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Test BPF program: kprobe on ks_test_vuln(), unconditionally
 * bpf_override_return(ctx, -ESRCH).  Used by tests/in_vm.sh to prove
 * engagebpf actually lets a non-whitelisted target accept a BPF
 * override.
 *
 * ESRCH is chosen because the test_killswitch trigger normally
 * returns EBADMSG; ESRCH gives a clean, distinct errno that the
 * userspace probe (tests/errno_check.c) can grep for.
 *
 * We deliberately don't use BPF_KPROBE() / PT_REGS_PARM*; that macro
 * suite requires struct pt_regs to be a complete type (it dereferences
 * fields).  Without vmlinux.h we'd have to drag in the kernel's asm
 * headers, which clang -target bpf can't satisfy.  Since this program
 * doesn't read args, treating ctx as opaque is sufficient.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * Counter map so the test can verify the program actually fired
 * regardless of whether the bpf_override_return call's IP rewrite
 * lands.  In a correctly working setup hits == fires.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

SEC("kprobe/ks_test_vuln")
int ks_override(void *ctx)
{
	__u32 zero = 0;
	__u64 *v = bpf_map_lookup_elem(&hits, &zero);
	if (v)
		__sync_fetch_and_add(v, 1);
	bpf_override_return(ctx, -3 /* ESRCH */);
	return 0;
}
