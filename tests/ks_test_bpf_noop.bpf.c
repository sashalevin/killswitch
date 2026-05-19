// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Test BPF program: kprobe on ks_test_vuln() that just bumps a
 * counter and lets the original function run.  No bpf_override_return.
 * Used by tests/in_vm.sh to prove that the verifier-bypass path also
 * accepts perfectly innocuous programs.
 *
 * ctx is treated as opaque (see the override variant for the rationale).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

SEC("kprobe/ks_test_vuln")
int ks_noop(void *ctx)
{
	__u32 zero = 0;
	__u64 *v = bpf_map_lookup_elem(&hits, &zero);
	if (v)
		__sync_fetch_and_add(v, 1);
	return 0;
}
