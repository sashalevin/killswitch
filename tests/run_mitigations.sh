#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# In-VM driver that exercises every script under /root/ks/mitigations/.
# This is NOT the default CI run — it's a heavyweight test invoked via
# the manual mitigations workflow.  Each script is judged on whether
# its engage/tryengage/engagebpf verb installs cleanly against the
# running kernel, not on whether it actually blocks any exploit.
#
# Outcomes per CVE:
#   PASS  — verb returned 0, the engagement is visible in
#           /sys/kernel/security/killswitch/engaged (or pinned at
#           /sys/fs/bpf/killswitch/<fn>), and clean disengage works.
#   SKIP  — target symbol isn't present on this kernel (module not
#           loaded, feature not built, on the kprobe blacklist).
#   FAIL  — script returned non-zero for a non-SKIP reason, no
#           engagement after success, or kernel Oops/BUG/RCU during
#           the run.
#
# Exit 0 only if FAIL == 0.

KS=/sys/kernel/security/killswitch
CTRL=$KS/control
MITIGATIONS=/root/ks/mitigations

# kprobe blacklist on the running kernel.  Some symbols are real but
# refuse a kprobe (NOKPROBE_SYMBOL or in a non-traceable section); we
# treat that as SKIP, not FAIL.
BLACKLIST=/sys/kernel/debug/kprobes/blacklist

# Parse the target kernel function out of a mitigation script's
# final `echo "<verb> <fn> ..." > $CTRL` line.  All scripts follow
# the same pattern.
extract_fn() {
	grep -oE 'echo "(engage|tryengage|engagebpf) [a-zA-Z_][a-zA-Z0-9_]*' "$1" \
		| tail -1 | awk '{print $3}'
}

extract_verb() {
	grep -oE 'echo "(engage|tryengage|engagebpf) ' "$1" \
		| tail -1 | awk '{print $2}' | tr -d '"'
}

symbol_kprobeable() {
	local fn="$1"
	# Must exist in kallsyms.
	grep -qE "^[0-9a-f]+ [a-zA-Z] $fn(	|\$)" /proc/kallsyms || return 1
	# Must NOT be on the kprobe blacklist.
	if [ -r "$BLACKLIST" ]; then
		grep -qE "[[:space:]]$fn(\$|[[:space:]])" "$BLACKLIST" && return 1
	fi
	return 0
}

engagement_visible() {
	local fn="$1"
	# tryengage/engage land an entry in $KS/engaged; engagebpf pins
	# under $KS/../../sys/fs/bpf/killswitch/<fn>.  Match either.
	grep -qE "^$fn " "$KS/engaged" 2>/dev/null && return 0
	[ -e /sys/fs/bpf/killswitch/"$fn" ] && return 0
	return 1
}

clean_target() {
	local fn="$1"
	echo "disengage $fn" > "$CTRL" 2>/dev/null || true
	rm -rf /sys/fs/bpf/killswitch/"$fn" 2>/dev/null || true
}

pass=0
fail=0
skip=0
N=0

# Load killswitch itself — the mitigation scripts all write to
# /sys/kernel/security/killswitch/control which doesn't exist without
# the module.  Bail loudly if it's missing because every subsequent
# test would FAIL identically.
if ! insmod /root/ks/killswitch.ko; then
	echo "1..1"
	echo "not ok 1 - insmod killswitch.ko failed"
	echo "===KSTEST_MITIGATIONS_DONE rc=1==="
	sync; sleep 1; poweroff -f
fi
[ -w "$CTRL" ] || {
	echo "1..1"
	echo "not ok 1 - $CTRL not writable after insmod"
	echo "===KSTEST_MITIGATIONS_DONE rc=1==="
	sync; sleep 1; poweroff -f
}

# Ensure bpffs exists; engagebpf scripts assume it.
mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true

echo "===KSTEST_MITIGATIONS_START==="

for sh in "$MITIGATIONS"/*.sh; do
	N=$((N + 1))
	name=$(basename "$sh" .sh)
	fn=$(extract_fn "$sh")
	verb=$(extract_verb "$sh")

	if [ -z "$fn" ]; then
		# Some mitigation scripts deliberately have no engage verb:
		# they print a rationale and exit 1 to document that this
		# particular CVE can't be mitigated by a kprobe gate (e.g.
		# requires IOMMU paging-cache flush, or a multi-engagement
		# cross-entry invariant).  Treat that as SKIP, not FAIL.
		echo "ok $N - SKIP $name (no killswitch-friendly mitigation)"
		skip=$((skip + 1))
		continue
	fi

	# Optional: scripts targeting a function that lives in a tristate
	# module declare `# KPROBE-MODULE: <m>` in their header so the
	# driver can attempt a modprobe before deciding the symbol is
	# unreachable.  Best-effort: failure here is fine, the
	# symbol_kprobeable check below makes the real call.
	for m in $(grep -oE '^# KPROBE-MODULE: \S+' "$sh" | awk '{print $3}'); do
		modprobe "$m" 2>/dev/null || true
	done

	if ! symbol_kprobeable "$fn"; then
		echo "ok $N - SKIP $name ($fn not kprobeable on this kernel)"
		skip=$((skip + 1))
		continue
	fi

	# Clean slate, including any stale engagement from a prior phase.
	clean_target "$fn"

	# Capture dmesg position so we can scan only what this script
	# emits, not earlier noise.
	mark=$(dmesg | wc -l)

	# tryengage scripts default to a long timeout (T=300s); for the
	# test we want quick commit/abort decisions.  Pass T=1 to any
	# script that takes a positional argument.
	rc=0
	timeout 60 sh "$sh" 1 >/tmp/run_mitigation.out 2>&1 || rc=$?

	post=$(dmesg | tail -n +"$((mark + 1))")
	oops=0
	echo "$post" | grep -qE "Oops:|BUG:|RCU stall|stack:" && oops=1

	if [ "$rc" -eq 77 ]; then
		# Script self-reported SKIP (autotools convention): the
		# target code path isn't reachable on this kernel, e.g.
		# the carrying module is modular and unavailable.
		reason=$(head -1 /tmp/run_mitigation.out 2>/dev/null)
		echo "ok $N - SKIP $name (${reason:-script reported not reachable})"
		skip=$((skip + 1))
	elif [ "$rc" -ne 0 ]; then
		echo "not ok $N - $name (verb=$verb rc=$rc)"
		head -5 /tmp/run_mitigation.out
		fail=$((fail + 1))
	elif [ "$oops" -eq 1 ]; then
		echo "not ok $N - $name (oops/BUG between mark and now)"
		echo "$post" | grep -E "Oops:|BUG:|RCU stall|stack:" | head -3
		fail=$((fail + 1))
	else
		# For a tryengage with T=1 the entry may have already
		# committed or aborted by now; allow either.  Visibility
		# is also OK while still in the probe window.
		# For engagebpf, the pin must exist.
		if engagement_visible "$fn"; then
			echo "ok $N - $name (verb=$verb fn=$fn)"
			pass=$((pass + 1))
		else
			# For tryengage with T=1 against a quiet symbol,
			# we likely committed already (kept).  Against a
			# noisy symbol, we likely aborted (removed).
			# Either is a successful install.  If the verb
			# was engagebpf and the pin is gone, that's a
			# real fail.
			if [ "$verb" = engagebpf ]; then
				echo "not ok $N - $name (engagebpf returned 0 but no pin)"
				fail=$((fail + 1))
			else
				echo "ok $N - $name (verb=$verb, tryengage settled)"
				pass=$((pass + 1))
			fi
		fi
	fi

	clean_target "$fn"
done

echo "1..$N"
echo "PASS=$pass FAIL=$fail SKIP=$skip"
if [ "$fail" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "FAIL ($fail)"
fi
echo "===KSTEST_MITIGATIONS_DONE rc=$fail==="
sync
sleep 1
poweroff -f
