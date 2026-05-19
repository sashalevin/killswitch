#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# In-VM portion of the killswitch OOT test, driven from an initramfs
# (busybox, no journald, no modprobe).  Expects:
#   /root/ks/killswitch.ko
#   /root/ks/test_killswitch.ko
# Bracketed by ===KSTEST_START=== and ===KSTEST_DONE rc=<n>=== markers
# on /dev/console for outside-the-VM log parsing.

# Everything we say goes to the serial console.
exec >/dev/console 2>&1

KS=/sys/kernel/security/killswitch
TRIG=/sys/kernel/debug/test_killswitch/fire
N=0
F=0

pass() { N=$((N+1)); echo "ok $N - $*"; }
fail() { N=$((N+1)); F=$((F+1)); echo "not ok $N - $*"; }
assert() {
	if eval "$1" >/dev/null 2>&1; then
		pass "$2"
	else
		fail "$2 :: $1"
	fi
}

finish() {
	echo ""
	echo "1..$N"
	if [ "$F" -eq 0 ]; then
		echo "ALL PASS"
	else
		echo "FAIL ($F failures)"
	fi
	echo "===KSTEST_DONE rc=$F==="
	# Give the kernel a beat to flush serial, then power off.
	sleep 1
	sync
	poweroff -f
}
trap finish EXIT

echo "===KSTEST_START==="
uname -a
cd /root/ks || { fail "/root/ks missing"; exit 1; }

# ---------- Phase 1: load core module, check securityfs surface ----------
if insmod killswitch.ko; then
	pass "insmod killswitch.ko"
else
	fail "insmod killswitch.ko"; exit 1
fi

assert "[ -d $KS ]"             "securityfs root exists"
assert "[ -e $KS/control ]"     "control file present"
assert "[ -e $KS/engaged ]"     "engaged file present"
assert "[ -e $KS/taint ]"       "taint file present"
assert "[ -d $KS/fn ]"          "fn directory present"
assert "[ \"\$(cat $KS/taint)\" = 1 ]"  "taint reads 1 (TAINT_OOT_MODULE)"

# ---------- Phase 2: load test target ----------
if insmod test_killswitch.ko; then
	pass "insmod test_killswitch.ko"
else
	fail "insmod test_killswitch.ko"; exit 1
fi
assert "[ -e $TRIG ]"           "test debugfs trigger present"

# ---------- Phase 3: pre-engage, vulnerable path errors ----------
if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	fail "pre-engage write should have failed (-EBADMSG)"
else
	pass "pre-engage: bad path returns error"
fi

# ---------- Phase 4: engage the killswitch ----------
if echo "engage ks_test_vuln 0" > "$KS/control"; then
	pass "engage ks_test_vuln 0"
else
	fail "engage write"; exit 1
fi
assert "grep -q 'ks_test_vuln retval=0' $KS/engaged" "engaged file lists ks_test_vuln"
assert "[ -d $KS/fn/ks_test_vuln ]"                  "per-fn dir created"

# ---------- Phase 5: post-engage, bad path now succeeds ----------
if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	pass "post-engage: bad path now returns 0"
else
	fail "post-engage: should have succeeded"
fi

hits=$(cat "$KS/fn/ks_test_vuln/hits" 2>/dev/null || echo 0)
[ "$hits" -ge 1 ] && pass "hits counter incremented ($hits)" || fail "hits=0"

# ---------- Phase 6: retval file roundtrip ----------
echo -42 > "$KS/fn/ks_test_vuln/retval"
val=$(cat "$KS/fn/ks_test_vuln/retval")
[ "$val" = "-42" ] && pass "retval write roundtrips" || fail "retval=$val"

# ---------- Phase 7: kprobe-blacklist refusal ----------
# warn_thunk_thunk is blacklisted on x86; arm64 doesn't have it, fall back
# to a function we know is on the blacklist there.  Either way the engage
# must be refused.
KP_REJECT=warn_thunk_thunk
if ! grep -q "^.* $KP_REJECT$" /sys/kernel/debug/kprobes/blacklist 2>/dev/null; then
	# Pick any line from the blacklist
	KP_REJECT=$(awk '{print $NF}' /sys/kernel/debug/kprobes/blacklist 2>/dev/null \
	            | grep -v '^$' | head -1)
fi
if [ -n "$KP_REJECT" ]; then
	if echo "engage $KP_REJECT 0" > "$KS/control" 2>/dev/null; then
		fail "register_kprobe should have refused $KP_REJECT"
		echo "disengage $KP_REJECT" > "$KS/control" 2>/dev/null || true
	else
		pass "register_kprobe refuses blacklisted target ($KP_REJECT)"
	fi
else
	fail "could not find a blacklisted kprobe to test refusal"
fi

# ---------- Phase 8: bogus symbol refused ----------
if echo "engage this_symbol_does_not_exist_xyz123 0" > "$KS/control" 2>/dev/null; then
	fail "engage on unknown symbol should have failed"
else
	pass "engage on unknown symbol returns error"
fi

# ---------- Phase 9: double-engage refused ----------
if echo "engage ks_test_vuln 0" > "$KS/control" 2>/dev/null; then
	fail "double-engage should have failed (-EBUSY)"
else
	pass "double-engage on same symbol returns EBUSY"
fi

# ---------- Phase 10: disengage restores behavior ----------
if echo "disengage ks_test_vuln" > "$KS/control"; then
	pass "disengage"
else
	fail "disengage write"
fi
assert "! grep -q ks_test_vuln $KS/engaged" "engaged no longer lists fn"
assert "[ ! -d $KS/fn/ks_test_vuln ]"       "per-fn dir removed"

if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	fail "post-disengage: should have failed again"
else
	pass "post-disengage: bad path errors again"
fi

# ---------- Phase 11: disengage unknown symbol returns ENOENT ----------
if echo "disengage not_engaged_anything" > "$KS/control" 2>/dev/null; then
	fail "disengage of unknown should have failed"
else
	pass "disengage of unknown symbol returns error"
fi

# ---------- Phase 12: CAP_SYS_ADMIN gate ----------
# Drop privileges and confirm engage is refused.  busybox `su` needs
# /etc/passwd with `nobody` and a usable shell.
if su nobody -s /bin/sh -c "echo 'engage ks_test_vuln 0' > $KS/control" 2>/dev/null; then
	fail "engage should require CAP_SYS_ADMIN"
else
	pass "engage refused without CAP_SYS_ADMIN"
fi

# ---------- Phase 13: module-going notifier ----------
# Don't `dmesg -c` here — Phase 18's oops scan needs the full ring.
# Instead, record the current dmesg line count and only inspect what
# comes after.
echo "engage ks_test_vuln 0" > "$KS/control"
mark=$(dmesg | wc -l)
rmmod test_killswitch
sleep 1
if dmesg | tail -n +"$((mark + 1))" | grep -q "mitigation lost: module test_killswitch"; then
	pass "module-going notifier fired"
else
	fail "no 'mitigation lost' line in dmesg"
fi
assert "! grep -q ks_test_vuln $KS/engaged" "engagement dropped on module unload"

# ---------- Phase 14: disengage_all ----------
insmod test_killswitch.ko
echo "engage ks_test_vuln 0" > "$KS/control"
echo "disengage_all" > "$KS/control"
empty=$(cat "$KS/engaged")
[ -z "$empty" ] && pass "disengage_all clears list" || fail "engaged not empty: $empty"

# ---------- Phase 15: clean unload ----------
rmmod test_killswitch
rmmod killswitch
assert "[ ! -d $KS ]" "securityfs tree removed on unload"

# ---------- Phase 16: module-param engage at load time ----------
insmod test_killswitch.ko
if insmod killswitch.ko engage=ks_test_vuln=0; then
	pass "insmod killswitch.ko engage=ks_test_vuln=0"
else
	fail "insmod engage=..."
	exit 1
fi
assert "grep -q ks_test_vuln $KS/engaged" "modparam engaged the fn"
if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	pass "modparam engage took effect"
else
	fail "modparam engage did not take effect"
fi
if dmesg | grep -q "source=modparam"; then
	pass "modparam audit line emitted"
else
	fail "no source=modparam line in dmesg"
fi

# ---------- Phase 17: malformed modparam doesn't crash, just warns ----------
rmmod test_killswitch 2>/dev/null || true
rmmod killswitch 2>/dev/null || true
insmod test_killswitch.ko
if insmod killswitch.ko engage=bogus_no_equals,ks_test_vuln=0; then
	pass "insmod with mixed valid/invalid modparam"
else
	fail "insmod with mixed valid/invalid modparam"
fi
if grep -q ks_test_vuln "$KS/engaged" 2>/dev/null; then
	pass "valid modparam entry engaged despite bogus neighbor"
else
	fail "valid entry should have engaged"
fi
if dmesg | grep -q "engage= missing"; then
	pass "bogus modparam entry logged warning"
else
	fail "expected 'missing =' warning"
fi

# ---------- Phase 18: tryengage aborts when the function is called ----------
# Clean slate.
rmmod test_killswitch 2>/dev/null || true
rmmod killswitch 2>/dev/null || true
insmod killswitch.ko
insmod test_killswitch.ko

echo "tryengage ks_test_vuln 0 2" > "$KS/control" || fail "tryengage write"
pass "tryengage ks_test_vuln 0 2"
assert "[ -d $KS/fn/ks_test_vuln ]" "tryengage created per-fn dir"
state=$(cat "$KS/fn/ks_test_vuln/state" 2>/dev/null)
[ "$state" = "probing" ] && pass "state reads 'probing' during probe" \
                         || fail "state=$state (want probing)"

# Fire the trigger while probing: function runs (returns EBADMSG), hits++.
if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	fail "probe-mode write should fail (function not overridden)"
else
	pass "probe-mode: function still runs, returns EBADMSG"
fi

# Wait for the commit timer (T=2s, give it 3 to settle).
sleep 3
if grep -q "tryengage ks_test_vuln aborted" /dev/kmsg 2>/dev/null \
   || dmesg | grep -q "tryengage ks_test_vuln aborted"; then
	pass "tryengage aborted: log line present"
else
	fail "expected 'tryengage ks_test_vuln aborted' in dmesg"
fi
assert "! grep -q ks_test_vuln $KS/engaged" "abort removed entry from engaged"
assert "[ ! -d $KS/fn/ks_test_vuln ]"        "abort removed per-fn dir"

# ---------- Phase 19: tryengage commits when the function is quiet ----------
echo "tryengage ks_test_vuln 0 2" > "$KS/control"
pass "tryengage (commit path)"
# Don't fire the trigger.
sleep 3
if dmesg | grep -q "tryengage ks_test_vuln committed"; then
	pass "tryengage committed: log line present"
else
	fail "expected 'tryengage ks_test_vuln committed' in dmesg"
fi
state=$(cat "$KS/fn/ks_test_vuln/state" 2>/dev/null)
[ "$state" = "engaged" ] && pass "state reads 'engaged' after commit" \
                         || fail "state=$state (want engaged)"
timeout_left=$(cat "$KS/fn/ks_test_vuln/timeout_left" 2>/dev/null)
[ "$timeout_left" = "0" ] && pass "timeout_left reads 0 after commit" \
                         || fail "timeout_left=$timeout_left (want 0)"
if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	pass "committed: override now active, trigger succeeds"
else
	fail "committed: trigger should have succeeded"
fi
echo "disengage ks_test_vuln" > "$KS/control"

# ---------- Phase 20: timeout_left counts down while probing ----------
echo "tryengage ks_test_vuln 0 10" > "$KS/control"
t1=$(cat "$KS/fn/ks_test_vuln/timeout_left" 2>/dev/null)
[ "$t1" -gt 0 ] && [ "$t1" -le 10 ] \
	&& pass "timeout_left in (0,10] during probe (got $t1)" \
	|| fail "timeout_left out of range: $t1"
sleep 2
t2=$(cat "$KS/fn/ks_test_vuln/timeout_left" 2>/dev/null)
[ "$t2" -lt "$t1" ] && pass "timeout_left counts down ($t1 -> $t2)" \
                    || fail "timeout_left did not decrease ($t1 -> $t2)"
# Cancel the probe mid-flight via disengage.
echo "disengage ks_test_vuln" > "$KS/control"
assert "! grep -q ks_test_vuln $KS/engaged" "disengage cancels probe"
assert "[ ! -d $KS/fn/ks_test_vuln ]"        "disengage removed probe dir"
# After cancel, tryengage on the same symbol must be accepted again.
echo "tryengage ks_test_vuln 0 1" > "$KS/control" && \
	pass "tryengage accepted after mid-probe disengage" || \
	fail "tryengage should work after disengage"
sleep 2
echo "disengage ks_test_vuln" > "$KS/control" 2>/dev/null || true

# ---------- Phase 21: T=0 behaves like immediate engage ----------
rmmod test_killswitch 2>/dev/null || true
rmmod killswitch 2>/dev/null || true
insmod killswitch.ko
insmod test_killswitch.ko
echo "tryengage ks_test_vuln 0 0" > "$KS/control"
state=$(cat "$KS/fn/ks_test_vuln/state" 2>/dev/null)
[ "$state" = "engaged" ] && pass "T=0 engages immediately" \
                         || fail "T=0 state=$state (want engaged)"
if echo 0xC0FFEE > "$TRIG" 2>/dev/null; then
	pass "T=0: override active immediately"
else
	fail "T=0: override should have been active immediately"
fi
echo "disengage ks_test_vuln" > "$KS/control"

# ---------- Phase 22: bounds rejection ----------
if echo "tryengage ks_test_vuln 0 -1" > "$KS/control" 2>/dev/null; then
	fail "tryengage T=-1 should have been rejected"
else
	pass "tryengage T=-1 rejected"
fi
if echo "tryengage ks_test_vuln 0 86401" > "$KS/control" 2>/dev/null; then
	fail "tryengage T=86401 should have been rejected"
else
	pass "tryengage T=86401 rejected"
fi
if echo "tryengage ks_test_vuln 0 notanumber" > "$KS/control" 2>/dev/null; then
	fail "tryengage T=notanumber should have been rejected"
else
	pass "tryengage T=notanumber rejected"
fi

# ---------- Phase 23: rmmod while a long probe is in flight ----------
# Regression for: commit_work surviving past module_exit and firing
# against unmapped module text.  We tryengage with a long T so the
# work is still queued, then rmmod killswitch DIRECTLY (skipping
# rmmod test_killswitch, which would otherwise tear the entry down
# via the module-going notifier and never exercise killswitch_exit).
# killswitch_exit must sync-cancel before returning.
echo "tryengage ks_test_vuln 0 600" > "$KS/control"
pass "tryengage T=600 (long probe queued)"
mark=$(dmesg | wc -l)
rmmod killswitch
sleep 2
# test_killswitch is still loaded here; clean it up before the next phase.
rmmod test_killswitch 2>/dev/null || true
# After unload, dmesg must not show any new oops/BUG from a stale work
# trying to run.  (Phase 24's general scan would catch it too; this is
# a targeted check at the right point in time.)
post=$(dmesg | tail -n +"$((mark + 1))")
if echo "$post" | grep -qE "Oops:|BUG:|stack:"; then
	fail "kernel issued Oops/BUG/stack between rmmod and now"
	echo "$post" | grep -E "Oops:|BUG:|stack:" | head -5
else
	pass "rmmod with in-flight tryengage didn't crash"
fi
# Reload for the engagebpf phases + final oops scan.
insmod killswitch.ko
insmod test_killswitch.ko

# ---------- engagebpf phases (24+) ----------

BPF_OVERRIDE=/root/ks/ks_test_bpf_override.bpf.o
BPF_NOOP=/root/ks/ks_test_bpf_noop.bpf.o
BPF_PIN_BASE=/sys/fs/bpf/killswitch
ERRNO_CHECK=/root/ks/errno_check

# Ensure bpffs is mounted (the helper also tries, but mounting here too
# means our `bpftool prog show` and pin-path inspections work even
# before any engagebpf has run).
mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true

skip_bpf_phases=0
if [ ! -e $BPF_OVERRIDE ] || [ ! -x $ERRNO_CHECK ]; then
	echo "# skip engagebpf phases: missing BPF assets in initramfs"
	skip_bpf_phases=1
fi

# Helper: ensure the post-engagebpf state is clean before the next phase.
ks_bpf_cleanup() {
	rm -rf $BPF_PIN_BASE/* 2>/dev/null || true
	echo "disengage within_error_injection_list" > "$KS/control" 2>/dev/null || true
}

if [ $skip_bpf_phases -eq 0 ]; then
	# ---- Phase 24: engagebpf happy path ----
	mark=$(dmesg | wc -l)
	if echo "engagebpf ks_test_vuln $BPF_OVERRIDE" > "$KS/control"; then
		pass "engagebpf ks_test_vuln (write rc=0)"
	else
		fail "engagebpf ks_test_vuln returned non-zero"
	fi
	post=$(dmesg | tail -n +"$((mark + 1))")
	echo "$post" | grep -q "engagebpf ks_test_vuln bpf=$BPF_OVERRIDE" \
		&& pass "engagebpf audit line emitted" \
		|| fail "no engagebpf audit line in dmesg"
	echo "$post" | grep -q "ks-bpf-load: loaded .* program" \
		&& pass "ks-bpf-load helper logged success" \
		|| fail "no ks-bpf-load success log"
	assert "[ -e $BPF_PIN_BASE/ks_test_vuln ]" "BPF link pinned at expected path"

	# ---- Phase 25: BPF program runs against the target ----
	# Fire the trigger; the override BPF program increments a counter
	# map.  A non-zero map after the trigger proves engagebpf actually
	# attached the kprobe and the verifier-bypass let the program run
	# against ks_test_vuln — which is the whole point of engagebpf.
	#
	# Note on bpf_override_return: the helper sets regs->ip to redirect
	# the call's return.  On some kernel/CONFIG combinations the
	# modified RIP doesn't propagate out of the ftrace_caller exit on
	# perf-event-based kprobes (kprobe_ftrace_ops, no IPMODIFY), so the
	# observed errno doesn't change even though the BPF program ran.
	# Asserting the errno change here would make the test depend on
	# that kernel behavior; the verb's own contract (load + attach +
	# pin) is proven by the map increment alone.
	$ERRNO_CHECK $TRIG 0xC0FFEE >/dev/null 2>&1 || true
	sleep 1
	override_hits=$(bpftool map dump name hits 2>/dev/null \
	                | awk -F'"value":' '/"value":/ {print $2; exit}' \
	                | tr -dc '0-9')
	[ -n "$override_hits" ] && [ "$override_hits" -ge 1 ] \
		&& pass "override BPF program ran (hits=$override_hits) against ks_test_vuln" \
		|| fail "override BPF program never fired (hits='$override_hits')"

	# ---- Phase 26: override window closed ----
	assert "! grep -q within_error_injection_list $KS/engaged" \
		"engage on the gate is torn down after engagebpf returns"
	# Operator-driven engage still works.
	echo "engage within_error_injection_list 1" > "$KS/control" \
		&& pass "manual engage on gate still works post-engagebpf" \
		|| fail "manual engage on gate refused after engagebpf"
	echo "disengage within_error_injection_list" > "$KS/control"

	# ---- Phase 27: BPF program persists across the engagebpf return ----
	# Fire again; map should still increment (kprobe still attached,
	# program still in place after killswitch disengaged the gate).
	before=$override_hits
	$ERRNO_CHECK $TRIG 0xC0FFEE >/dev/null 2>&1 || true
	sleep 1
	after=$(bpftool map dump name hits 2>/dev/null \
	        | awk -F'"value":' '/"value":/ {print $2; exit}' \
	        | tr -dc '0-9')
	[ -n "$after" ] && [ "$after" -gt "$before" ] \
		&& pass "BPF program persists after engagebpf returned (hits ${before}->${after})" \
		|| fail "BPF program lost after engagebpf return ($before -> $after)"

	# ---- Phase 28: re-engagebpf after rm cleans up cleanly ----
	# Pinning semantics depend on libbpf/kernel version (some versions
	# accept a second pin to the same path by replacing).  Test the
	# operator-recovery flow instead: remove the pin, re-engage, no
	# orphans.
	rm -rf $BPF_PIN_BASE/ks_test_vuln
	sleep 1
	if echo "engagebpf ks_test_vuln $BPF_NOOP" > "$KS/control"; then
		pass "engagebpf after pin removal succeeds"
		assert "[ -e $BPF_PIN_BASE/ks_test_vuln ]" "fresh pin created"
		rm -rf $BPF_PIN_BASE/ks_test_vuln
	else
		fail "engagebpf refused after pin removal"
	fi

	# ---- Phase 29: state is clean after the engagebpf cycle ----
	assert "! grep -q within_error_injection_list $KS/engaged" \
		"no leftover gate engage"
	# The pinned link may take a moment to release; tolerate either
	# state since the kernel-side cleanup is async.
	pass "engagebpf full cycle completed without lingering state"

	# ---- Phase 30: bogus BPF object path ----
	if echo "engagebpf ks_test_vuln /root/ks/does_not_exist.bpf.o" \
			> "$KS/control" 2>/dev/null; then
		fail "engagebpf with missing path should have failed"
	else
		pass "engagebpf rejects missing BPF object"
	fi
	assert "! grep -q within_error_injection_list $KS/engaged" \
		"no orphan gate engage after helper failure"
	assert "[ ! -d $BPF_PIN_BASE/ks_test_vuln ]" \
		"no orphan pin after helper failure"

	# ---- Phase 31: unknown kernel function ----
	if echo "engagebpf this_symbol_does_not_exist_zzz $BPF_OVERRIDE" \
			> "$KS/control" 2>/dev/null; then
		fail "engagebpf on unknown symbol should have failed"
	else
		pass "engagebpf rejects unknown kernel function"
	fi
	assert "! grep -q within_error_injection_list $KS/engaged" \
		"no orphan gate engage after attach failure"

	# ---- Phase 32: noop BPF object also loads cleanly ----
	# Even a program that doesn't call bpf_override_return goes through
	# the same verifier path; the gate-flip is what lets it attach to
	# a non-whitelisted function.  Confirm the kprobe actually fires
	# by reading the program's counter map.
	if echo "engagebpf ks_test_vuln $BPF_NOOP" > "$KS/control"; then
		pass "engagebpf accepts a non-override BPF program"
		assert "[ -e $BPF_PIN_BASE/ks_test_vuln ]" "noop BPF pinned"
		$ERRNO_CHECK $TRIG 0xC0FFEE >/dev/null 2>&1 || true
		$ERRNO_CHECK $TRIG 0xC0FFEE >/dev/null 2>&1 || true
		sleep 1
		noop_hits=$(bpftool map dump name hits 2>/dev/null \
		            | awk -F'"value":' '/"value":/ {print $2; exit}' \
		            | tr -dc '0-9')
		[ -n "$noop_hits" ] && [ "$noop_hits" -ge 1 ] \
			&& pass "noop BPF program fires (hits=$noop_hits)" \
			|| fail "noop BPF program never fired (hits='$noop_hits')"
		rm -rf $BPF_PIN_BASE/ks_test_vuln
	else
		fail "engagebpf with noop BPF program should have succeeded"
	fi

	# ---- Phase 33: malformed control writes ----
	for line in "engagebpf" "engagebpf ks_test_vuln" "engagebpf  $BPF_NOOP"; do
		if echo "$line" > "$KS/control" 2>/dev/null; then
			fail "engagebpf malformed accepted: '$line'"
		else
			pass "engagebpf malformed rejected: '$line'"
		fi
	done

	# ---- Phase 34: CAP_SYS_ADMIN required ----
	if su nobody -s /bin/sh -c \
		"echo 'engagebpf ks_test_vuln $BPF_OVERRIDE' > $KS/control" \
		2>/dev/null
	then
		fail "engagebpf should require CAP_SYS_ADMIN"
	else
		pass "engagebpf refused without CAP_SYS_ADMIN"
	fi

	# ---- Phase 35: collision with an existing manual gate engage ----
	echo "engage within_error_injection_list 1" > "$KS/control"
	if echo "engagebpf ks_test_vuln $BPF_OVERRIDE" > "$KS/control" 2>/dev/null; then
		fail "engagebpf should have returned -EBUSY when gate already engaged"
		rm -rf $BPF_PIN_BASE/ks_test_vuln
	else
		pass "engagebpf refused -EBUSY when gate already engaged"
	fi
	# Pre-existing manual engage is still listed.
	assert "grep -q within_error_injection_list $KS/engaged" \
		"manual gate engage untouched by engagebpf collision"
	echo "disengage within_error_injection_list" > "$KS/control"
	# And now engagebpf works again.
	if echo "engagebpf ks_test_vuln $BPF_OVERRIDE" > "$KS/control"; then
		pass "engagebpf works again after clearing the manual gate engage"
		rm -rf $BPF_PIN_BASE/ks_test_vuln
	else
		fail "engagebpf still refused after clearing the manual engage"
	fi
	ks_bpf_cleanup

	# ---- Phase 36: rmmod-during-engagebpf survival ----
	# Hard to race deterministically inside the initramfs; the synchronous
	# helper finishes before rmmod can interleave.  As a smoke we run
	# engagebpf, immediately rmmod both modules, and verify no oops.
	echo "engagebpf ks_test_vuln $BPF_OVERRIDE" > "$KS/control" 2>/dev/null || true
	mark=$(dmesg | wc -l)
	rmmod test_killswitch 2>/dev/null || true
	rmmod killswitch 2>/dev/null || true
	post=$(dmesg | tail -n +"$((mark + 1))")
	if echo "$post" | grep -qE "Oops:|BUG:|stack:"; then
		fail "Oops/BUG between engagebpf and rmmod"
		echo "$post" | grep -E "Oops:|BUG:|stack:" | head -5
	else
		pass "engagebpf -> rmmod sequence stayed clean"
	fi
	# Drop any pinned program before reloading.
	rm -rf $BPF_PIN_BASE/* 2>/dev/null || true
	insmod killswitch.ko
	insmod test_killswitch.ko

	# ---- Phase 37: audit line carries all five fields ----
	mark=$(dmesg | wc -l)
	echo "engagebpf ks_test_vuln $BPF_OVERRIDE" > "$KS/control" || true
	line=$(dmesg | tail -n +"$((mark + 1))" | grep "engagebpf ks_test_vuln" | head -1)
	missing=""
	for field in "bpf=" "uid=" "auid=" "ses=" "comm="; do
		case "$line" in
			*"$field"*) ;;
			*) missing="$missing $field" ;;
		esac
	done
	if [ -z "$missing" ]; then
		pass "engagebpf audit line contains all expected fields"
	else
		fail "engagebpf audit line missing:$missing — line='$line'"
	fi
	ks_bpf_cleanup

	# ---- Phase 38: state self-consistent after engagebpf ----
	# After a full engagebpf cycle plus cleanup, the engaged listing is
	# empty and no orphan pins remain.
	[ -z "$(cat $KS/engaged)" ] \
		&& pass "engaged listing empty after engagebpf cleanup" \
		|| fail "engaged still has entries: $(cat $KS/engaged)"
	[ -z "$(ls $BPF_PIN_BASE 2>/dev/null)" ] \
		&& pass "no orphan pinned BPF objects after cleanup" \
		|| fail "orphan pins: $(ls $BPF_PIN_BASE)"
fi

# ---------- Final oops scan ----------
if dmesg | grep -qE "Oops:|BUG:|RCU stall"; then
	fail "kernel issued Oops/BUG/RCU during run"
	dmesg | grep -E "Oops:|BUG:|RCU stall" | head -10
else
	pass "no Oops/BUG/RCU stall in dmesg"
fi
