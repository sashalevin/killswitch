#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Boot a test kernel under qemu with our initramfs and the OOT modules,
# capture serial output, and return the rc emitted by in_vm.sh.
#
# Required env:
#   ARCH         x86_64 | arm64
#   QEMU         path/name of qemu-system-* binary
#   KERNEL       path to bzImage / Image
#   INITRAMFS    path to initramfs.cpio.gz
# Optional:
#   SERIAL_LOG   path for serial output (default: $(mktemp))
#   KVM          1|0 (default: auto-detect via /dev/kvm)
#   TIMEOUT      seconds (default: 300)

set -euo pipefail

: "${ARCH:?ARCH required}"
: "${QEMU:?QEMU required}"
: "${KERNEL:?KERNEL required}"
: "${INITRAMFS:?INITRAMFS required}"
SERIAL_LOG="${SERIAL_LOG:-$(mktemp /tmp/ks-serial-XXXX.log)}"
TIMEOUT="${TIMEOUT:-300}"

if [ -z "${KVM:-}" ]; then
	if [ -w /dev/kvm ]; then KVM=1; else KVM=0; fi
fi

case "$ARCH" in
	x86_64)
		APPEND="console=ttyS0 panic=1 oops=panic loglevel=7 printk.devkmsg=on"
		MACHINE_OPTS=""
		if [ "$KVM" = 1 ]; then
			EXTRA="-enable-kvm -cpu host"
		else
			EXTRA="-cpu max"
		fi
		;;
	arm64)
		APPEND="console=ttyAMA0 panic=1 oops=panic loglevel=7 printk.devkmsg=on"
		if [ "$KVM" = 1 ]; then
			MACHINE_OPTS="-machine virt,gic-version=3,accel=kvm"
			EXTRA="-cpu host"
		else
			MACHINE_OPTS="-machine virt,gic-version=3"
			EXTRA="-cpu cortex-a72"
		fi
		;;
	*) echo "unsupported ARCH=$ARCH" >&2; exit 2 ;;
esac

echo "run_qemu.sh: $ARCH (kvm=$KVM), kernel=$KERNEL, initramfs=$INITRAMFS"
echo "run_qemu.sh: serial -> $SERIAL_LOG"

set +e
# -net none: don't auto-add a virtio-net-pci (the default on -machine
# virt would otherwise pull in efi-virtio.rom, which we don't need and
# isn't always installed).  The test doesn't need network.
timeout --foreground "$TIMEOUT" "$QEMU" \
	-m 2048 -smp 2 \
	$MACHINE_OPTS $EXTRA \
	-kernel "$KERNEL" \
	-initrd "$INITRAMFS" \
	-append "$APPEND" \
	-net none \
	-no-reboot -display none \
	-monitor none \
	-serial "file:$SERIAL_LOG"
qemu_rc=$?
set -e

# in_vm.sh / run_mitigations.sh print "===KSTEST*_DONE rc=N===" before
# powering off.  Default looks for the primary marker; the mitigations
# workflow overrides DONE_MARKER to "===KSTEST_MITIGATIONS_DONE".
DONE_MARKER="${DONE_MARKER:-===KSTEST_DONE}"
echo "--- serial log (KSTEST window) ---"
awk -v done="$DONE_MARKER" \
	'/===KSTEST_(MITIGATIONS_)?START===/,$0 ~ done' "$SERIAL_LOG" || true

rc=$(grep -oE "${DONE_MARKER} rc=[0-9]+===" "$SERIAL_LOG" | tail -1 \
	| sed -n 's/.*rc=\([0-9]\+\).*/\1/p' || true)

if [ -z "$rc" ]; then
	echo "run_qemu.sh: $DONE_MARKER marker not found; qemu_rc=$qemu_rc" >&2
	echo "--- serial log tail ---" >&2
	tail -50 "$SERIAL_LOG" >&2
	exit 1
fi

# Honor qemu_rc even when the marker was found: a timeout, qemu crash,
# or kernel panic after the marker would otherwise be silently ignored.
# qemu's clean-poweroff path exits 0; anything else (timeout=124, crash,
# guest oops with panic=1) deserves a CI fail.
if [ "$qemu_rc" -ne 0 ]; then
	echo "run_qemu.sh: qemu exited with rc=$qemu_rc (marker rc=$rc); failing" >&2
	echo "--- serial log tail ---" >&2
	tail -50 "$SERIAL_LOG" >&2
	exit "$qemu_rc"
fi

if [ "$rc" -ne 0 ]; then
	echo "run_qemu.sh: in-VM test reported $rc failures" >&2
	exit "$rc"
fi

echo "run_qemu.sh: PASS"
