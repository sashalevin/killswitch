#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Build a test kernel for the killswitch OOT CI.
#
#   ARCH={x86_64|arm64}  target arch (default: native)
#   TAG=vX.Y[.Z]         linux tag to clone (required)
#   OUT=<dir>            output directory (default: linux-build)
#
# Shallow-clones torvalds/linux at $TAG, applies tests/kernel_config.fragment
# on top of defconfig, builds the bootable image + modules_prepare, and
# seeds Module.symvers from vmlinux.symvers (needed for OOT modpost).

set -euo pipefail

ARCH="${ARCH:-$(uname -m)}"
TAG="${TAG:?TAG is required (e.g. v7.0)}"
OUT="${OUT:-linux-build}"
[ -n "$OUT" ] || { echo "OUT must not be empty" >&2; exit 2; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRAGMENT="$REPO_ROOT/tests/kernel_config.fragment"

case "$ARCH" in
	x86_64) KARCH=x86;  IMAGE_TARGET=bzImage; DEFCONFIG=x86_64_defconfig ;;
	arm64)  KARCH=arm64; IMAGE_TARGET=Image;   DEFCONFIG=defconfig ;;
	*)      echo "unsupported ARCH=$ARCH" >&2; exit 1 ;;
esac

if [ -f "$OUT/.ks_build_done" ] \
	&& [ "$(cat "$OUT/.ks_build_done")" = "$TAG" ] \
	&& [ -f "$OUT/arch/$KARCH/boot/$IMAGE_TARGET" ]; then
	echo "build_kernel.sh: $OUT already built for $TAG, skipping"
	exit 0
fi

echo "build_kernel.sh: cloning $TAG into $OUT (shallow)"
rm -rf "$OUT"
git clone --depth=1 --branch "$TAG" \
	https://github.com/torvalds/linux.git "$OUT"

cd "$OUT"
echo "build_kernel.sh: applying defconfig + fragment"
make "ARCH=$KARCH" "$DEFCONFIG" >/dev/null
fragments="$FRAGMENT"
# Optional second fragment merged on top — used by the mitigations
# test to enable subsystems the per-CVE scripts target.  Default CI
# leaves EXTRA_FRAGMENT unset.
if [ -n "${EXTRA_FRAGMENT:-}" ]; then
	# Resolve relative paths against REPO_ROOT before we cd into the
	# kernel tree.  Caller can pass either form.
	case "$EXTRA_FRAGMENT" in
		/*) ;;
		*) EXTRA_FRAGMENT="$REPO_ROOT/$EXTRA_FRAGMENT" ;;
	esac
	[ -f "$EXTRA_FRAGMENT" ] || {
		echo "build_kernel.sh: EXTRA_FRAGMENT=$EXTRA_FRAGMENT not found" >&2
		exit 1
	}
	fragments="$fragments $EXTRA_FRAGMENT"
	echo "build_kernel.sh: also merging $EXTRA_FRAGMENT"
fi
# shellcheck disable=SC2086 -- intentional word splitting on $fragments
./scripts/kconfig/merge_config.sh -m -O . .config $fragments >/dev/null
make "ARCH=$KARCH" olddefconfig >/dev/null

# Sanity: every symbol the fragment asks to enable must really be =y
# after the merge.  The fragment also has a couple of "# CONFIG_X is not
# set" directives we check explicitly below.
#
# KPROBES_ON_FTRACE is intentionally NOT in this list: only a subset of
# arches select HAVE_KPROBES_ON_FTRACE (x86/s390/ppc/csky/loongarch/parisc),
# and arm64 isn't one of them.  Without KPROBES_ON_FTRACE the kprobe
# layer falls back to breakpoint+single-step; the OOT module's
# pre-handler (which sets regs and returns 1) still works correctly.
need_y="KPROBES FTRACE FUNCTION_TRACER DYNAMIC_FTRACE
        SECURITY SECURITYFS MODULES MODULE_UNLOAD DEBUG_FS DEBUG_FS_ALLOW_ALL
        BLK_DEV_INITRD RD_GZIP DEVTMPFS DEVTMPFS_MOUNT
        VIRTIO VIRTIO_PCI VIRTIO_BLK VIRTIO_NET VIRTIO_CONSOLE
        SERIAL_8250 SERIAL_8250_CONSOLE
        SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE
        FUNCTION_ERROR_INJECTION
        BPF BPF_SYSCALL BPF_EVENTS BPF_JIT BPF_KPROBE_OVERRIDE KPROBE_EVENTS"
need_n="MODULE_SIG_FORCE"

# arm64 doesn't have SERIAL_8250_CONSOLE in defconfig, and x86 doesn't have
# PL011.  Restrict to the arch we're actually building.
case "$KARCH" in
	x86)   skip="SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE" ;;
	arm64) skip="SERIAL_8250 SERIAL_8250_CONSOLE" ;;
esac
for s in $skip; do need_y=$(echo "$need_y" | tr ' \n' '\n\n' | grep -v "^${s}$" | tr '\n' ' '); done

for sym in $need_y; do
	if ! grep -q "^CONFIG_${sym}=y" .config; then
		echo "build_kernel.sh: CONFIG_${sym}=y not set after merge" >&2
		grep -E "^(# )?CONFIG_${sym}\b" .config >&2 || true
		exit 1
	fi
done
for sym in $need_n; do
	if grep -q "^CONFIG_${sym}=y" .config; then
		echo "build_kernel.sh: CONFIG_${sym}=y must be unset" >&2
		exit 1
	fi
done

JOBS="$(nproc)"
echo "build_kernel.sh: building $IMAGE_TARGET + modules_prepare with -j$JOBS"
make "ARCH=$KARCH" -j"$JOBS" "$IMAGE_TARGET" modules_prepare

# modules_prepare doesn't emit Module.symvers; OOT modpost needs one.
# vmlinux.symvers (produced by the bzImage/Image link) is a sufficient seed.
if [ ! -f Module.symvers ]; then
	if [ ! -f vmlinux.symvers ]; then
		echo "build_kernel.sh: neither Module.symvers nor vmlinux.symvers exists; build broken" >&2
		exit 1
	fi
	cp vmlinux.symvers Module.symvers
fi

echo "$TAG" > .ks_build_done
echo "build_kernel.sh: done. image=$OUT/arch/$KARCH/boot/$IMAGE_TARGET"
