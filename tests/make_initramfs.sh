#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
#
# Build a tiny initramfs that runs tests/in_vm.sh against the OOT modules.
# Requires:
#   - busybox-static at /bin/busybox (Debian/Ubuntu: `apt install busybox-static`)
#   - killswitch.ko + test_killswitch.ko built (see top-level `make`)
# Output: initramfs.cpio.gz in CWD (or $OUT).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$REPO_ROOT/initramfs.cpio.gz}"

# Pick the static busybox.  On Debian/Ubuntu, busybox-static installs
# /bin/busybox as a statically linked binary, while /usr/bin/busybox
# is the dynamically linked default-flavour one.  Use whichever is
# actually static.
BUSYBOX=""
for cand in /bin/busybox /usr/bin/busybox.static /usr/bin/busybox; do
	[ -x "$cand" ] || continue
	if file "$cand" 2>/dev/null | grep -q "statically linked"; then
		BUSYBOX="$cand"
		break
	fi
done
if [ -z "$BUSYBOX" ]; then
	echo "make_initramfs.sh: no static busybox found; install busybox-static" >&2
	exit 1
fi
echo "make_initramfs.sh: using $BUSYBOX"

for f in "$REPO_ROOT/killswitch.ko" "$REPO_ROOT/test_killswitch.ko"; do
	[ -f "$f" ] || { echo "make_initramfs.sh: $f missing (run make first)" >&2; exit 1; }
done

# Build the userspace helper if not present (the engagebpf verb invokes it).
if [ ! -x "$REPO_ROOT/tools/ks-bpf-load" ]; then
	echo "make_initramfs.sh: building tools/ks-bpf-load"
	make -C "$REPO_ROOT/tools" >&2
fi

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT"/{bin,sbin,etc,proc,sys,dev,root/ks,tmp,var/log,usr/sbin,lib,lib64,sys/fs/bpf}
cp "$BUSYBOX" "$ROOT/bin/busybox"

# Copy a dynamically-linked binary's shared-library closure into the
# initramfs at the exact paths ldd reports.  Critically, copy to those
# paths verbatim (NOT the canonical realpath): the ELF's PT_INTERP
# embeds an absolute path (e.g. /lib64/ld-linux-x86-64.so.2) and the
# in-VM kernel exec() looks up the interpreter at that exact string.
# Following the symlink with `readlink -f` first would land it at the
# canonical /usr/lib/.../ld-linux-* and break exec.
copy_dynlibs() {
	local bin="$1"
	local lib dest
	for lib in $(ldd "$bin" 2>/dev/null | awk '/=>/ {print $3} /^[[:space:]]*\// {print $1}'); do
		[ -e "$lib" ] || continue
		dest="$ROOT$lib"
		mkdir -p "$(dirname "$dest")"
		cp -L "$lib" "$dest"
	done
}

# The ks-bpf-load helper + bpftool (used by tests to introspect pinned
# programs) get installed under /usr/sbin/ with their shared-library
# closure copied to the same paths the host has them at.
cp "$REPO_ROOT/tools/ks-bpf-load" "$ROOT/usr/sbin/ks-bpf-load"
chmod +x "$ROOT/usr/sbin/ks-bpf-load"
copy_dynlibs "$REPO_ROOT/tools/ks-bpf-load"

# bpftool ships under different paths depending on distro/version.
# On Ubuntu /usr/sbin/bpftool is a SHELL SCRIPT wrapper that execs
# the real ELF at /usr/lib/linux-tools/<kver>/bpftool — we want the
# ELF, not the wrapper, so prefer the per-kver paths.  On Debian
# /usr/sbin/bpftool *is* the real binary.
BPFTOOL=""
for cand in /usr/lib/linux-tools/*/bpftool \
            /usr/lib/linux-tools-*/bpftool \
            /usr/sbin/bpftool /usr/bin/bpftool \
            $(command -v bpftool 2>/dev/null); do
	[ -e "$cand" ] || continue
	# Skip scripts (Ubuntu wrapper); we only want a real ELF binary
	# whose ldd we can resolve to stage the shared-library closure.
	if file "$cand" 2>/dev/null | grep -q "ELF.*executable"; then
		BPFTOOL="$cand"
		break
	fi
done
echo "make_initramfs.sh: bpftool=${BPFTOOL:-<not found>}"
if [ -n "$BPFTOOL" ]; then
	cp "$BPFTOOL" "$ROOT/usr/sbin/bpftool"
	chmod +x "$ROOT/usr/sbin/bpftool"
	ln -sf ../sbin/bpftool "$ROOT/usr/bin/bpftool" 2>/dev/null || true
	# /bin/bpftool too so the in-VM `bpftool` command works without
	# needing PATH adjustment.
	mkdir -p "$ROOT/bin"
	ln -sf ../usr/sbin/bpftool "$ROOT/bin/bpftool" 2>/dev/null || true
	copy_dynlibs "$BPFTOOL"
else
	echo "make_initramfs.sh: bpftool not found; in-VM introspection tests will skip" >&2
fi

# Link in busybox applets we need.
APPLETS="sh ash cat echo grep ls mount umount insmod rmmod dmesg sleep
        poweroff sync mkdir rm chmod chown su head tail awk sed cut tr
        printf find cpio file lsmod test true false sort uniq xargs
        login getty mknod sysctl uname"
for a in $APPLETS; do
	ln -sf busybox "$ROOT/bin/$a"
done
ln -sf ../bin/busybox "$ROOT/sbin/poweroff"
ln -sf ../bin/busybox "$ROOT/sbin/init"

# /etc/passwd + group so `su nobody` works for the CAP_SYS_ADMIN test.
# Empty password so su doesn't prompt.
cat > "$ROOT/etc/passwd" <<EOF
root::0:0:root:/root:/bin/sh
nobody::65534:65534:nobody:/:/bin/sh
EOF
cat > "$ROOT/etc/group" <<EOF
root:x:0:
nobody:x:65534:
EOF
cat > "$ROOT/etc/shadow" <<EOF
root::0:0:99999:7:::
nobody::0:0:99999:7:::
EOF
chmod 0640 "$ROOT/etc/shadow"

cp "$REPO_ROOT/killswitch.ko" "$REPO_ROOT/test_killswitch.ko" \
   "$REPO_ROOT/tests/in_vm.sh" "$ROOT/root/ks/"
chmod +x "$ROOT/root/ks/in_vm.sh"

# Compile the BPF objects used by Phases 24+.  clang lives on the host;
# the resulting .bpf.o is portable enough to pass libbpf's verifier
# inside the VM after the engagebpf gate-open.
# libbpf's BPF_KPROBE macro needs a __TARGET_ARCH_xxx hint; pick it
# off uname.  Add the asm-arch include dir so <linux/bpf.h> resolves
# correctly under clang -target bpf.
case "$(uname -m)" in
	x86_64) BPF_ARCH_DEF=-D__TARGET_ARCH_x86  ; BPF_HDRS_INC=-I/usr/include/x86_64-linux-gnu ;;
	aarch64) BPF_ARCH_DEF=-D__TARGET_ARCH_arm64; BPF_HDRS_INC=-I/usr/include/aarch64-linux-gnu ;;
	*) BPF_ARCH_DEF=""; BPF_HDRS_INC="" ;;
esac
for src in ks_test_bpf_override ks_test_bpf_noop; do
	clang -O2 -g -target bpf -Wall $BPF_ARCH_DEF $BPF_HDRS_INC \
		-c "$REPO_ROOT/tests/${src}.bpf.c" \
		-o "$ROOT/root/ks/${src}.bpf.o"
done

# errno_check probe: tiny static-ish C binary that does a write() and
# prints the exact errno.  Built static so we don't need libc copied
# into /root/ks; falls back to dynamic if static libc isn't available.
if ! ${CC:-cc} -O2 -Wall -static \
	"$REPO_ROOT/tests/errno_check.c" \
	-o "$ROOT/root/ks/errno_check" 2>/dev/null
then
	echo "make_initramfs.sh: -static build of errno_check failed, falling back to dynamic"
	${CC:-cc} -O2 -Wall \
		"$REPO_ROOT/tests/errno_check.c" \
		-o "$ROOT/root/ks/errno_check"
	copy_dynlibs "$ROOT/root/ks/errno_check"
fi
chmod +x "$ROOT/root/ks/errno_check"

# Mitigations mode: stage the per-CVE scripts plus a clang toolchain
# so the scripts can compile their .bpf.c → .bpf.o inside the VM.
# This balloons the initramfs to ~100MB compressed, which is fine for
# the manual mitigations workflow but is NOT used by the default CI
# run (KS_INITRAMFS_MODE unset).
INIT_TARGET=/root/ks/in_vm.sh
if [ "${KS_INITRAMFS_MODE:-}" = "mitigations" ]; then
	echo "make_initramfs.sh: staging mitigations + clang toolchain"
	mkdir -p "$ROOT/root/ks/mitigations" "$ROOT/usr/bin" "$ROOT/usr/lib"
	cp "$REPO_ROOT"/mitigations/*.sh "$ROOT/root/ks/mitigations/"
	chmod +x "$ROOT/root/ks/mitigations/"*.sh
	cp "$REPO_ROOT/tests/run_mitigations.sh" "$ROOT/root/ks/"
	chmod +x "$ROOT/root/ks/run_mitigations.sh"
	INIT_TARGET=/root/ks/run_mitigations.sh

	# Find the real clang ELF (not the wrapper) and stage it + its
	# entire shared-library closure + the compiler-builtin headers.
	CLANG_REAL=""
	for cand in /usr/lib/llvm-*/bin/clang /usr/bin/clang-* /usr/bin/clang; do
		[ -e "$cand" ] || continue
		if file "$cand" 2>/dev/null | grep -q "ELF.*executable"; then
			CLANG_REAL="$cand"
			break
		fi
	done
	if [ -z "$CLANG_REAL" ]; then
		echo "make_initramfs.sh: clang ELF not found; install clang/llvm" >&2
		exit 1
	fi
	echo "make_initramfs.sh: clang=$CLANG_REAL"
	mkdir -p "$ROOT$(dirname "$CLANG_REAL")"
	cp "$CLANG_REAL" "$ROOT$CLANG_REAL"
	chmod +x "$ROOT$CLANG_REAL"
	# Expose at /usr/bin/clang where the kernel module's helper looks.
	mkdir -p "$ROOT/usr/bin"
	ln -sf "$CLANG_REAL" "$ROOT/usr/bin/clang"
	copy_dynlibs "$CLANG_REAL"

	# Compiler-builtin headers (stddef.h, stdint.h, the -target bpf
	# intrinsics).  They live next to clang at ../lib/clang/<ver>/include.
	CLANG_RES_DIR=$("$CLANG_REAL" -print-resource-dir 2>/dev/null)
	if [ -n "$CLANG_RES_DIR" ] && [ -d "$CLANG_RES_DIR" ]; then
		mkdir -p "$ROOT$CLANG_RES_DIR"
		cp -a "$CLANG_RES_DIR/." "$ROOT$CLANG_RES_DIR/"
	fi

	# Userspace headers that the BPF C sources include.  /usr/include
	# and the per-arch tree under /usr/include/<arch>-linux-gnu cover
	# <linux/bpf.h>, <bpf/bpf_helpers.h>, and asm.
	for d in /usr/include/linux /usr/include/bpf /usr/include/asm-generic \
	         /usr/include/x86_64-linux-gnu /usr/include/aarch64-linux-gnu; do
		[ -d "$d" ] || continue
		mkdir -p "$ROOT$d"
		cp -a "$d/." "$ROOT$d/"
	done

	# Debian's linux-libc-dev puts the actual UAPI headers at
	# /usr/lib/linux/uapi/<arch>/asm/ and symlinks them from
	# /usr/include/<triplet>/asm/.  Without the backing files the
	# symlinks are dangling and clang reports "asm/types.h not found"
	# even though it walks /usr/include/<triplet>.  Copy the real
	# tree too.
	if [ -d /usr/lib/linux/uapi ]; then
		mkdir -p "$ROOT/usr/lib/linux/uapi"
		cp -a /usr/lib/linux/uapi/. "$ROOT/usr/lib/linux/uapi/"
	fi

	# Distros ship /usr/include/asm as a symlink to the per-arch dir
	# (Debian/Ubuntu: /usr/include/x86_64-linux-gnu/asm or
	# /usr/include/aarch64-linux-gnu/asm).  Clang's default include
	# search for `-target bpf` covers /usr/include but NOT the
	# triplet subdir, so without this symlink `#include <asm/types.h>`
	# fails even though the file is staged.
	if [ -L /usr/include/asm ]; then
		cp -P /usr/include/asm "$ROOT/usr/include/asm"
	else
		# Fall back to a manual symlink if the host doesn't have
		# the convenience link (some minimal images).
		for arch_dir in x86_64-linux-gnu aarch64-linux-gnu; do
			if [ -d "$ROOT/usr/include/$arch_dir/asm" ]; then
				ln -sf "$arch_dir/asm" "$ROOT/usr/include/asm"
				break
			fi
		done
	fi
fi

# /init: mount the virtual filesystems and exec the test.  Output goes
# to /dev/console (which qemu's -serial captures).  in_vm.sh ends with
# poweroff -f.
cat > "$ROOT/init" <<INIT
#!/bin/sh
mount -t proc     none /proc
mount -t sysfs    none /sys
mount -t devtmpfs none /dev
# securityfs + debugfs aren't auto-mounted on a vanilla boot.
mkdir -p /sys/kernel/debug /sys/kernel/security
mount -t debugfs    none /sys/kernel/debug    2>/dev/null || true
mount -t securityfs none /sys/kernel/security 2>/dev/null || true

# Make su happy under busybox: skip PAM, login_class, etc.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
exec /bin/sh $INIT_TARGET
INIT
chmod +x "$ROOT/init"

# Pack: find . prints leading "./" entries; cpio accepts those.
( cd "$ROOT" && find . -print0 | cpio --quiet -o -0 -H newc ) \
	| gzip -9 > "$OUT"

echo "make_initramfs.sh: wrote $OUT ($(stat -c %s "$OUT") bytes)"
