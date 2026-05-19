<!--
SPDX-License-Identifier: GPL-2.0
Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
-->
# killswitch (out-of-tree module)

`killswitch` makes a chosen kernel function return a fixed value without
running its body. It's a per-CVE mitigation primitive for the window
between disclosure and "patched kernel built, distributed, and
rebooted into."

When a serious bug lands in a code path that most installs only have
on by accident (AF\_ALG, ksmbd, nf\_tables, vsock, ax25, ...), an admin
can write:

    echo "engage af_alg_sendmsg -1" > /sys/kernel/security/killswitch/control

After that, `af_alg_sendmsg()` returns `-EPERM` on every call. The
mitigation takes effect immediately, persists for the lifetime of the
kernel, and goes away on the next reboot — by which point a patched
kernel is, hopefully, in place.

This repository is the out-of-tree variant. It carries the same
mechanism as the upstream `killswitch` patch but builds against
a stock distro kernel: no kernel patch, no kernel rebuild.

## What it is not

- **Not livepatch.** There is no replacement implementation; the
  function simply returns the chosen value.
- **Not error injection.** No `ALLOW_ERROR_INJECTION()` allow-list,
  no debugfs ceremony, no probabilistic override.
- **Not a permanent fix.** Engaging a killswitch is a band-aid. The
  taint never goes away until reboot, and an oops on an engaged
  kernel must reflect that fact in triage.

## Requirements

The running kernel must have:

- `CONFIG_KPROBES=y` and `CONFIG_KPROBES_ON_FTRACE=y`
- `CONFIG_SECURITYFS=y`
- `CONFIG_FTRACE=y` and a writable `/sys/kernel/security/`
- Matching `linux-headers` (or kernel build tree) for the running kernel
- For `engagebpf`: `CONFIG_FUNCTION_ERROR_INJECTION=y`,
  `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_EVENTS=y`,
  `CONFIG_BPF_KPROBE_OVERRIDE=y`, `libbpf` at run time on the host,
  and `/sys/fs/bpf` available (mounted or mountable)

Supported architectures: **x86_64** and **arm64**. Adding more is a
ten-line job per arch — see `arch/x86/error_inject.c` for the template.

## Build

Against the running kernel:

    make
    sudo make install
    sudo modprobe killswitch

Against a custom kernel tree:

    make KDIR=/path/to/linux

Cross-build for arm64:

    make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/linux

## Use

Once the module is loaded, `/sys/kernel/security/killswitch/` exposes:

| Path | Mode | Meaning |
| --- | --- | --- |
| `control` | wo | command sink: `engage <sym> <retval>`, `tryengage <sym> <retval> <T>`, `engagebpf <sym> <bpf.o>`, `disengage <sym>`, `disengage_all` |
| `engaged` | r | one line per engagement: `<sym> retval=<v> hits=<n>` |
| `taint` | r | `1` while the module is loaded (reads `TAINT_OOT_MODULE`) |
| `fn/<sym>/retval` | rw | per-engagement return value, late changes are picked up live |
| `fn/<sym>/hits` | r | per-cpu summed call count |
| `fn/<sym>/state` | r | `probing` while a `tryengage` timer is pending, `engaged` otherwise |
| `fn/<sym>/timeout_left` | r | seconds remaining on the probe (0 once engaged) |

### Probe-then-commit (`tryengage`)

`tryengage <sym> <retval> <T>` is `engage` with a safety net: instead of
overriding immediately, it installs the kprobe in probe mode (counts
calls but lets them run) for T seconds. After the timer fires:

- if `hits > 0`, the engagement is **aborted** — the kprobe is removed,
  the function keeps working, dmesg gets `tryengage <sym> aborted:
  hits=<n>...`;
- if `hits == 0`, the engagement is **committed** — the same kprobe
  flips to overriding mode, dmesg gets `tryengage <sym> committed...`.

`T` is in seconds, range `0..86400`. `T=0` skips the probe entirely
and is equivalent to `engage`. While probing, `fn/<sym>/state` reads
`probing` and `fn/<sym>/timeout_left` counts down. `disengage <sym>`
during the probe window cancels the timer cleanly.

Use this when you believe a code path is idle on this host but want
kernel-side proof before breaking it.

### BPF mitigations via `engagebpf`

For mitigations that need to look at arguments (selective drop, not
full shutoff), use a BPF override.  Stock kernels gate
`bpf_override_return` behind `ALLOW_ERROR_INJECTION()` annotations,
so freshly-disclosed CVEs are usually unreachable.  `engagebpf` opens
that gate just long enough to load your program:

    clang -target bpf -O2 -c cve-31431.bpf.c -o /tmp/cve-31431.bpf.o
    echo "engagebpf af_alg_sendmsg /tmp/cve-31431.bpf.o" \
        > /sys/kernel/security/killswitch/control

`engagebpf` takes a pre-compiled BPF ELF object (`.bpf.o`).  Compile
your source with `clang -target bpf` before passing it in — the
mitigation scripts under `mitigations/` show the exact invocation
each one uses (see e.g. `mitigations/cve-2025-21700.sh`).  Keeping
the compile step in userspace means the kernel module never shells
out to a multi-megabyte compiler and the host doesn't need clang
installed unless you're actually authoring new mitigations.

What that line does, end-to-end:

1. Killswitch engages an internal override on
   `within_error_injection_list` (the verifier's whitelist check) so
   it returns true for any address.
2. The kernel module runs `/usr/sbin/ks-bpf-load <bpf.o> <fn>` under
   `call_usermodehelper`, blocking the write until the helper exits.
3. The helper uses libbpf to open + load + attach the program, then
   pins the resulting link at `/sys/fs/bpf/killswitch/<fn>`.
4. The kernel module disengages the gate override.  The write returns
   the helper's exit code (0 on success, `-EIO` on any failure with
   the real reason in dmesg).

The BPF program persists in `/sys/fs/bpf/killswitch/<fn>`; the bypass
window does not.  Remove the pin (`rm -rf /sys/fs/bpf/killswitch/<fn>`)
to drop the mitigation.

The helper ships with the OOT module — `sudo make install` puts it
at `/usr/sbin/ks-bpf-load`.  Runtime dep: `libbpf` (`apt install
libbpf1` or equivalent).  The BPFFS mount is expected at
`/sys/fs/bpf`; the helper mounts it if absent.  Authoring a new
mitigation also needs `clang` + `libbpf-dev` on the build host
(but not at the host that runs `engagebpf`).

### Rejection

Engagement is rejected when:

- the symbol is unknown, in a non-traceable section, on the kprobe
  blacklist, or otherwise refused by `register_kprobe()` (the kprobe
  layer's error is logged and returned to userspace);
- the symbol is already engaged (`-EBUSY`);
- the caller lacks `CAP_SYS_ADMIN`;
- the kernel is in `lockdown=integrity`. Use the `engage=` module
  parameter at load time for boot-time mitigation under lockdown.

Every engage / disengage emits a `KERN_WARNING` line with the symbol,
return value, hit count (on disengage), and the operator's identity
(uid, audit loginuid, session id, comm).

## Boot-time engagement

`__setup()` boot parameters aren't available to modules, so use a
module parameter instead. Drop a file in `/etc/modprobe.d/`:

    # /etc/modprobe.d/killswitch.conf
    options killswitch engage=af_alg_sendmsg=-1,ksmbd_smb2_negotiate=-22

and ensure the module is loaded early:

    echo killswitch > /etc/modules-load.d/killswitch.conf

A copy of this file lives at `modprobe.d/killswitch.conf.example`.

## Selftest

    cd selftests
    make
    sudo modprobe killswitch
    sudo modprobe test_killswitch
    sudo ./killswitch_test.sh

The selftest engages a killswitch on `ks_test_vuln()` (provided by
`test_killswitch.ko`), confirms the override changed observable
behavior, then disengages. It also runs the bundled CVE-31431 and
CVE-43284 demonstrators against the running kernel (they skip
gracefully if the affected subsystems aren't reachable).

## Tainting

Loading the module sets `TAINT_OOT_MODULE` ('O'), as with any
out-of-tree module. The upstream in-tree variant adds a dedicated
`TAINT_KILLSWITCH` ('H'); the OOT module reuses `TAINT_OOT_MODULE`
because a new taint bit requires a kernel change.

Oops triage on an OOT-killswitched kernel: check
`/sys/kernel/security/killswitch/engaged` before further analysis —
the kernel is not running its source.

## DKMS

For fleet deployment that survives kernel upgrades:

    sudo cp -r . /usr/src/killswitch-0.1
    sudo dkms add -m killswitch -v 0.1
    sudo dkms build -m killswitch -v 0.1
    sudo dkms install -m killswitch -v 0.1

Under Secure Boot you'll need to sign the resulting modules with an
MOK-enrolled key; `dkms.conf` does not sign for you.

## Lockdown semantics

| Lockdown level | Runtime `engage` via `control` | Module-param `engage=` at load |
| --- | --- | --- |
| `none` | allowed (CAP\_SYS\_ADMIN) | allowed |
| `integrity` | refused (`-EPERM` from `LOCKDOWN_KPROBES`) | allowed (LSM not yet armed for early modprobe; same as the in-tree variant's cmdline path) |
| `confidentiality` | refused | refused |

This is the closest analogue to the in-tree behavior with
`LOCKDOWN_KILLSWITCH` (which only exists in the patched kernel).

## Differences from upstream `killswitch`

The two trees are kept deliberately small and close. See the header
comment in `ks_main.c` for the full list. The summary:

| Aspect | Upstream | OOT module |
| --- | --- | --- |
| Taint | `TAINT_KILLSWITCH` ('H') | `TAINT_OOT_MODULE` ('O') |
| Lockdown enum | `LOCKDOWN_KILLSWITCH` | `LOCKDOWN_KPROBES` |
| `override_function_with_return()` | kernel-provided | shipped per-arch in `arch/<arch>/error_inject.c` |
| Boot-time engage | `killswitch=` on the kernel cmdline | `engage=` module parameter |
| KUnit test suite | yes | no (selftests cover the same ground) |

## Layout

    ks_main.c                # main module
    arch/x86/error_inject.c  # ks_override_function_with_return for x86
    arch/arm64/error_inject.c
    test_killswitch.c        # debugfs target for the selftest
    selftests/               # standalone shell + C test harness
    Kbuild                   # multi-object module assembly
    Makefile                 # OOT wrapper
    dkms.conf                # DKMS recipe
    modprobe.d/              # example modprobe drop-in

## License

GPL-2.0. See `LICENSE`.
