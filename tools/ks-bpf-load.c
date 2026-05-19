// SPDX-License-Identifier: GPL-2.0
/*
 * ks-bpf-load: userspace helper invoked by killswitch's engagebpf verb.
 *
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Loads + attaches + pins a pre-compiled BPF program (.bpf.o) that
 * targets an arbitrary kernel function.  The kernel module engages
 * the verifier's ALLOW_ERROR_INJECTION gate around the call to this
 * helper, so the load passes even when the target isn't in the
 * whitelist.  Compile-from-source is the operator's job (clang
 * -target bpf in their mitigation script) — the helper deliberately
 * does NOT run clang, which keeps the kernel module's responsibility
 * narrow and means the host doesn't need a compiler installed.
 *
 * Synopsis:
 *   ks-bpf-load <bpf.o> <kernel_function>
 *
 * On success, pins the resulting BPF link at /sys/fs/bpf/killswitch/<fn>
 * and exits 0.  Any failure produces a diagnostic on stderr (piped
 * to /dev/kmsg so dmesg captures it) and a non-zero exit code.
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BPFFS_ROOT		"/sys/fs/bpf"
#define KS_PIN_BASE		BPFFS_ROOT "/killswitch"

static int libbpf_log_cb(enum libbpf_print_level level,
			 const char *fmt, va_list ap)
{
	/* Suppress libbpf's verbose INFO/DEBUG chatter — when stderr is
	 * redirected to /dev/kmsg (call_usermodehelper case) the
	 * kernel's printk ratelimiter eats most of it anyway, and the
	 * volume hides the actual error.  Keep WARN and above. */
	if (level > LIBBPF_WARN)
		return 0;
	vfprintf(stderr, fmt, ap);
	return 0;
}

static int ensure_bpffs(void)
{
	struct stat st;
	int rc;

	if (stat(BPFFS_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
		/* Already a dir.  If it's not actually bpffs, the mount below
		 * is a no-op (mount returns EBUSY when bpffs is already there
		 * or fails harmlessly when it isn't and we silently continue —
		 * libbpf will produce a useful error later if pinning fails). */
		rc = mount("bpffs", BPFFS_ROOT, "bpf", 0, NULL);
		if (rc && errno != EBUSY)
			fprintf(stderr,
				"ks-bpf-load: mount %s failed (errno=%d), continuing\n",
				BPFFS_ROOT, errno);
		return 0;
	}
	if (mkdir(BPFFS_ROOT, 0755) && errno != EEXIST) {
		fprintf(stderr, "ks-bpf-load: mkdir %s: %s\n",
			BPFFS_ROOT, strerror(errno));
		return -1;
	}
	if (mount("bpffs", BPFFS_ROOT, "bpf", 0, NULL)) {
		fprintf(stderr, "ks-bpf-load: mount %s: %s\n",
			BPFFS_ROOT, strerror(errno));
		return -1;
	}
	return 0;
}

static int ensure_pin_base(void)
{
	if (mkdir(KS_PIN_BASE, 0755) && errno != EEXIST) {
		fprintf(stderr, "ks-bpf-load: mkdir %s: %s\n",
			KS_PIN_BASE, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Read the first four bytes of `path` and return non-zero if it
 * looks like an ELF binary.  Used to fail fast when an operator
 * accidentally passes BPF source where the helper expects an
 * already-compiled .bpf.o.
 */
static int file_is_elf(const char *path)
{
	unsigned char magic[4];
	int fd, rc;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	rc = read(fd, magic, sizeof(magic));
	close(fd);
	if (rc != (int)sizeof(magic))
		return 0;
	return magic[0] == 0x7f && magic[1] == 'E' &&
	       magic[2] == 'L' && magic[3] == 'F';
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	char pin_path[PATH_MAX];
	const char *bpf_path, *fn;
	int progs_attached = 0;
	int err, ret = 1;
	int kmsg_fd;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <bpf.o> <kernel_function>\n",
			argv[0]);
		return 2;
	}
	bpf_path = argv[1];
	fn = argv[2];

	/* call_usermodehelper discards stdout/stderr.  Redirect both to
	 * /dev/kmsg so diagnostics show up in dmesg — that's the only
	 * trail the operator gets after the fact. */
	kmsg_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (kmsg_fd >= 0) {
		dup2(kmsg_fd, 1);
		dup2(kmsg_fd, 2);
		close(kmsg_fd);
	}

	libbpf_set_print(libbpf_log_cb);

	if (ensure_bpffs() < 0)
		return 1;
	if (ensure_pin_base() < 0)
		return 1;

	snprintf(pin_path, sizeof(pin_path), "%s/%s", KS_PIN_BASE, fn);
	if (access(pin_path, F_OK) == 0) {
		fprintf(stderr, "ks-bpf-load: pin path %s already exists; "
			"remove it before re-engaging\n", pin_path);
		return 1;
	}

	switch (file_is_elf(bpf_path)) {
	case -1:
		fprintf(stderr, "ks-bpf-load: cannot read %s: %s\n",
			bpf_path, strerror(errno));
		return 1;
	case 0:
		fprintf(stderr, "ks-bpf-load: %s is not an ELF .bpf.o; "
			"compile your BPF source with clang -target bpf before "
			"passing it to engagebpf\n", bpf_path);
		return 1;
	}

	obj = bpf_object__open_file(bpf_path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "ks-bpf-load: open_file(%s): %s\n",
			bpf_path, strerror(-err));
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ks-bpf-load: load(%s): %s\n",
			bpf_path, strerror(-err));
		goto out;
	}

	/* Attach every program in the object as a kprobe on the named
	 * function, and pin the resulting link.  The pin is what keeps
	 * the kprobe attached past helper exit — without it, the link's
	 * fd closes when we return, libbpf destroys the link, and the
	 * kprobe detaches.
	 *
	 * Pin layout, flat under KS_PIN_BASE so libbpf's make_parent_dir
	 * (which mkdir(0700)'s the parent) gets a known-bpffs parent:
	 *
	 *   /sys/fs/bpf/killswitch/<fn>           (link pin, single-program case)
	 *   /sys/fs/bpf/killswitch/<fn>__<prog>   (multi-program case)
	 */
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link;
		char link_pin[PATH_MAX];

		link = bpf_program__attach_kprobe(prog, false /* retprobe */, fn);
		err = libbpf_get_error(link);
		if (err) {
			fprintf(stderr, "ks-bpf-load: attach_kprobe(%s, %s): %s\n",
				bpf_program__name(prog), fn, strerror(-err));
			goto out;
		}

		if (progs_attached == 0)
			snprintf(link_pin, sizeof(link_pin), "%s/%s",
				 KS_PIN_BASE, fn);
		else
			snprintf(link_pin, sizeof(link_pin), "%s/%s__%s",
				 KS_PIN_BASE, fn, bpf_program__name(prog));

		err = bpf_link__pin(link, link_pin);
		if (err) {
			fprintf(stderr, "ks-bpf-load: pin_link(%s): %s\n",
				link_pin, strerror(-err));
			bpf_link__destroy(link);
			goto out;
		}
		/* Deliberately do NOT bpf_link__destroy(link) here: destroy
		 * detaches the link.  The pin in BPFFS holds a kernel-side
		 * ref that keeps the kprobe attached after the helper exits;
		 * the userspace bpf_link struct will be freed by exit(). */
		progs_attached++;
	}

	if (progs_attached == 0) {
		fprintf(stderr, "ks-bpf-load: %s contains no programs\n",
			bpf_path);
		goto out;
	}

	/* Recompute the primary pin path the test greps for. */
	snprintf(pin_path, sizeof(pin_path), "%s/%s", KS_PIN_BASE, fn);

	/* This is the line the in-VM test greps for. */
	printf("ks-bpf-load: loaded %d program(s), pinned at %s\n",
	       progs_attached, pin_path);
	ret = 0;

out:
	if (obj)
		bpf_object__close(obj);
	return ret;
}
