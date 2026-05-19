// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Tiny userspace probe used by tests/in_vm.sh to read the exact
 * errno a write() call returns.  Busybox `echo > path` only tells us
 * whether the write succeeded, not whether the kernel returned the
 * specific errno (e.g. ESRCH) the BPF override is supposed to inject.
 *
 *   errno_check <path> <bytes>
 *
 * Prints "ok <n>\n" on success, "errno=<N>\n" on failure, and exits
 * 0 / non-zero respectively.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int fd;
	ssize_t n;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <path> <bytes>\n", argv[0]);
		return 2;
	}
	fd = open(argv[1], O_WRONLY);
	if (fd < 0) {
		printf("open errno=%d\n", errno);
		return 2;
	}
	n = write(fd, argv[2], strlen(argv[2]));
	if (n < 0) {
		printf("errno=%d\n", errno);
		close(fd);
		return 1;
	}
	printf("ok %zd\n", n);
	close(fd);
	return 0;
}
