/*
 * src/rt32/ppc32_host.c — Optional /dev/a32host handshake & capability detection
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from i686rt/src/rt32/rt32_host.c (itself vendored
 * from a32rt/src/host.c @ d84feb3, SPEC D13): mechanical renames, retyped
 * on ppc32_ctx_t; the a32h_* handshake itself is unchanged (D14).
 */

#define _GNU_SOURCE
#include "ppc32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* --no-host latch (Wave 1 CLI): the frozen context carries no slot
 * for it, so it lives next to the probe it gates. Set once from
 * main.c CLI parsing before the first probe. */
static bool g_no_host = false;

void ppc32_host_set_no_host(bool skip)
{
    g_no_host = skip;
}

void ppc32_host_probe(ppc32_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    memset(&ctx->host_info, 0, sizeof(ctx->host_info));
    ctx->has_host_info = false;

    if (g_no_host) {
        return;
    }

    const char *host_env = getenv("PPC32RT_HOST");
    if (host_env && strcmp(host_env, "none") == 0) {
        return;
    }

    int fd = open(A32H_DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0 && (errno == EACCES || errno == EPERM || errno == EROFS)) {
        fd = open(A32H_DEV_PATH, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return;
    }

    a32h_info_t info = {0};
    if (syscall(SYS_ioctl, fd, (unsigned long)A32H_GET_INFO, &info) == 0 &&
        info.abi_major == A32H_ABI_MAJOR) {
        ctx->host_info = info;
        ctx->has_host_info = true;
    }

    close(fd);
}
