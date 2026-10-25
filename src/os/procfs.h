/*
 * src/os/procfs.h — Synthetic /proc/self/... content builders for ppc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 5, lane L5a: serves /proc/self/{exe,maps,cmdline,stat,auxv}
 * from translator state (guest path, region table, guest argv, minimal
 * stat fields, the exact auxv bytes handed to the guest). exe keeps
 * symlink semantics: opens resolve to the guest executable, readlink
 * reports the guest path. syscalls.c routes /proc/self/... opens here
 * inside its existing sys_openat path and dispatches readlink(85) here.
 */

#ifndef PPC32RT_OS_PROCFS_H
#define PPC32RT_OS_PROCFS_H

#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"

/* procfs kinds matched by ppc32_procfs_kind (0 = not a synthetic path). */
enum {
    PPC32_PROCFS_NONE    = 0,
    PPC32_PROCFS_EXE     = 1,
    PPC32_PROCFS_MAPS    = 2,
    PPC32_PROCFS_CMDLINE = 3,
    PPC32_PROCFS_STAT    = 4,
    PPC32_PROCFS_AUXV    = 5
};

/* Classify a guest path: one of PPC32_PROCFS_* (NONE when the host
 * should serve it). Only the exact /proc/self/<name> spellings match. */
int ppc32_procfs_kind(const char *path);

/* Open a synthetic path: exe opens the guest executable read-only (via
 * the sysroot-aware loader helper); maps/cmdline/stat/auxv build their
 * content and serve it on a seekable anonymous fd. Returns the host fd,
 * or a negative errno on failure. */
int ppc32_procfs_open(ppc32_ctx_t *ctx, const char *path);

/* readlink(85) for the guest: /proc/self/exe reports the guest path
 * (truncated to bufsiz, no NUL, Linux semantics); other synthetic
 * paths are not symlinks (-EINVAL); anything else falls through to the
 * host readlink. Args are guest VAs; returns the placed byte count or
 * a negative errno. */
long ppc32_procfs_readlink(ppc32_ctx_t *ctx, uint32_t path_va,
    uint32_t buf_va, uint32_t bufsiz);

#endif /* PPC32RT_OS_PROCFS_H */
