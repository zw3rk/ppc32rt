/*
 * src/os/syscalls_min.c — Minimal PPC32 Linux syscall layer (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thin alias over the maintained dispatcher (os/syscalls.c): the old
 * unchecked per-call switch lived here (R5-10) and is gone, so syscall
 * handling exists in exactly one place.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/syscalls_min.h"

#include <stdint.h>

#include "os/syscall_nr.h"
#include "os/syscalls.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

int ppc32_syscall_min_is_exit(uint32_t nr)
{
    return (nr == PPC32_NR_EXIT || nr == PPC32_NR_EXIT_GROUP) ? 1 : 0;
}

/* R5-10: delegate to the maintained dispatcher; the duplicate
 * unchecked handling that used to live here is removed. */
void ppc32_syscall_min(ppc32_ctx_t *ctx)
{
    ppc32_syscall(ctx);
}
