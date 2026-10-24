/*
 * src/os/syscalls_min.h — Minimal PPC32 Linux syscall layer (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dispatches on r0 with arguments in r3..r8 (SPEC 2.3, E01): success
 * clears CR0.SO and leaves r3 = (uint32_t)ret; error sets CR0.SO and
 * leaves r3 = (uint32_t)(-ret). Unimplemented numbers return -ENOSYS
 * through the same error path. nip advances past sc on return; exit
 * and exit_group are terminal (see ppc32_syscall_min_is_exit).
 */

#ifndef PPC32_SYSCALLS_MIN_H
#define PPC32_SYSCALLS_MIN_H

#include <stdint.h>

#include "ppc32rt.h"

void ppc32_syscall_min(ppc32_ctx_t *ctx);
int ppc32_syscall_min_is_exit(uint32_t nr);

#endif /* PPC32_SYSCALLS_MIN_H */
