/*
 * src/os/proc.h — Process-lifecycle syscall layer for ppc32rt (Phase 4, L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns the PPC32 process-lifecycle calls (SPEC sections 1.1 and 2.3):
 * fork(2), vfork(190), execve(11) (re-enter ELF admission with profile
 * re-detect), wait4(114) (+ waitpid(7) alias), waitid, pipe2 (+ pipe(42)
 * alias), dup2(63).
 *
 * Contract: every ppc32_proc_* handler returns a kernel-style long
 * (non-negative value, or a negative errno). Handlers never touch
 * gpr[3]/CR0.SO/nip themselves, except ppc32_proc_execve, which on
 * success reparks nip/sp and the register file on the new image (the
 * caller must not advance nip past sc afterwards). ppc32_proc_return
 * applies the E01 return convention (CR0.SO + r3) and advances nip;
 * ppc32_proc_dispatch handles one sc by number (1 = owned, 0 = not
 * owned) so a future syscalls.c wiring is a single call.
 */

#ifndef PPC32RT_OS_PROC_H
#define PPC32RT_OS_PROC_H

#include <stdint.h>

#include "ppc32rt.h"

/* Numbers absent from the frozen os/syscall_nr.h (arch/powerpc
 * syscall.tbl / uapi unistd_32.h): waitid 272, pipe2 317. Guarded so a
 * future header update wins. */
#ifndef PPC32_NR_WAITID
#define PPC32_NR_WAITID 272U
#endif
#ifndef PPC32_NR_PIPE2
#define PPC32_NR_PIPE2 317U
#endif

/* fork(2): host fork(); the child gets a per-process identity refresh.
 * Returns the child pid to the parent, 0 in the child. */
long ppc32_proc_fork(ppc32_ctx_t *ctx);

/* vfork(190): same observable result as fork (no address-space sharing
 * fast path; the child is expected to execve or exit promptly). */
long ppc32_proc_vfork(ppc32_ctx_t *ctx);

/* execve(11): replace the image. On success returns 0 with nip/sp and
 * the register file reparked on the new entry point (SPEC 1.1 ELF
 * admission: ELFCLASS32/ELFDATA2MSB/EM_PPC, PT_INTERP, fresh stack +
 * auxv, profile re-detected unless --profile/PPC32RT_PROFILE forced
 * it). Returns a negative errno on failure with ctx untouched. */
long ppc32_proc_execve(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t argv_va,
    uint32_t envp_va);

/* wait4(114): pid (or -1 any, <-1 pgroup, 0 group), BE status word,
 * options passthrough, BE struct rusage (NULL/0 skips). */
long ppc32_proc_wait4(ppc32_ctx_t *ctx, uint32_t pid_va, uint32_t status_va,
    uint32_t options, uint32_t rusage_va);

/* waitid: idtype (P_ALL 0, P_PID 1, P_PGID 2), id, 128 B BE siginfo
 * out, options passthrough. WNOWAIT is rejected with -EINVAL (the
 * zombie must stay queued; the translator keeps no siginfo queue). */
long ppc32_proc_waitid(ppc32_ctx_t *ctx, uint32_t idtype, uint32_t id,
    uint32_t infop_va, uint32_t options);

/* pipe2: write two BE fds at fds_va; only O_CLOEXEC (02000000) is
 * accepted in flags, anything else is -EINVAL. */
long ppc32_proc_pipe2(ppc32_ctx_t *ctx, uint32_t fds_va, uint32_t flags);

/* pipe(42): pipe2 with flags 0. */
long ppc32_proc_pipe(ppc32_ctx_t *ctx, uint32_t fds_va);

/* dup2(63): oldfd onto newfd; oldfd == newfd returns newfd after an
 * EBADF validity check, matching Linux. */
long ppc32_proc_dup2(uint32_t oldfd, uint32_t newfd);

/* Profile re-detect after execve: explicit --profile/PPC32RT_PROFILE
 * (ctx->profile already 0/1) wins; otherwise scan the new text for a
 * major-opcode-4 (SPE) word and set profile + is_spe. */
void ppc32_proc_redetect_profile(ppc32_ctx_t *ctx, uint32_t text_start,
    uint32_t text_end);

/* Apply the E01 convention (CR0.SO + r3) and advance nip past sc. */
void ppc32_proc_return(ppc32_ctx_t *ctx, long ret);

/* Dispatch one sc by number; 1 = owned and fully applied (return
 * convention + nip, except execve success which reparks nip), 0 = not
 * owned by this module. */
int ppc32_proc_dispatch(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

#endif /* PPC32RT_OS_PROC_H */
