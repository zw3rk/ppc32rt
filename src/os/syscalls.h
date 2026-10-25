/*
 * src/os/syscalls.h — Full static-libc PPC32 Linux syscall layer (Phase 2, L2a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dispatches on r0 with arguments in r3..r8 (SPEC 2.3, E01): success
 * clears CR0.SO and leaves r3 = (uint32_t)ret; error sets CR0.SO and
 * leaves r3 = (uint32_t)(-ret). Unimplemented numbers take the -ENOSYS
 * error path. nip advances past sc on return; exit and exit_group are
 * terminal (see ppc32_syscall_is_exit). Struct arguments are converted
 * with the big-endian-safe helpers in os/convert.h.
 *
 * Coverage: exit, exit_group, read, write, readv, writev, open, openat,
 * close, lseek, llseek, brk, mmap, mmap2, munmap, mprotect, uname, stat,
 * lstat, fstat, stat64, lstat64, fstat64, clock_gettime, gettimeofday,
 * getrandom, futex (threads layer), fcntl, ioctl (allowlist),
 * set_tid_address (threads layer), getpid, kill (self-delivery),
 * clone (inline child, see ppc32_run_guest_child), rt_sigaction,
 * rt_sigprocmask, rt_sigpending, rt_sigreturn, sigaltstack (signals
 * layer), fork/vfork/execve/wait4/waitpid/waitid/pipe/pipe2/dup/dup2
 * (proc layer). Old-style sigaction/sigprocmask stay -ENOSYS. Replaces
 * syscalls_min callers; syscalls_min.c itself is untouched.
 */

#ifndef PPC32_SYSCALLS_H
#define PPC32_SYSCALLS_H

#include <stdint.h>

#include "ppc32rt.h"

void ppc32_syscall(ppc32_ctx_t *ctx);
int ppc32_syscall_is_exit(uint32_t nr);

/* Longest guest path buffer shared by the file layer. */
#define PPC32_PATH_MAX 4096U

/* RC5 file layer (syscalls_file.c): openat plus the PPC/host O_*
 * translation (LARGEFILE 0200000 and DIRECT 0400000 trade places;
 * all other bits pass). */
long sys_openat(ppc32_ctx_t *ctx, uint32_t dfd_va, uint32_t path_va,
    uint32_t flags, uint32_t mode);
uint32_t ppc32_open_flags_ppc2host(uint32_t flags);
uint32_t ppc32_open_flags_host2ppc(uint32_t flags);
/* Moved here from syscalls.c (RC-H): fcntl dispatch including the
 * 64-bit lock commands 12/13/14 (struct flock64). */
long sys_fcntl(ppc32_ctx_t *ctx, uint32_t fd, uint32_t cmd, uint32_t arg);

/* RC5 dynamic-loading layer (syscalls_dyn.c): access/statx/getcwd/
 * rlimit/dents64/ids. Returns 1 with `*out_ret` set when owned. */
int ppc32_dyn_dispatch(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
    long *out_ret);

/* RC4 inline clone child (main.c): drive `child` to guest exit on the
 * calling host thread through the child's own engine loop (syscall
 * dispatch, fault/trap delivery, exit interception). Returns the guest
 * exit code (0..255), or a negative guest signal number when a
 * fault/trap goes undelivered (no installed handler). */
long ppc32_run_guest_child(ppc32_ctx_t *child);

#endif /* PPC32_SYSCALLS_H */
