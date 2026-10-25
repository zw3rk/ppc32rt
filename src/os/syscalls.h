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

/* RC4 inline clone child (main.c): drive `child` to guest exit on the
 * calling host thread through the child's own engine loop (syscall
 * dispatch, fault/trap delivery, exit interception). Returns the guest
 * exit code (0..255), or a negative guest signal number when a
 * fault/trap goes undelivered (no installed handler). */
long ppc32_run_guest_child(ppc32_ctx_t *child);

#endif /* PPC32_SYSCALLS_H */
