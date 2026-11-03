/*
 * src/os/signals.h — PPC32 Linux signal subsystem interface (Phase 4, L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Serves the PPC32 rt_sigframe build/restore (SPEC 2.3, frozen
 * os/sigframe_ppc32.h, E04-verified 992 B mcontext) plus the rt_sigaction,
 * rt_sigprocmask, rt_sigpending, rt_sigreturn, and sigaltstack syscalls.
 * The Phase 2 syscall layer keeps its -ENOSYS stubs until the coordinator
 * wires ppc32_sig_syscall into the dispatch switch.
 *
 * Signal-safety: the delivery path (ppc32_sig_deliver_sync and
 * ppc32_sig_build_frame) uses only plain loads/stores, memcpy/memset, and
 * integer arithmetic — no allocation, no formatted I/O, no locks — so it
 * stays within the async-signal-safe subset even if invoked from a host
 * signal context. Guest FPR state is copied as opaque u64 bit patterns;
 * the host FP environment (FPCR/FPSCR, rounding mode) is never touched.
 *
 * Locking: the process-shared disposition table has its own spinlock,
 * outermost in the global order (selection may not touch guest memory
 * while held; syscall handlers snapshot inputs before writing outputs).
 */

#ifndef PPC32RT_OS_SIGNALS_H
#define PPC32RT_OS_SIGNALS_H

#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"

/* ---- Guest signal numbers (Linux arch/powerpc = asm-generic, _NSIG 64) ---- */
#define PPC32_SIGHUP 1U
#define PPC32_SIGINT 2U
#define PPC32_SIGQUIT 3U
#define PPC32_SIGILL 4U
#define PPC32_SIGTRAP 5U
#define PPC32_SIGABRT 6U
#define PPC32_SIGBUS 7U
#define PPC32_SIGFPE 8U
#define PPC32_SIGKILL 9U
#define PPC32_SIGUSR1 10U
#define PPC32_SIGSEGV 11U
#define PPC32_SIGUSR2 12U
#define PPC32_SIGPIPE 13U
#define PPC32_SIGALRM 14U
#define PPC32_SIGTERM 15U
#define PPC32_SIGSTKFLT 16U
#define PPC32_SIGCHLD 17U
#define PPC32_SIGCONT 18U
#define PPC32_SIGSTOP 19U
#define PPC32_SIGTSTP 20U
#define PPC32_SIGTTIN 21U
#define PPC32_SIGTTOU 22U
#define PPC32_SIGURG 23U
#define PPC32_SIGXCPU 24U
#define PPC32_SIGXFSZ 25U
#define PPC32_SIGVTALRM 26U
#define PPC32_SIGPROF 27U
#define PPC32_SIGWINCH 28U
#define PPC32_SIGIO 29U
#define PPC32_SIGPWR 30U
#define PPC32_SIGSYS 31U
#define PPC32_NSIG 64U
#define PPC32_SIGRTMIN 32U
#define PPC32_SIGRTMAX 64U

/* Special dispositions. */
#define PPC32_SIG_DFL 0U
#define PPC32_SIG_IGN 1U

/* ---- si_code defaults for synchronous delivery (asm-generic/siginfo.h) ---- */
#define PPC32_SI_USER 0
#define PPC32_SI_KERNEL 0x80
#define PPC32_SEGV_MAPERR 1
#define PPC32_SEGV_ACCERR 2
#define PPC32_BUS_ADRALN 1
#define PPC32_ILL_ILLOPC 1
#define PPC32_FPE_INTDIV 1
#define PPC32_TRAP_BRKPT 1

/* ---- sa_flags (asm-generic/signal.h; powerpc follows the generic set) ---- */
#define PPC32_SA_NOCLDSTOP 0x00000001U
#define PPC32_SA_NOCLDWAIT 0x00000002U
#define PPC32_SA_SIGINFO 0x00000004U
#define PPC32_SA_RESTORER 0x04000000U
#define PPC32_SA_ONSTACK 0x08000000U
#define PPC32_SA_RESTART 0x10000000U
#define PPC32_SA_NODEFER 0x40000000U
#define PPC32_SA_RESETHAND 0x80000000U

/* ---- sigprocmask how values ---- */
#define PPC32_SIG_BLOCK 0U
#define PPC32_SIG_UNBLOCK 1U
#define PPC32_SIG_SETMASK 2U

/* ---- sigaltstack (guest stack_t is 12 B: u32 sp, i32 flags, u32 size) ---- */
#define PPC32_SS_ONSTACK 1U
#define PPC32_SS_DISABLE 2U
#define PPC32_MINSIGSTKSZ 2048U
#define PPC32_SIGSTACK_SIZE 12U

/* ---- Guest struct sigaction (rt, 20 B) and kernel sigset (8 B) ---- */
#define PPC32_SIGACTION_SIZE 20U
#define PPC32_SIGSET_SIZE 8U

/* ---- PowerPC exception vector offsets recorded in mc_gregs[trap] ---- */
#define PPC32_TRAP_DSI 0x300U
#define PPC32_TRAP_PROGRAM 0x700U
#define PPC32_TRAP_TRACE 0xD00U

/* ---- Synthetic vDSO sigtramp (SPEC 1.1): lr points here without SA_RESTORER.
 * Phase 5 fills real `li r0,173; sc` code; L4a only needs the address. ---- */
#define PPC32_SIGTRAMP_RT (PPC32_SIGTRAMP_BASE + 0x20U)

/* Guest disposition table entry (process-shared, mirrors kernel sighand). */
typedef struct ppc32_sigact {
    uint32_t handler;  /* PPC32_SIG_DFL / PPC32_SIG_IGN / guest code VA */
    uint32_t flags;    /* PPC32_SA_* */
    uint32_t restorer; /* sa_restorer VA (used with PPC32_SA_RESTORER) */
    uint32_t mask[2];  /* 64-bit kernel mask, word 0 = signals 1..32 */
} ppc32_sigact_t;

/* Reset every disposition to SIG_DFL (test setup). */
void ppc32_sig_reset(void);

/* P32-R6-6: deliver the first pending unblocked catchable signal (the
 * DBT dispatcher bail and the syscall tails call this so the frame
 * captures the boundary nip). */
void ppc32_sig_pump_pending(ppc32_ctx_t *ctx);

/* execve reset: caught dispositions return to SIG_DFL, ignored stay
 * ignored; the calling thread's mask and pending set are preserved. */
void ppc32_sig_reset_exec(void);

/* Fork coordination for the ppc32_proc_fork protocol (prepare holds the
 * disposition lock across the snapshot; parent releases; the child
 * drops the inherited locked value). */
void ppc32_sig_fork_prepare(void);
void ppc32_sig_fork_parent(void);
void ppc32_sig_fork_child(void);

/* Direct table access (used by the L4c fixture and future clone/exec). */
int ppc32_sigaction_get(int sig, ppc32_sigact_t *out);
int ppc32_sigaction_set_raw(int sig, const ppc32_sigact_t *act);

/* SIGKILL/SIGSTOP can never be caught, blocked, or ignored. */
int ppc32_sig_is_catchable(int sig);

/*
 * Syscall dispatch hook for the Phase 2 layer. Handles rt_sigaction,
 * rt_sigprocmask, rt_sigpending, rt_sigreturn, and sigaltstack; returns 1
 * with *out_ret set to the kernel-style long (negative errno on error) or
 * 0 when nr is not a signal number (caller keeps -ENOSYS).
 *
 * rt_sigreturn restores nip directly from the frame at r1, so after a
 * handled rt_sigreturn the caller must NOT advance nip past the sc
 * (see ppc32_sig_nr_no_advance).
 */
int ppc32_sig_syscall(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, long *out_ret);
int ppc32_sig_nr_no_advance(uint32_t nr);

/*
 * Build the 1536 B rt_sigframe for sig on the guest stack (or altstack
 * with SA_ONSTACK), fill siginfo/ucontext/mcontext from ctx, then install
 * the handler entry state (r1 = frame, r3 = sig, r4 = siginfo VA,
 * r5 = ucontext VA, nip = handler, lr = restorer/trampoline) and the new
 * blocked mask. trap/dar/dsisr land in mc_gregs. Returns 0 or -EFAULT /
 * -ENOMEM (bad stack range); *out_frame_va receives the frame address.
 */
int ppc32_sig_build_frame(ppc32_ctx_t *ctx, int sig,
    const ppc32_sigact_t *act, int code, uint32_t fault_addr, uint32_t trap,
    uint32_t dsisr, uint32_t *out_frame_va);

/* Restore live state (gpr, nip, ctr, lr, xer, cr, fpscr, fpr, SPE overlay,
 * blocked mask) from the frame at frame_va. Returns 0 or -EFAULT. */
int ppc32_sig_restore_frame(ppc32_ctx_t *ctx, uint32_t frame_va);

/*
 * Synchronous delivery (SIGSEGV/SIGILL/SIGFPE/SIGBUS/SIGTRAP from a fault
 * or trap insn). The guest PC stays in nip (copied into mc nip); the
 * lwarx/stwcx. reservation is cleared. code == 0 selects the per-signal
 * default si_code. fault_addr is the faulting VA (dar/si_addr); pass
 * ctx->nip for trap-class signals. is_store != 0 marks a store fault.
 * Returns 0 (handler entered), 1 (SIG_IGN: re-execute, may re-fault like
 * native), or a negative errno (SIG_DFL or bad stack: fatal to the guest).
 */
long ppc32_sig_deliver_sync(ppc32_ctx_t *ctx, int sig, int code,
    uint32_t fault_addr, uint32_t is_store);
/* kill(2) self-delivery fast path (see signals.c): 1 when fully applied
 * (handler entered, no tail advance), 0 with *out_ret for the tail. */
int ppc32_sig_kill(ppc32_ctx_t *ctx, uint32_t pid_va, uint32_t sig,
    long *out_ret);
/* pid-directed signal dispatch for the generic switch (kill, gettid,
 * tkill, tgkill): 1 when fully applied inside (no tail advance), 0
 * with *out_ret set for the E01 + nip-advance tail. */
int ppc32_sig_pid_nr(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, long *out_ret);

#endif /* PPC32RT_OS_SIGNALS_H */
