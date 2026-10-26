/*
 * src/os/hostfault.c — host SIGSEGV/SIGBUS translation for engine memory
 * accesses.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mirrors mips32rt/src/os/hostfault.c, simplified: ppc32rt needs no
 * code-pool range check because the discriminator is the data address
 * (si_addr), not the faulting PC. Interpreter faults land inside
 * interp_step itself, so a PC-in-pool test would misroute them; a data
 * address inside the reserved guest window can only come from a guest
 * access (the translator's own mappings live outside the window, or
 * the window reservation would have failed). Per-thread arm state via
 * __thread: guest execution always runs on the calling host thread,
 * and fork children re-arm from zero (disarmed) after proc_child_refresh.
 *
 * The handler only records and longjmps; all guest work happens back
 * in normal C context at the checkpoint in ppc32_hostfault_enter.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/hostfault.h"
#include "vm/vm32.h"

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os/signals.h"

/* Host signal numbers as seen in si_signo (Linux/aarch64: BUS 10, SEGV 11)
 * are preserved onto ctx->fault_signo as the GUEST number (SIGBUS 7 /
 * SIGSEGV 11) so deliver_sync raises the right synchronous signal. */
#define HF_SIGSEGV 11
#define HF_SIGBUS 10
#define HF_WINDOW_SIZE 0x100000000ULL

static __thread int hf_armed;
static __thread ppc32_ctx_t *hf_ctx;
static __thread int hf_signo;
static __thread void *hf_addr;
static __thread sigjmp_buf hf_jb;
static int hf_installed;

static void hf_chain(int signo, siginfo_t *si)
{
    /* Not ours: restore the default and re-raise so the process dies
     * with the original signal (SA_NODEFER below keeps it unblocked). */
    struct sigaction dfl;

    (void)si;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    (void)sigemptyset(&dfl.sa_mask);
    (void)sigaction(signo, &dfl, NULL);
    (void)raise(signo);
    _Exit(128 + (signo & 0x7F)); /* unreachable if raise worked */
}

static void hf_handler(int signo, siginfo_t *si, void *uc)
{
    uintptr_t addr;
    uint64_t guest_base;

    (void)uc;
    if (hf_armed == 0 || hf_ctx == NULL || si == NULL) {
        hf_chain(signo, si);
        return;
    }
    addr = (uintptr_t)si->si_addr;
    guest_base = hf_ctx->guest_base;
    if (hf_ctx->vm_ready == false || addr < (uintptr_t)guest_base ||
        (uint64_t)(addr - (uintptr_t)guest_base) >= HF_WINDOW_SIZE) {
        hf_chain(signo, si);
        return;
    }
    hf_signo = (signo == SIGBUS) ? HF_SIGBUS : HF_SIGSEGV;
    hf_addr = si->si_addr;
    hf_armed = 0;
    siglongjmp(hf_jb, 1);
}

void ppc32_hostfault_install(void)
{
    struct sigaction sa;

    if (hf_installed != 0) {
        return;
    }
    hf_installed = 1;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = hf_handler;
    (void)sigemptyset(&sa.sa_mask);
    /* NODEFER: re-raise in hf_chain must deliver immediately; the armed
     * window is always exited via longjmp or disarm, never by return. */
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
}

int ppc32_hostfault_run(ppc32_ctx_t *ctx, ppc32_hostfault_fn_t run)
{
    if (sigsetjmp(hf_jb, 0) != 0) {
        /* Revived from a host fault inside the engine. hf_ctx (written
         * to TLS before the setjmp, never a register temporary) names
         * the armed context; the ctx parameter may be stale after the
         * longjmp, so it is not touched. Mirrors the fault() helper in
         * interp/interp.h: record EA, stop, drop the reservation. */
        ppc32_ctx_t *rc = hf_ctx;
        uint64_t guest_base;
        int signo = hf_signo;

        hf_armed = 0;
        if (rc == NULL) {
            _Exit(128 + (signo & 0x7F));
        }
        (void)ctx;
        guest_base = rc->guest_base;
        rc->fault_addr =
            (uint32_t)((uintptr_t)hf_addr - (uintptr_t)guest_base);
        rc->fault_signo = (uint32_t)((signo == HF_SIGBUS) ?
            PPC32_SIGBUS : PPC32_SIGSEGV);
        /* RC-U3-r4: a truncated-file page traps as SIGBUS even when the
         * host delivered SIGSEGV (PROT_NONE tail), matching Linux
         * beyond-EOF semantics for both interp and DBT faults. */
        if (vm32_page_is_eof_trap(rc->fault_addr)) {
            rc->fault_signo = (uint32_t)PPC32_SIGBUS;
        }
        rc->exit_reason = PPC32_EXIT_FAULT;
        rc->res_valid = 0;
        rc->reservation_epoch++;
        return 1;
    }
    hf_ctx = ctx;
    hf_armed = 1;
    run(ctx);
    hf_armed = 0;
    return 0;
}
