/*
 * src/os/signals.c — PPC32 Linux signal subsystem (Phase 4, L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Builds and restores the PPC32 rt_sigframe (SPEC 2.3, frozen
 * os/sigframe_ppc32.h, E04-verified 992 B mcontext: mc_gregs[48]@0x0,
 * mc_fregs[33]@0xc0, pad@0x1c8, mc_vregs[528]@0x1d0 with the SPE
 * evr[32]+acc+spefscr overlay) and serves rt_sigaction, rt_sigprocmask,
 * rt_sigpending, rt_sigreturn, and sigaltstack for the syscall layer.
 *
 * Delivery follows arch/powerpc/kernel/signal_32.c (RT path): the frame is
 * 16-byte aligned on the guest stack (or the altstack with SA_ONSTACK),
 * r1 points at the frame, r3/r4/r5 carry (sig, &siginfo, &ucontext),
 * nip enters the handler, lr returns via sa_restorer or the synthetic
 * vDSO trampoline, and the blocked mask becomes old | act | sig (minus
 * SIGKILL/SIGSTOP, plus SA_NODEFER/SA_RESETHAND handling). The faulting
 * guest PC is preserved in nip (and mirrored into mc nip); the
 * lwarx/stwcx. reservation is cleared on delivery (SPEC 2.2).
 *
 * Guest memory is big-endian: every multi-byte frame field goes through
 * the local BE helpers below. Char/byte payloads (siginfo padding, vregs
 * tail, abigap) are zeroed, never copied from the host stack.
 */

#include "os/signals.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "os/sigframe_ppc32.h"
#include "os/syscall_nr.h"

/* siginfo/ucontext geometry inside struct rt_sigframe (frozen header). */
#define SIGINFO_SIZE 128U
#define SIGINFO_OFF 0x80U
#define UCONTEXT_OFF 0x80U
#define ABIGAP_OFF 0x520U

/* siginfo word offsets (Linux struct siginfo: signo, errno, code, addr). */
#define SI_SIGNO_OFF 0U
#define SI_ERRNO_OFF 4U
#define SI_CODE_OFF 8U
#define SI_ADDR_OFF 12U

/* DSISR class bits for mc dsisr on a DSI fault (informational: only the
 * store/load class is modeled, matching the is_store delivery argument). */
#define DSISR_STORE_CLASS 0x02000000U
#define DSISR_LOAD_CLASS 0x40000000U

/* Process-shared disposition table (kernel sighand equivalent; per-thread
 * state — the blocked mask — already lives in ppc32_ctx_t for L4b). */
static ppc32_sigact_t sig_actions[PPC32_NSIG + 1U];
static int sig_installed[PPC32_NSIG + 1U];

/* ---- Frozen-layout compile checks (SPEC 2.3) ---- */
_Static_assert(PPC32_SIGACTION_SIZE == 20U, "guest sigaction must be 20 B");
_Static_assert(PPC32_SIGSTACK_SIZE == 12U, "guest stack_t must be 12 B");
_Static_assert(offsetof(ppc32_mcontext_t, mc_gregs) == 0x0U, "mc_gregs@0x0");
_Static_assert(offsetof(ppc32_mcontext_t, mc_fregs) == 0xC0U, "mc_fregs@0xc0");
_Static_assert(offsetof(ppc32_mcontext_t, mc_pad) == 0x1C8U, "pad@0x1c8");
_Static_assert(offsetof(ppc32_mcontext_t, mc_vregs) == 0x1D0U, "vregs@0x1d0");
_Static_assert(offsetof(ppc32_ucontext_t, uc_regs) == 0x30U, "uc_regs@0x30");
_Static_assert(offsetof(ppc32_ucontext_t, uc_sigmask) == 0x34U, "mask@0x34");
_Static_assert(offsetof(ppc32_ucontext_t, uc_mcontext) == 0xC0U, "mc@0xc0");
_Static_assert(UCONTEXT_OFF == 0x80U, "ucontext@0x80");
_Static_assert(ABIGAP_OFF == 0x520U, "abigap@0x520");

/* ---- Local guest-memory helpers (BE scalars; byte streams raw) ----
 * convert.h is deliberately not included: its ppc32_stat_t collides with
 * the frozen sigframe header, so the two BE/load helpers needed here are
 * restated on top of ppc32_guest_ptr (same window semantics). */

static int sig_range_ok(uint32_t va, size_t len)
{
    uint64_t end;

    if (len == 0U) {
        return 1;
    }
    if (va < PPC32_LOW_GUARD_SIZE) {
        return 0;
    }
    end = (uint64_t)va + (uint64_t)len;
    if (end > 0x100000000ULL) {
        return 0;
    }
    return 1;
}

static uint32_t sig_ld32(const ppc32_ctx_t *ctx, uint32_t va)
{
    uint32_t v;

    memcpy(&v, ppc32_guest_ptr(ctx, va), sizeof v);
    return ppc32_be32(v);
}

static uint64_t sig_ld64(const ppc32_ctx_t *ctx, uint32_t va)
{
    uint64_t v;

    memcpy(&v, ppc32_guest_ptr(ctx, va), sizeof v);
    return ppc32_be64(v);
}

static void sig_st32(const ppc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint32_t t = ppc32_be32(v);

    memcpy(ppc32_guest_ptr(ctx, va), &t, sizeof t);
}

static void sig_st64(const ppc32_ctx_t *ctx, uint32_t va, uint64_t v)
{
    uint64_t t = ppc32_be64(v);

    memcpy(ppc32_guest_ptr(ctx, va), &t, sizeof t);
}

static void sig_zero(const ppc32_ctx_t *ctx, uint32_t va, size_t len)
{
    memset(ppc32_guest_ptr(ctx, va), 0, len);
}

/* Mask word with bit (sig-1) set; 0 when sig is outside 1..64. */
static uint64_t sig_bit(int sig)
{
    if (sig < 1 || sig > (int)PPC32_NSIG) {
        return 0ULL;
    }
    return 1ULL << (uint64_t)(sig - 1);
}

/* SIGKILL/SIGSTOP can never be caught, blocked, or ignored. */
int ppc32_sig_is_catchable(int sig)
{
    return (sig == (int)PPC32_SIGKILL || sig == (int)PPC32_SIGSTOP) ? 0 : 1;
}

void ppc32_sig_reset(void)
{
    uint32_t i;

    for (i = 0U; i <= PPC32_NSIG; i++) {
        sig_actions[i].handler = PPC32_SIG_DFL;
        sig_actions[i].flags = 0U;
        sig_actions[i].restorer = 0U;
        sig_actions[i].mask[0] = 0U;
        sig_actions[i].mask[1] = 0U;
        sig_installed[i] = 0;
    }
}

int ppc32_sigaction_get(int sig, ppc32_sigact_t *out)
{
    if (sig < 1 || sig > (int)PPC32_NSIG || out == NULL) {
        return -EINVAL;
    }
    out->handler = sig_actions[(uint32_t)sig].handler;
    out->flags = sig_actions[(uint32_t)sig].flags;
    out->restorer = sig_actions[(uint32_t)sig].restorer;
    out->mask[0] = sig_actions[(uint32_t)sig].mask[0];
    out->mask[1] = sig_actions[(uint32_t)sig].mask[1];
    return 0;
}

int ppc32_sigaction_set_raw(int sig, const ppc32_sigact_t *act)
{
    if (sig < 1 || sig > (int)PPC32_NSIG || act == NULL) {
        return -EINVAL;
    }
    if (!ppc32_sig_is_catchable(sig) && act->handler != PPC32_SIG_DFL) {
        return -EINVAL;
    }
    sig_actions[(uint32_t)sig].handler = act->handler;
    sig_actions[(uint32_t)sig].flags = act->flags;
    sig_actions[(uint32_t)sig].restorer = act->restorer;
    sig_actions[(uint32_t)sig].mask[0] = act->mask[0];
    sig_actions[(uint32_t)sig].mask[1] = act->mask[1];
    sig_installed[(uint32_t)sig] = 1;
    return 0;
}

/* Current altstack flags for ucontext: SS_ONSTACK when sp is inside it. */
static uint32_t sig_current_stack_flags(const ppc32_ctx_t *ctx)
{
    uint32_t sp = ctx->gpr[PPC32_REG_SP];

    if (ctx->altstack_size == 0U ||
        (ctx->altstack_flags & PPC32_SS_DISABLE) != 0U) {
        return PPC32_SS_DISABLE;
    }
    if (sp >= ctx->altstack_sp &&
        sp < ctx->altstack_sp + ctx->altstack_size) {
        return PPC32_SS_ONSTACK;
    }
    return 0U;
}

/* Pick the frame base: altstack top with SA_ONSTACK, else current sp. */
static uint32_t sig_frame_base(const ppc32_ctx_t *ctx, uint32_t flags)
{
    uint32_t sp = ctx->gpr[PPC32_REG_SP];

    if ((flags & PPC32_SA_ONSTACK) != 0U && ctx->altstack_size != 0U &&
        (ctx->altstack_flags & PPC32_SS_DISABLE) == 0U &&
        sig_current_stack_flags(ctx) != PPC32_SS_ONSTACK) {
        return ctx->altstack_sp + ctx->altstack_size;
    }
    return sp;
}

int ppc32_sig_build_frame(ppc32_ctx_t *ctx, int sig,
    const ppc32_sigact_t *act, int code, uint32_t fault_addr, uint32_t trap,
    uint32_t dsisr, uint32_t *out_frame_va)
{
    uint32_t base;
    uint32_t frame;
    uint32_t info_va;
    uint32_t uc_va;
    uint32_t mc_va;
    uint32_t greg_va;
    uint32_t freg_va;
    uint32_t vreg_va;
    uint32_t old_lo;
    uint32_t old_hi;
    uint32_t lr;
    uint32_t i;
    uint64_t old_mask;
    uint64_t act_mask;
    uint64_t new_mask;

    if (ctx == NULL || act == NULL || out_frame_va == NULL) {
        return -EFAULT;
    }
    if (sig < 1 || sig > (int)PPC32_NSIG) {
        return -EINVAL;
    }
    base = sig_frame_base(ctx, act->flags);
    /* 16-byte aligned frame below the base (ppc32 SysV ABI alignment). */
    frame = (base - (uint32_t)sizeof(ppc32_rt_sigframe_t)) & ~15U;
    if (!sig_range_ok(frame, sizeof(ppc32_rt_sigframe_t))) {
        return -EFAULT;
    }
    if ((uint64_t)frame + sizeof(ppc32_rt_sigframe_t) >
        (uint64_t)PPC32_TASK_SIZE_TOP) {
        return -EFAULT;
    }
    if ((uint64_t)frame + sizeof(ppc32_rt_sigframe_t) > (uint64_t)base) {
        return -ENOMEM;
    }

    info_va = frame;
    uc_va = frame + UCONTEXT_OFF;
    mc_va = uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_mcontext);
    greg_va = mc_va + (uint32_t)offsetof(ppc32_mcontext_t, mc_gregs);
    freg_va = mc_va + (uint32_t)offsetof(ppc32_mcontext_t, mc_fregs);
    vreg_va = mc_va + (uint32_t)offsetof(ppc32_mcontext_t, mc_vregs);

    sig_zero(ctx, frame, sizeof(ppc32_rt_sigframe_t));

    /* ---- siginfo: signo/errno/code + fault address, rest zeroed ---- */
    sig_st32(ctx, info_va + SI_SIGNO_OFF, (uint32_t)sig);
    sig_st32(ctx, info_va + SI_ERRNO_OFF, 0U);
    sig_st32(ctx, info_va + SI_CODE_OFF, (uint32_t)code);
    sig_st32(ctx, info_va + SI_ADDR_OFF, fault_addr);

    /* ---- ucontext header ---- */
    old_mask = ctx->sig_mask;
    old_lo = (uint32_t)(old_mask & 0xFFFFFFFFULL);
    old_hi = (uint32_t)((old_mask >> 32) & 0xFFFFFFFFULL);
    sig_st32(ctx, uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_flags), 0U);
    sig_st32(ctx, uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_link), 0U);
    sig_st32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_stack_sp),
        ctx->altstack_sp);
    sig_st32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_stack_flags),
        (uint32_t)(int32_t)sig_current_stack_flags(ctx));
    sig_st32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_stack_size),
        ctx->altstack_size);
    sig_st32(ctx, uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_regs),
        greg_va);
    sig_st32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_sigmask), old_lo);
    sig_st32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_sigmask) + 4U,
        old_hi);

    /* ---- mcontext: integer state (BE words, kernel mc_gregs order) ---- */
    for (i = 0U; i < 32U; i++) {
        sig_st32(ctx, greg_va + i * 4U, ctx->gpr[i]);
    }
    sig_st32(ctx,
        greg_va + (uint32_t)PPC32_MC_NIP * 4U, ctx->nip);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_MSR * 4U, 0U);
    sig_st32(ctx,
        greg_va + (uint32_t)PPC32_MC_ORIG_R3 * 4U, ctx->gpr[3]);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_CTR * 4U, ctx->ctr);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_LINK * 4U, ctx->lr);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_XER * 4U, ctx->xer);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_CCR * 4U, ctx->cr);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_MQ * 4U, 0U);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_TRAP * 4U, trap);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_DAR * 4U, fault_addr);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_DSISR * 4U, dsisr);
    sig_st32(ctx, greg_va + (uint32_t)PPC32_MC_RESULT * 4U, 0U);
    /* Remaining mc_gregs words (DSCR/spares) stay zeroed. */

    /* ---- mcontext: FP state as opaque BE doubles; fpscr in the high word
     * of slot 32 (kernel stores it via (unsigned int *)&mc_fregs[32]
     * on big-endian). Host FP state is untouched. ---- */
    for (i = 0U; i < 32U; i++) {
        sig_st64(ctx, freg_va + i * 8U, ctx->fpr[i]);
    }
    sig_st64(ctx, freg_va + 32U * 8U, ((uint64_t)ctx->fpscr << 32));
    /* mc_pad stays zeroed. */

    /* ---- mc_vregs: zeroed, then the SPE overlay on e500v2 ---- */
    if (ctx->is_spe != 0U) {
        for (i = 0U; i < 32U; i++) {
            sig_st32(ctx, vreg_va + i * 4U, ctx->gpr_hi[i]);
        }
        sig_st64(ctx, vreg_va + 128U, ctx->acc);
        sig_st32(ctx, vreg_va + 136U, ctx->spefscr);
    }
    /* abigap stays zeroed (deterministic; kernel leaves it untouched). */

    /* ---- Enter the handler ---- */
    if ((act->flags & PPC32_SA_RESTORER) != 0U && act->restorer != 0U) {
        lr = act->restorer;
    } else {
        /* Write in-frame RT sigreturn trampoline (li r0,172; sc) into abigap,
         * matching arch/powerpc/kernel/signal_32.c setup_trampoline. */
        sig_st32(ctx, frame + ABIGAP_OFF, 0x38000000U | PPC32_NR_RT_SIGRETURN);
        sig_st32(ctx, frame + ABIGAP_OFF + 4U, 0x44000002U);
        lr = frame + ABIGAP_OFF;
    }
    ctx->gpr[PPC32_REG_SP] = frame;
    ctx->gpr[3] = (uint32_t)sig;
    ctx->gpr[4] = info_va;
    ctx->gpr[5] = uc_va;
    ctx->nip = act->handler;
    ctx->lr = lr;

    /* ---- New blocked mask: old | act | sig (KILL/STOP never blocked) ---- */
    act_mask = ((uint64_t)act->mask[1] << 32) | (uint64_t)act->mask[0];
    new_mask = old_mask | act_mask;
    if ((act->flags & PPC32_SA_NODEFER) == 0U) {
        new_mask |= sig_bit(sig);
    }
    new_mask &= ~(sig_bit((int)PPC32_SIGKILL) |
        sig_bit((int)PPC32_SIGSTOP));
    ctx->sig_mask = new_mask;

    /* Reservation dies on delivery (SPEC 2.2); anchor the frame. */
    ctx->res_valid = 0U;
    ctx->reservation_epoch++;
    ctx->pending_signals &= ~sig_bit(sig);
    ctx->sync_sig_delivered = 1;
    ctx->sig_last_frame_va = frame;
    ctx->sig_last_frame_rt = 1U;

    if ((act->flags & PPC32_SA_RESETHAND) != 0U) {
        sig_actions[(uint32_t)sig].handler = PPC32_SIG_DFL;
        sig_actions[(uint32_t)sig].flags = 0U;
        sig_actions[(uint32_t)sig].restorer = 0U;
        sig_actions[(uint32_t)sig].mask[0] = 0U;
        sig_actions[(uint32_t)sig].mask[1] = 0U;
    }

    *out_frame_va = frame;
    return 0;
}

int ppc32_sig_restore_frame(ppc32_ctx_t *ctx, uint32_t frame_va)
{
    uint32_t uc_va;
    uint32_t mc_va;
    uint32_t greg_va;
    uint32_t freg_va;
    uint32_t vreg_va;
    uint32_t lo;
    uint32_t hi;
    uint32_t i;
    uint64_t mask;

    if (ctx == NULL) {
        return -EFAULT;
    }
    if (!sig_range_ok(frame_va, sizeof(ppc32_rt_sigframe_t))) {
        return -EFAULT;
    }

    uc_va = frame_va + UCONTEXT_OFF;
    mc_va = uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_mcontext);
    greg_va = mc_va + (uint32_t)offsetof(ppc32_mcontext_t, mc_gregs);
    freg_va = mc_va + (uint32_t)offsetof(ppc32_mcontext_t, mc_fregs);
    vreg_va = mc_va + (uint32_t)offsetof(ppc32_mcontext_t, mc_vregs);

    /* Blocked mask first (KILL/STOP forced unblocked, as in the kernel). */
    lo = sig_ld32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_sigmask));
    hi = sig_ld32(ctx,
        uc_va + (uint32_t)offsetof(ppc32_ucontext_t, uc_sigmask) + 4U);
    mask = ((uint64_t)hi << 32) | (uint64_t)lo;
    mask &= ~(sig_bit((int)PPC32_SIGKILL) | sig_bit((int)PPC32_SIGSTOP));
    ctx->sig_mask = mask;

    /* Integer state; msr/orig_r3/trap/dar/dsisr/result are informational. */
    for (i = 0U; i < 32U; i++) {
        ctx->gpr[i] = sig_ld32(ctx, greg_va + i * 4U);
    }
    ctx->nip = sig_ld32(ctx, greg_va + (uint32_t)PPC32_MC_NIP * 4U);
    ctx->ctr = sig_ld32(ctx, greg_va + (uint32_t)PPC32_MC_CTR * 4U);
    ctx->lr = sig_ld32(ctx, greg_va + (uint32_t)PPC32_MC_LINK * 4U);
    ctx->xer = sig_ld32(ctx, greg_va + (uint32_t)PPC32_MC_XER * 4U);
    ctx->cr = sig_ld32(ctx, greg_va + (uint32_t)PPC32_MC_CCR * 4U);

    /* FP state: opaque bit patterns; fpscr from the high word of slot 32. */
    for (i = 0U; i < 32U; i++) {
        ctx->fpr[i] = sig_ld64(ctx, freg_va + i * 8U);
    }
    ctx->fpscr = (uint32_t)(sig_ld64(ctx, freg_va + 32U * 8U) >> 32);

    /* SPE overlay only on e500v2 (classic leaves gpr_hi/acc alone). */
    if (ctx->is_spe != 0U) {
        for (i = 0U; i < 32U; i++) {
            ctx->gpr_hi[i] = sig_ld32(ctx, vreg_va + i * 4U);
        }
        ctx->acc = sig_ld64(ctx, vreg_va + 128U);
        ctx->spefscr = sig_ld32(ctx, vreg_va + 136U);
    }

    /* A stale reservation must not survive the handler (SPEC 2.2). */
    ctx->res_valid = 0U;
    ctx->reservation_epoch++;
    ctx->sig_last_frame_va = 0U;
    ctx->sig_last_frame_rt = 0U;
    return 0;
}

static int sig_default_code(int sig)
{
    switch (sig) {
    case (int)PPC32_SIGSEGV:
        return PPC32_SEGV_MAPERR;
    case (int)PPC32_SIGBUS:
        return PPC32_BUS_ADRALN;
    case (int)PPC32_SIGILL:
        return PPC32_ILL_ILLOPC;
    case (int)PPC32_SIGFPE:
        return PPC32_FPE_INTDIV;
    case (int)PPC32_SIGTRAP:
        return PPC32_TRAP_BRKPT;
    default:
        break;
    }
    return PPC32_SI_USER;
}

static void sig_default_trap(int sig, uint32_t fault_addr, uint32_t is_store,
    uint32_t *out_trap, uint32_t *out_dar, uint32_t *out_dsisr)
{
    uint32_t trap = 0U;
    uint32_t dar = 0U;
    uint32_t dsisr = 0U;

    switch (sig) {
    case (int)PPC32_SIGSEGV:
    case (int)PPC32_SIGBUS:
        trap = PPC32_TRAP_DSI;
        dar = fault_addr;
        dsisr = (is_store != 0U) ? DSISR_STORE_CLASS : DSISR_LOAD_CLASS;
        break;
    case (int)PPC32_SIGILL:
    case (int)PPC32_SIGFPE:
        trap = PPC32_TRAP_PROGRAM;
        dar = fault_addr;
        break;
    case (int)PPC32_SIGTRAP:
        trap = PPC32_TRAP_TRACE;
        dar = fault_addr;
        break;
    default:
        break;
    }
    *out_trap = trap;
    *out_dar = dar;
    *out_dsisr = dsisr;
}

long ppc32_sig_deliver_sync(ppc32_ctx_t *ctx, int sig, int code,
    uint32_t fault_addr, uint32_t is_store)
{
    ppc32_sigact_t act;
    uint32_t trap;
    uint32_t dar;
    uint32_t dsisr;
    uint32_t frame;
    int r;

    if (ctx == NULL) {
        return -EFAULT;
    }
    if (sig < 1 || sig > (int)PPC32_NSIG) {
        return -EINVAL;
    }
    if (ppc32_sigaction_get(sig, &act) != 0) {
        return -EINVAL;
    }
    if (act.handler == PPC32_SIG_IGN) {
        return 1;
    }
    if (act.handler == PPC32_SIG_DFL) {
        return -EFAULT;
    }
    if (code == 0) {
        code = sig_default_code(sig);
    }
    sig_default_trap(sig, fault_addr, is_store, &trap, &dar, &dsisr);
    r = ppc32_sig_build_frame(ctx, sig, &act, code, dar, trap, dsisr,
        &frame);
    if (r != 0) {
        return (long)r;
    }
    (void)frame;
    return 0;
}

/* ---- Syscall argument handlers (kernel-style long returns) ---- */

static long sys_rt_sigaction(ppc32_ctx_t *ctx, uint32_t sig, uint32_t act_va,
    uint32_t old_va, uint32_t setsize)
{
    ppc32_sigact_t neu;
    ppc32_sigact_t old;

    if (sig < 1U || sig > PPC32_NSIG) {
        return -EINVAL;
    }
    if (setsize != PPC32_SIGSET_SIZE) {
        return -EINVAL;
    }
    if (ppc32_sigaction_get((int)sig, &old) != 0) {
        return -EINVAL;
    }
    if (old_va != 0U) {
        /* Guest struct sigaction: handler, flags, restorer, mask[2]. */
        if (!sig_range_ok(old_va, PPC32_SIGACTION_SIZE)) {
            return -EFAULT;
        }
        sig_st32(ctx, old_va, old.handler);
        sig_st32(ctx, old_va + 4U, old.flags);
        sig_st32(ctx, old_va + 8U, old.restorer);
        sig_st32(ctx, old_va + 12U, old.mask[0]);
        sig_st32(ctx, old_va + 16U, old.mask[1]);
    }
    if (act_va != 0U) {
        if (!sig_range_ok(act_va, PPC32_SIGACTION_SIZE)) {
            return -EFAULT;
        }
        neu.handler = sig_ld32(ctx, act_va);
        neu.flags = sig_ld32(ctx, act_va + 4U);
        neu.restorer = sig_ld32(ctx, act_va + 8U);
        neu.mask[0] = sig_ld32(ctx, act_va + 12U);
        neu.mask[1] = sig_ld32(ctx, act_va + 16U);
        if (ppc32_sigaction_set_raw((int)sig, &neu) != 0) {
            return -EINVAL;
        }
    }
    return 0;
}

static long sys_rt_sigprocmask(ppc32_ctx_t *ctx, uint32_t how,
    uint32_t set_va, uint32_t old_va, uint32_t setsize)
{
    uint64_t new_mask;
    uint64_t set;

    if (setsize != PPC32_SIGSET_SIZE) {
        return -EINVAL;
    }
    if (old_va != 0U) {
        if (!sig_range_ok(old_va, PPC32_SIGSET_SIZE)) {
            return -EFAULT;
        }
        sig_st32(ctx, old_va,
            (uint32_t)(ctx->sig_mask & 0xFFFFFFFFULL));
        sig_st32(ctx, old_va + 4U,
            (uint32_t)((ctx->sig_mask >> 32) & 0xFFFFFFFFULL));
    }
    if (set_va != 0U) {
        if (!sig_range_ok(set_va, PPC32_SIGSET_SIZE)) {
            return -EFAULT;
        }
        set = (uint64_t)sig_ld32(ctx, set_va) |
            ((uint64_t)sig_ld32(ctx, set_va + 4U) << 32);
        /* SIGKILL/SIGSTOP are never blocked. */
        set &= ~(sig_bit((int)PPC32_SIGKILL) |
            sig_bit((int)PPC32_SIGSTOP));
        switch (how) {
        case PPC32_SIG_BLOCK:
            new_mask = ctx->sig_mask | set;
            break;
        case PPC32_SIG_UNBLOCK:
            new_mask = ctx->sig_mask & ~set;
            break;
        case PPC32_SIG_SETMASK:
            new_mask = set;
            break;
        default:
            return -EINVAL;
        }
        ctx->sig_mask = new_mask;
    }
    return 0;
}

static long sys_rt_sigpending(ppc32_ctx_t *ctx, uint32_t set_va,
    uint32_t setsize)
{
    uint64_t pend;

    if (setsize != PPC32_SIGSET_SIZE) {
        return -EINVAL;
    }
    if (set_va == 0U) {
        return -EFAULT;
    }
    if (!sig_range_ok(set_va, PPC32_SIGSET_SIZE)) {
        return -EFAULT;
    }
    /* Blocked-but-raised signals awaiting delivery. */
    pend = ctx->pending_signals & ctx->sig_mask;
    sig_st32(ctx, set_va, (uint32_t)(pend & 0xFFFFFFFFULL));
    sig_st32(ctx, set_va + 4U, (uint32_t)((pend >> 32) & 0xFFFFFFFFULL));
    return 0;
}

static long sys_rt_sigreturn(ppc32_ctx_t *ctx)
{
    /* The frame address is the current stack pointer (the vDSO
     * __kernel_sigtramp_rt issues `li r0,173; sc` without moving r1).
     * nip is restored from the frame; the caller must not advance it. */
    return (long)ppc32_sig_restore_frame(ctx, ctx->gpr[PPC32_REG_SP]);
}

static long sys_sigaltstack(ppc32_ctx_t *ctx, uint32_t uss_va,
    uint32_t uoss_va)
{
    uint32_t sp;
    uint32_t flags;
    uint32_t size;
    uint32_t cur_flags;

    if (uoss_va != 0U) {
        if (!sig_range_ok(uoss_va, PPC32_SIGSTACK_SIZE)) {
            return -EFAULT;
        }
        cur_flags = sig_current_stack_flags(ctx);
        sig_st32(ctx, uoss_va, ctx->altstack_sp);
        sig_st32(ctx, uoss_va + 4U, (uint32_t)(int32_t)cur_flags);
        sig_st32(ctx, uoss_va + 8U, ctx->altstack_size);
    }
    if (uss_va == 0U) {
        return 0;
    }
    if (!sig_range_ok(uss_va, PPC32_SIGSTACK_SIZE)) {
        return -EFAULT;
    }
    sp = sig_ld32(ctx, uss_va);
    flags = sig_ld32(ctx, uss_va + 4U);
    size = sig_ld32(ctx, uss_va + 8U);
    if ((flags & ~(PPC32_SS_DISABLE | PPC32_SS_ONSTACK)) != 0U) {
        return -EINVAL;
    }
    if ((flags & PPC32_SS_DISABLE) != 0U) {
        if (sig_current_stack_flags(ctx) == PPC32_SS_ONSTACK) {
            return -ENOMEM;
        }
        ctx->altstack_flags = PPC32_SS_DISABLE;
        ctx->altstack_sp = 0U;
        ctx->altstack_size = 0U;
        return 0;
    }
    /* SS_ONSTACK in the input is ignored (kernel tracks it internally). */
    if (size < PPC32_MINSIGSTKSZ) {
        return -ENOMEM;
    }
    if (sig_current_stack_flags(ctx) == PPC32_SS_ONSTACK) {
        return -ENOMEM;
    }
    if (!sig_range_ok(sp, size)) {
        return -EFAULT;
    }
    ctx->altstack_sp = sp;
    ctx->altstack_size = size;
    ctx->altstack_flags = 0U;
    return 0;
}

int ppc32_sig_nr_no_advance(uint32_t nr)
{
    return (nr == PPC32_NR_RT_SIGRETURN) ? 1 : 0;
}

/* kill(2): self-delivery goes through the guest signal layer (a host
 * kill would bypass the installed handler and slay the translator);
 * anything else forwards to the host (fork children are real host
 * processes, so kill/wait4 on them behave natively). Returns 1 when the
 * call was fully applied inside (E01 + nip + syscalls_executed all
 * handled, ppc32_sig_deliver_sync entered the handler); 0 with *out_ret
 * set when the generic tail (E01 + advance) still applies. Moved here
 * from syscalls.c in RC5 (file-size discipline): the signal layer owns
 * delivery, so it owns the self-delivery fast path too. */
int ppc32_sig_kill(ppc32_ctx_t *ctx, uint32_t pid_va, uint32_t sig,
    long *out_ret)
{
    ppc32_sigact_t act;

    if (out_ret == NULL) {
        return 0;
    }
    if (sig < 1U || sig > PPC32_NSIG) {
        *out_ret = -EINVAL;
        return 0;
    }
    if ((pid_t)(int32_t)pid_va != getpid()) {
        *out_ret = (kill((pid_t)(int32_t)pid_va, (int)sig) == 0) ? 0L :
            -(long)errno;
        return 0;
    }
    if (ppc32_sigaction_get((int)sig, &act) != 0) {
        *out_ret = -EINVAL;
        return 0;
    }
    if (act.handler != PPC32_SIG_DFL && act.handler != PPC32_SIG_IGN) {
        /* Handled: success return first (post-sc nip is what the frame
         * captures), then redirect into the handler; the tail must not
         * advance nip a second time. */
        ctx->gpr[3] = 0U;
        ctx->cr &= (uint32_t)~PPC32_CR0_SO;
        ctx->nip += 4U;
        ctx->syscalls_executed++;
        if (ppc32_sig_deliver_sync(ctx, (int)sig, 0, 0U, 0U) != 0) {
            raise(SIGSEGV);
            *out_ret = -EFAULT;
            return 0;
        }
        return 1;
    }
    if (act.handler == PPC32_SIG_IGN) {
        *out_ret = 0L;
        return 0;
    }
    /* Default disposition: let the host apply it (fatal signals terminate
     * us exactly like the qemu-ppc oracle dies; ignore-defaults return). */
    *out_ret = (raise((int)sig) == 0) ? 0L : -(long)errno;
    return 0;
}

int ppc32_sig_syscall(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, long *out_ret)
{
    long ret;

    if (ctx == NULL || out_ret == NULL) {
        return 0;
    }
    switch (nr) {
    case PPC32_NR_RT_SIGACTION:
        ret = sys_rt_sigaction(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_RT_SIGPROCMASK:
        ret = sys_rt_sigprocmask(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_RT_SIGPENDING:
        ret = sys_rt_sigpending(ctx, a0, a1);
        break;
    case PPC32_NR_RT_SIGRETURN:
        ret = sys_rt_sigreturn(ctx);
        break;
    case PPC32_NR_SIGALTSTACK:
        ret = sys_sigaltstack(ctx, a0, a1);
        break;
    default:
        return 0;
    }
    *out_ret = ret;
    return 1;
}
