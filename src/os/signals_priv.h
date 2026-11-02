/*
 * src/os/signals_priv.h — Shared signal-layer guest-memory helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal only (never installed): the BE scalar helpers and sigframe
 * geometry shared by the signals.c frame build/restore, delivery, and
 * syscall-handler paths. convert.h is deliberately not
 * included: its ppc32_stat_t collides with the frozen sigframe header,
 * so the BE helpers needed here are restated on top of
 * ppc32_vm_copyin_safe/ppc32_vm_copyout_safe.
 */

#ifndef PPC32RT_OS_SIGNALS_PRIV_H
#define PPC32RT_OS_SIGNALS_PRIV_H

#include <stddef.h>
#include <stdint.h>

#include "os/signals.h"
#include "rt32/ppc32.h"

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
    if (end > (uint64_t)PPC32_TASK_SIZE_TOP) {
        return 0;
    }
    return 1;
}

static int sig_range_prot_ok(const ppc32_ctx_t *ctx, uint32_t va, size_t len,
    uint32_t need_prot)
{
    if (!sig_range_ok(va, len)) {
        return 0;
    }
    return ppc32_vm_range_prot_ok(ctx, va, len, need_prot) ? 1 : 0;
}

/* Fail the caller with -EFAULT when a safe guest access fails. */
#define SIG_MUST(expr) do { if ((expr) != 0) { return -EFAULT; } } while (0)

static int sig_ld32(const ppc32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint32_t raw = 0U;
    int rc;

    if (out == NULL) {
        return -EFAULT;
    }
    rc = ppc32_vm_copyin_safe(ctx, va, &raw, sizeof raw);
    if (rc != 0) {
        return rc;
    }
    *out = ppc32_be32(raw);
    return 0;
}

static int sig_ld64(const ppc32_ctx_t *ctx, uint32_t va, uint64_t *out)
{
    uint64_t raw = 0ULL;
    int rc;

    if (out == NULL) {
        return -EFAULT;
    }
    rc = ppc32_vm_copyin_safe(ctx, va, &raw, sizeof raw);
    if (rc != 0) {
        return rc;
    }
    *out = ppc32_be64(raw);
    return 0;
}

static int sig_st32(const ppc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint32_t t = ppc32_be32(v);

    return ppc32_vm_copyout_safe(ctx, va, &t, sizeof t);
}

static int sig_st64(const ppc32_ctx_t *ctx, uint32_t va, uint64_t v)
{
    uint64_t t = ppc32_be64(v);

    return ppc32_vm_copyout_safe(ctx, va, &t, sizeof t);
}

static int sig_zero(const ppc32_ctx_t *ctx, uint32_t va, size_t len)
{
    static const char zeros[64] = { 0 };
    uint32_t cur = va;
    size_t left = len;

    while (left > 0U) {
        size_t n = (left > sizeof zeros) ? sizeof zeros : left;
        int rc = ppc32_vm_copyout_safe(ctx, cur, zeros, n);

        if (rc != 0) {
            return rc;
        }
        cur += (uint32_t)n;
        left -= n;
    }
    return 0;
}

/* Mask word with bit (sig-1) set; 0 when sig is outside 1..64. */
static uint64_t sig_bit(int sig)
{
    if (sig < 1 || sig > (int)PPC32_NSIG) {
        return 0ULL;
    }
    return 1ULL << (uint64_t)(sig - 1);
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

#endif /* PPC32RT_OS_SIGNALS_PRIV_H */
