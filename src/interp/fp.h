/*
 * src/interp/fp.h — classic-FPU + e500v2-SPE single-step (Phase 3, lane L3a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Classic FPU (750): full data-move/arithmetic/compare/convert/move/
 * FPSCR set (fres/frsqrte UNDEF; 32-bit insns never touch gpr_hi).
 * e500v2 SPE (major opcode 4, full 11-bit XO): integer/logical/merge/
 * ldst/compare/select, scalar efs/efd, vector evfs, MAC (per-EREF:
 * traps on the qemu oracle). XOs gas+objdump verified.
 */

#ifndef PPC32_FP_H
#define PPC32_FP_H

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "ppc32rt.h"
#include "interp/decode.h"
#include "interp/interp.h"

/* Execute one FP/SPE instruction. Unknown FP/SPE opcodes set
 * PPC32_EXIT_UNDEF. Classic FPU data moves keep RC2 behavior, except
 * lfs/stfs now do true single<->double conversion (hardware parity). */
void ppc32_fp_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);
/* e500v2 SPE worker (fp_spe.c); called by ppc32_fp_step. */
void fp_spe(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);

/* ---- shared inline helpers (fp.c implementation detail) ------------ */

static inline uint64_t fp_u64(double d)
{
    uint64_t u;

    memcpy(&u, &d, 8);
    return u;
}

static inline double fp_f64(uint64_t u)
{
    double d;

    memcpy(&d, &u, 8);
    return d;
}

static inline uint32_t fp_u32(float f)
{
    uint32_t u;

    memcpy(&u, &f, 4);
    return u;
}

static inline float fp_f32(uint32_t u)
{
    float f;

    memcpy(&f, &u, 4);
    return f;
}

static inline uint64_t fp_gpr64(const ppc32_ctx_t *ctx, unsigned r)
{
    return ((uint64_t)ctx->gpr_hi[r & 31u] << 32) | ctx->gpr[r & 31u];
}

static inline void fp_gpr64_set(ppc32_ctx_t *ctx, unsigned r, uint64_t v)
{
    ctx->gpr_hi[r & 31u] = (uint32_t)(v >> 32);
    ctx->gpr[r & 31u] = (uint32_t)v;
}

static inline uint64_t fp_ld64(const ppc32_ctx_t *ctx, uint32_t ea)
{
    return ((uint64_t)ld32(ctx, ea) << 32) | ld32(ctx, ea + 4u);
}

static inline void fp_st64(ppc32_ctx_t *ctx, uint32_t ea, uint64_t v)
{
    st32(ctx, ea, (uint32_t)(v >> 32));
    st32(ctx, ea + 4u, (uint32_t)v);
}

/* FPSCR LSB numbers (verified against qemu cpu.h). */
#define F_FX 31u
#define F_FEX 30u
#define F_VX 29u
#define F_OX 28u
#define F_UX 27u
#define F_ZX 26u
#define F_XX 25u
#define F_VXSNAN 24u
#define F_VXISI 23u
#define F_VXIDI 22u
#define F_VXZDZ 21u
#define F_VXIMZ 20u
#define F_VXVC 19u
#define F_FR 18u
#define F_FI 17u
#define F_VXCVI 8u
#define F_VXSQRT 9u
#define F_VXSOFT 10u
#define F_FX_M (1u << F_FX)
#define F_FEX_M (1u << F_FEX)
#define F_VX_M (1u << F_VX)
#define F_OX_M (1u << F_OX)
#define F_UX_M (1u << F_UX)
#define F_ZX_M (1u << F_ZX)
#define F_XX_M (1u << F_XX)
#define F_VXSNAN_M (1u << F_VXSNAN)
#define F_VXISI_M (1u << F_VXISI)
#define F_VXIDI_M (1u << F_VXIDI)
#define F_VXZDZ_M (1u << F_VXZDZ)
#define F_VXIMZ_M (1u << F_VXIMZ)
#define F_VXVC_M (1u << F_VXVC)
#define F_FI_M (1u << F_FI)
#define F_FR_M (1u << F_FR)
#define F_VXCVI_M (1u << F_VXCVI)
#define F_VXSQRT_M (1u << F_VXSQRT)
#define F_VXSOFT_M (1u << F_VXSOFT)

/* FPSCR summary maintenance (P32-R7-18): FX/VX are sticky-event bits,
 * set only when the mutation introduces a newly-set exception bit; a
 * software-cleared FX is never reasserted merely because an old
 * exception bit remains. FEX is a live cause/enable summary and is
 * recomputed (set or cleared). `old` is the pre-mutation FPSCR. */
static inline void fp_touch(ppc32_ctx_t *ctx, uint32_t old)
{
    static const uint32_t vxsub = F_VXSNAN_M | F_VXISI_M | F_VXIDI_M |
        F_VXZDZ_M | F_VXIMZ_M | F_VXVC_M | F_VXSOFT_M | F_VXSQRT_M |
        F_VXCVI_M;
    static const uint32_t exc = F_VX_M | F_OX_M | F_UX_M | F_ZX_M |
        F_XX_M | F_VXSNAN_M | F_VXISI_M | F_VXIDI_M | F_VXZDZ_M |
        F_VXIMZ_M | F_VXVC_M | F_VXSOFT_M | F_VXSQRT_M | F_VXCVI_M;
    uint32_t cur = ctx->fpscr;
    uint32_t chg = cur & ~old;

    if ((chg & vxsub) != 0u) {
        cur |= F_VX_M;
    }
    if ((chg & exc) != 0u) {
        cur |= F_FX_M;
    }
    /* FEX iff any cause (VX,OX,UX,ZX,XX = bits 29..25) pairs with its
     * enable (bits 7..3). */
    if ((((cur >> 25) & 0x1fu) & ((cur >> 3) & 0x1fu)) != 0u) {
        cur |= F_FEX_M;
    } else {
        cur &= ~F_FEX_M;
    }
    ctx->fpscr = cur;
}

/* OR exception bits; recompute FX/FEX summaries (never raises). */
static inline void fp_raise(ppc32_ctx_t *ctx, uint32_t bits)
{
    uint32_t old = ctx->fpscr;

    ctx->fpscr = old | bits;
    fp_touch(ctx, old);
}

/* FPRF class (matches qemu COMPUTE_FPRF_F64). */
static inline uint32_t fp_fprf64(uint64_t u)
{
    uint32_t exp = (uint32_t)((u >> 52) & 0x7ffu);
    uint64_t man = u & 0xfffffffffffffull;
    int neg = (u >> 63) != 0u;

    if (exp == 0x7ffu) {
        if (man == 0u) {
            return neg ? 0x09u : 0x05u;
        }
        return (man & 0x8000000000000ull) != 0u ? 0x11u : 0u;
    }
    if (exp == 0u) {
        if (man == 0u) {
            return neg ? 0x12u : 0x02u;
        }
        return neg ? 0x18u : 0x14u;
    }
    return neg ? 0x08u : 0x04u;
}

/* Exact single->double expansion. */
static inline uint64_t fp_xtod(uint32_t w)
{
    uint32_t s = w >> 31;
    uint32_t e = (w >> 23) & 0xffu;
    uint32_t m = w & 0x7fffffu;

    if (e == 0xffu) {
        return ((uint64_t)s << 63) | ((uint64_t)0x7ff << 52) |
            ((uint64_t)m << 29);
    }
    if (e != 0u) {
        return ((uint64_t)s << 63) | ((uint64_t)(e + 896u) << 52) |
            ((uint64_t)m << 29);
    }
    if (m == 0u) {
        return (uint64_t)s << 63;
    }
    {
        int32_t eb = 1;
        uint32_t mm = m;

        while ((mm & 0x800000u) == 0u) {
            mm <<= 1;
            eb--;
        }
        return ((uint64_t)s << 63) | ((uint64_t)(eb + 896) << 52) |
            ((uint64_t)(mm & 0x7fffffu) << 29);
    }
}

/* Double->single, truncation + exponent wrap, silent (matches qemu stfs:
 * no flags, truncates mantissa, wraps exp as (unbiased+127) mod 896,
 * NaN-quiet rides payload shift, double-denormals to signed zero). */
static inline uint32_t fp_dtos(uint64_t d)
{
    uint32_t s = (uint32_t)(d >> 63);
    uint32_t e = (uint32_t)((d >> 52) & 0x7ffu);
    uint32_t m = (uint32_t)((d >> 29) & 0x7fffffu);

    if (e == 0x7ffu) {
        return (s << 31) | (0xffu << 23) | m;
    }
    if (e == 0u) {
        return s << 31;
    }
    {
        int32_t e32 = (int32_t)e - 1023 + 127;

        if (e32 <= 0) {
            if (e32 < -24) {
                return s << 31;
            }
            return (s << 31) |
                ((((uint32_t)(((d >> 29) & 0x7fffffu) | 0x800000u))) >>
                (uint32_t)(1 - e32));
        }
        return (s << 31) | ((uint32_t)(((e32 % 896) + 896) % 896) << 23) | m;
    }
}

/* CR1 <- FPSCR[FX,FEX,VX,OX] (matches qemu gen_set_cr1_from_fpscr).
 * P32-R7-5: CR1 is field 1 (shift 24), not field 6. */
static inline void fp_cr1(ppc32_ctx_t *ctx)
{
    uint32_t v = (ctx->fpscr >> 28) & 0xfu;
    ctx->cr = (ctx->cr & ~(0xfu << 24)) | (v << 24);
}

/* FPRF class for single-precision results (P32-R7-22): values that are
 * subnormal as singles but normal as doubles (e.g. 2^-127) classify as
 * subnormal here. */
static inline uint32_t fp_fprf32(uint32_t w)
{
    uint32_t exp = (w >> 23) & 0xffu;
    uint32_t man = w & 0x7fffffu;
    int neg = (w >> 31) != 0u;

    if (exp == 0xffu) {
        if (man == 0u) {
            return neg ? 0x09u : 0x05u;
        }
        return (man & 0x400000u) != 0u ? 0x11u : 0u;
    }
    if (exp == 0u) {
        if (man == 0u) {
            return neg ? 0x12u : 0x02u;
        }
        return neg ? 0x18u : 0x14u;
    }
    return neg ? 0x08u : 0x04u;
}

/* FPRF recompute + FI/FR assign (P32-R7-19: FR mirrors the current
 * rounding event — set iff inexact, cleared for exact operations;
 * P32-R7-22: single results classify before double expansion). */
static inline void fp_flags_arith(ppc32_ctx_t *ctx, uint64_t res, int inexact,
    uint32_t sticky, int single)
{
    uint32_t f;
    uint32_t fprf = (single != 0) ? fp_fprf32(fp_dtos(res)) :
        fp_fprf64(res);

    fp_raise(ctx, sticky);
    f = ctx->fpscr;
    f &= ~(0x1fu << 12);
    f |= fprf << 12;
    f &= ~(F_FI_M | F_FR_M);
    if (inexact) {
        f |= F_FI_M | F_FR_M;
    }
    ctx->fpscr = f;
}

static inline int fp_isnan(uint64_t u)
{
    return ((u & 0x7ff0000000000000ull) == 0x7ff0000000000000ull) &&
        ((u & 0xfffffffffffffull) != 0u);
}

static inline int fp_isinf(uint64_t u)
{
    return ((u & 0x7ff0000000000000ull) == 0x7ff0000000000000ull) &&
        ((u & 0xfffffffffffffull) == 0u);
}

static inline int fp_iszero(uint64_t u)
{
    return (u & 0x7fffffffffffffffull) == 0u;
}

/* First-NaN-operand pick, quieted copy out, SNaN-ness out (any-operand
 * SNaN counts, matching softfloat propagate). Caller raises via
 * fp_nanres in fp.c. */
static inline int fp_nan2(uint64_t a, uint64_t b, uint64_t *res, int *snan)
{
    int sa = fp_isnan(a);
    int sb = fp_isnan(b);
    uint64_t n;

    if (!sa && !sb) {
        return 0;
    }
    n = sa ? a : b;
    *snan = (sa && (a & 0x8000000000000ull) == 0u) ||
        (sb && (b & 0x8000000000000ull) == 0u);
    if ((n & 0x8000000000000ull) == 0u) {
        n |= 0x8000000000000ull;
    }
    *res = n;
    return 1;
}

/* Invalid combos on doubles (op: 0 add, 1 sub, 2 mul, 3 div).
 * P32-R7-6: addition is invalid on opposite-sign infinities, subtraction
 * on same-sign infinities. */
static inline uint32_t fp_inv2(int op, uint64_t a, uint64_t b)
{
    if (op == 0) {
        if (fp_isinf(a) && fp_isinf(b) && (((a ^ b) >> 63) & 1u) != 0u) {
            return F_VXISI_M;
        }
    } else if (op == 1) {
        if (fp_isinf(a) && fp_isinf(b) && (((a ^ b) >> 63) & 1u) == 0u) {
            return F_VXISI_M;
        }
    } else if (op == 2) {
        if ((fp_iszero(a) && fp_isinf(b)) || (fp_iszero(b) && fp_isinf(a))) {
            return F_VXIMZ_M;
        }
    } else if (op == 3) {
        if (fp_iszero(a) && fp_iszero(b)) {
            return F_VXZDZ_M;
        }
        if (fp_isinf(a) && fp_isinf(b)) {
            return F_VXIDI_M;
        }
    }
    return 0u;
}

static inline int fp_snan(uint32_t u)
{
    return ((u & 0x7f800000u) == 0x7f800000u) && ((u & 0x7fffffu) != 0u);
}

static inline int fp_sinf(uint32_t u)
{
    return ((u & 0x7f800000u) == 0x7f800000u) && ((u & 0x7fffffu) == 0u);
}

static inline int fp_szero(uint32_t u)
{
    return (u & 0x7fffffffu) == 0u;
}

/* Invalid combos on singles (post-conversion; P32-R7-6 sign rule as
 * for doubles). */
static inline uint32_t fp_inv2s(int op, uint32_t a, uint32_t b)
{
    if (op == 0) {
        if (fp_sinf(a) && fp_sinf(b) && (((a ^ b) >> 31) & 1u) != 0u) {
            return F_VXISI_M;
        }
    } else if (op == 1) {
        if (fp_sinf(a) && fp_sinf(b) && (((a ^ b) >> 31) & 1u) == 0u) {
            return F_VXISI_M;
        }
    } else if (op == 2) {
        if ((fp_szero(a) && fp_sinf(b)) || (fp_szero(b) && fp_sinf(a))) {
            return F_VXIMZ_M;
        }
    } else if (op == 3) {
        if (fp_szero(a) && fp_szero(b)) {
            return F_VXZDZ_M;
        }
        if (fp_sinf(a) && fp_sinf(b)) {
            return F_VXIDI_M;
        }
    }
    return 0u;
}

/* Quieted-double-NaN to single bits (payload>>29, quiet rides shift). */
static inline uint32_t fp_qnan32(uint64_t n)
{
    return (uint32_t)(((n >> 29) & 0x7fffffu) | 0x7f800000u |
        ((n >> 63) << 31));
}

static inline int fp_rn(const ppc32_ctx_t *ctx)
{
    return (int)(ctx->fpscr & 3u); /* RN: FPSCR bits 0-1. */
}

static inline void fp_setrn(int rn)
{
    static const int modes[4] = { FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD,
        FE_DOWNWARD };

    fesetround(modes[rn & 3]);
}

/* Store FPR + Rc->CR1 + advance (shared op epilogue). */
static inline void fp_done(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint64_t v)
{
    ctx->fpr[insn->rt & 31u] = v;
    if (insn->rc) fp_cr1(ctx);
    ctx->nip += 4u;
}

/* ---- SPE helpers (qemu spe-impl/fpu_helper; e500v2) ------------------
 * 64-bit GPRs as (hi<<32)|lo. Classic 32-bit ops never touch hi; SPE
 * 32-bit-out ops preserve it (split storage). SPE never touches
 * FPSCR/SPEFSCR/CR except compares (CR only), evsel (GPRs only), MAC
 * (ACC). No traps are simulated. */

/* Vector compare composite (matches qemu GEN_SPEOP_COMP; hi->bit3,
 * lo->bit2, OR->bit1, AND->bit0). */
static inline uint32_t fp_evcmp(int hi, int lo)
{
    uint32_t cr = 0u;

    if (lo) {
        cr |= 0x7u;
    }
    if (hi) {
        cr |= 0xau;
    } else {
        cr &= ~0x9u;
    }
    return cr;
}

/* Vector float compare merge (P32-R7-8): lane results are normalized
 * to 0/1 here, so the composite is a 4-bit CR field value occupying
 * exactly one nibble (both lanes true -> 0xf). */
static inline uint32_t fp_fcmp_merge(uint32_t t0, uint32_t t1)
{
    t0 = (t0 != 0u) ? 1u : 0u;
    t1 = (t1 != 0u) ? 1u : 0u;
    return (t0 << 3) | (t1 << 2) | ((t0 | t1) << 1) | (t0 & t1);
}

/* Write exactly the selected CR field (P32-R7-8): the value is masked to
 * one nibble and never bleeds into the neighboring field. */
static inline void fp_set_crf_bleed(ppc32_ctx_t *ctx, unsigned bf,
    uint32_t m)
{
    uint32_t shift = 4u * (7u - (bf & 7u));

    ctx->cr = (ctx->cr & ~(0xfu << shift)) | ((m & 0xfu) << shift);
}

/* OR sticky status bits (enables select interrupt delivery on hardware;
 * this user-mode emulator records status and always commits). */
static inline void spe_raise(ppc32_ctx_t *ctx, uint32_t bits)
{
    ctx->spefscr |= bits;
}

/* Apply the SPEFSCR FRMC rounding mode to the host environment. */
static inline void spe_setrn(const ppc32_ctx_t *ctx)
{
    fp_setrn((int)(ctx->spefscr & SPE_FRMC));
}

/* Fold captured host FP flags into SPEFSCR sticky/current status. */
static inline void spe_flags(ppc32_ctx_t *ctx)
{
    if (fetestexcept(FE_INVALID) != 0) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
    }
    if (fetestexcept(FE_DIVBYZERO) != 0) {
        spe_raise(ctx, SPE_FDBZ | SPE_FDBZS);
    }
    if (fetestexcept(FE_OVERFLOW) != 0) {
        spe_raise(ctx, SPE_FOVF | SPE_FOVFS);
    }
    if (fetestexcept(FE_UNDERFLOW) != 0) {
        spe_raise(ctx, SPE_FUNF | SPE_FUNFS);
    }
    if (fetestexcept(FE_INEXACT) != 0) {
        spe_raise(ctx, SPE_FINXS);
    }
}

/* Scalar-single efs arithmetic core (NaN: first-operand payload, SNaN
 * quieted; P32-R7-13: FRMC rounding, denormal inputs flush to zero
 * with FINV, status recorded in SPEFSCR). */
static inline uint32_t fp_efs_arith(ppc32_ctx_t *ctx, uint32_t a, uint32_t b,
    int op)
{
    float fa = fp_f32(a);
    float fb = fp_f32(b);
    int old = fegetround();
    float fr;
    uint32_t r;

    if (fp_snan(a) || fp_snan(b)) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
        return (fp_snan(a) ? a : b) | 0x400000u;
    }
    if (fpclassify(fa) == FP_SUBNORMAL) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
        fa = copysignf(0.0f, fa);
    }
    if (fpclassify(fb) == FP_SUBNORMAL) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
        fb = copysignf(0.0f, fb);
    }
    spe_setrn(ctx);
    feclearexcept(FE_ALL_EXCEPT);
    if (op == 0) {
        fr = fa + fb;
    } else if (op == 1) {
        fr = fa - fb;
    } else if (op == 2) {
        fr = fa * fb;
    } else {
        fr = fa / fb;
    }
    if (fpclassify(fr) == FP_SUBNORMAL) {
        spe_raise(ctx, SPE_FUNF | SPE_FUNFS | SPE_FINXS);
        r = signbit(fr) ? 0x80000000u : 0u;
    } else {
        spe_flags(ctx);
        r = fp_u32(fr);
    }
    fesetround(old);
    return r;
}

/* Double efd arithmetic core (NaN first-operand; P32-R7-13 rounding and
 * status as for efs). */
static inline uint64_t fp_efd_arith(ppc32_ctx_t *ctx, uint64_t a, uint64_t b,
    int op)
{
    double fa = fp_f64(a);
    double fb = fp_f64(b);
    int old = fegetround();
    double fr;
    uint64_t r;

    if (fp_isnan(a) || fp_isnan(b)) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
        return (fp_isnan(a) ? a : b) | 0x8000000000000ull;
    }
    if (fpclassify(fa) == FP_SUBNORMAL) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
        fa = copysign(0.0, fa);
    }
    if (fpclassify(fb) == FP_SUBNORMAL) {
        spe_raise(ctx, SPE_FINV | SPE_FINVS);
        fb = copysign(0.0, fb);
    }
    spe_setrn(ctx);
    feclearexcept(FE_ALL_EXCEPT);
    if (op == 0) {
        fr = fa + fb;
    } else if (op == 1) {
        fr = fa - fb;
    } else if (op == 2) {
        fr = fa * fb;
    } else {
        fr = fa / fb;
    }
    if (fpclassify(fr) == FP_SUBNORMAL) {
        spe_raise(ctx, SPE_FUNF | SPE_FUNFS | SPE_FINXS);
        r = signbit(fr) ? 0x8000000000000000ull : 0u;
    } else {
        spe_flags(ctx);
        r = fp_u64(fr);
    }
    fesetround(old);
    return r;
}

/* Saturating float->int32 (caller pre-maps NaN as needed). z selects
 * round-to-zero else nearest-even. Host rounding must be nearest. */
static inline int32_t fp_f2i(float f, int z)
{
    float r = z ? truncf(f) : rintf(f);

    if (isnan(f)) {
        return signbit(f) ? (int32_t)0x80000000 : 0x7fffffff;
    }
    if (!isfinite(f)) {
        return f > 0.0f ? 0x7fffffff : (int32_t)0x80000000;
    }
    /* P32-R7-12: 2147483647.0f rounds to 2^31, which is out of range;
     * reject at >= 2^31 before the (undefined) cast. */
    if (r >= 2147483648.0f) {
        return 0x7fffffff;
    }
    if (r < -2147483648.0f) {
        return (int32_t)0x80000000;
    }
    return (int32_t)r;
}

static inline uint32_t fp_f2u(float f, int z)
{
    float r = z ? truncf(f) : rintf(f);

    if (isnan(f)) {
        return signbit(f) ? 0u : 0xffffffffu;
    }
    if (!isfinite(f)) {
        return f > 0.0f ? 0xffffffffu : 0u;
    }
    /* P32-R7-12: 4294967295.0f rounds to 2^32; reject at >= 2^32. */
    if (r >= 4294967296.0f) {
        return 0xffffffffu;
    }
    if (r < 0.0f) {
        return 0u;
    }
    return (uint32_t)r;
}

static inline int32_t fp_d2i(double d, int z)
{
    double r = z ? trunc(d) : rint(d);

    if (isnan(d)) {
        return signbit(d) ? (int32_t)0x80000000 : 0x7fffffff;
    }
    if (!isfinite(d)) {
        return d > 0.0 ? 0x7fffffff : (int32_t)0x80000000;
    }
    if (r >= 2147483648.0) {
        return 0x7fffffff;
    }
    if (r < -2147483648.0) {
        return (int32_t)0x80000000;
    }
    return (int32_t)r;
}

static inline uint32_t fp_d2u(double d, int z)
{
    double r = z ? trunc(d) : rint(d);

    if (isnan(d)) {
        return signbit(d) ? 0u : 0xffffffffu;
    }
    if (!isfinite(d)) {
        return d > 0.0 ? 0xffffffffu : 0u;
    }
    if (r >= 4294967296.0) {
        return 0xffffffffu;
    }
    if (r < 0.0) {
        return 0u;
    }
    return (uint32_t)r;
}

#include "interp/fp_spe.h"

#endif /* PPC32_FP_H */
