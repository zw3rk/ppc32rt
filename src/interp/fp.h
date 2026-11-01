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

/* OR exception bits; recompute FX/FEX summaries (never raises). */
static inline void fp_raise(ppc32_ctx_t *ctx, uint32_t bits)
{
    uint32_t f = ctx->fpscr | bits;

    if ((f & (F_VX_M | F_OX_M | F_UX_M | F_ZX_M | F_XX_M | F_VXSNAN_M |
        F_VXISI_M | F_VXIDI_M | F_VXZDZ_M | F_VXIMZ_M | F_VXVC_M)) != 0u) {
        f |= F_FX_M;
    }
    /* FEX iff any cause (VX,OX,UX,ZX,XX = bits 29..25) pairs with its
     * enable (bits 7..3). */
    if ((((f >> 25) & 0x1fu) & ((f >> 3) & 0x1fu)) != 0u) {
        f |= F_FEX_M;
    }
    ctx->fpscr = f;
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

/* CR1 <- FPSCR[FX,FEX,VX,OX] (matches qemu gen_set_cr1_from_fpscr). */
static inline void fp_cr1(ppc32_ctx_t *ctx)
{
    uint32_t v = (ctx->fpscr >> 28) & 0xfu;
    ctx->cr = (ctx->cr & ~(0xfu << 4)) | (v << 4);
}

/* FPRF recompute + FI assign (FR stale-kept; qemu never sets FR, invalid
 * paths clear FR|FI explicitly). */
static inline void fp_flags_arith(ppc32_ctx_t *ctx, uint64_t res, int inexact,
    uint32_t sticky)
{
    uint32_t f;

    fp_raise(ctx, sticky);
    f = ctx->fpscr;
    f &= ~(0x1fu << 12);
    f |= fp_fprf64(res) << 12;
    f &= ~F_FI_M;
    if (inexact) {
        f |= F_FI_M;
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

/* Invalid combos on doubles (op: 0 add, 1 sub, 2 mul, 3 div). */
static inline uint32_t fp_inv2(int op, uint64_t a, uint64_t b)
{
    if (op == 0 || op == 1) {
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

/* Invalid combos on singles (post-conversion). */
static inline uint32_t fp_inv2s(int op, uint32_t a, uint32_t b)
{
    if (op == 0 || op == 1) {
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

/* Scalar/vector float compare bit (matches qemu scalar helpers and merge;
 * scalar TRUE->0x4 else 0; vector merges per-half 0/4 with bleed). */
static inline uint32_t fp_fcmp_merge(uint32_t t0, uint32_t t1)
{
    return (t0 << 3) | (t1 << 2) | ((t0 | t1) << 1) | (t0 & t1);
}

/* Write CR field with vector-merge bleed (matches qemu mfcr; values >15
 * bleed into the neighbor low bits). */
static inline void fp_set_crf_bleed(ppc32_ctx_t *ctx, unsigned bf,
    uint32_t m)
{
    uint32_t shift = 4u * (7u - (bf & 7u));

    ctx->cr = (ctx->cr & ~(0xfu << shift)) | ((m & 0xfu) << shift);
    if (bf > 0u && (m >> 4) != 0u) {
        uint32_t nshift = 4u * (7u - ((bf - 1u) & 7u));

        ctx->cr |= ((m >> 4) & 0x3u) << nshift;
    }
}

/* Scalar-single efs arithmetic core (nearest always; NaN: first-operand
 * payload, SNaN quieted silently; result zero-extends). */
static inline uint32_t fp_efs_arith(uint32_t a, uint32_t b, int op)
{
    float fa = fp_f32(a);
    float fb = fp_f32(b);

    if (fp_snan(a) || fp_snan(b)) {
        return (fp_snan(a) ? a : b) | 0x400000u;
    }
    if (op == 0) {
        return fp_u32(fa + fb);
    }
    if (op == 1) {
        return fp_u32(fa - fb);
    }
    if (op == 2) {
        return fp_u32(fa * fb);
    }
    return fp_u32(fa / fb);
}

/* Double efd arithmetic core (nearest always; NaN first-operand). */
static inline uint64_t fp_efd_arith(uint64_t a, uint64_t b, int op)
{
    double fa = fp_f64(a);
    double fb = fp_f64(b);

    if (fp_isnan(a) || fp_isnan(b)) {
        return (fp_isnan(a) ? a : b) | 0x8000000000000ull;
    }
    if (op == 0) {
        return fp_u64(fa + fb);
    }
    if (op == 1) {
        return fp_u64(fa - fb);
    }
    if (op == 2) {
        return fp_u64(fa * fb);
    }
    return fp_u64(fa / fb);
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
    if (r > 2147483647.0f) {
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
    if (r > 4294967295.0f) {
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
    if (r > 2147483647.0) {
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
    if (r > 4294967295.0) {
        return 0xffffffffu;
    }
    if (r < 0.0) {
        return 0u;
    }
    return (uint32_t)r;
}

/* SPE converts (qemu helpers/macros; nearest-always; silent). single
 * ct*: QNaN->0 else invalid->max; double ct*: any-NaN->0. Fractional
 * x2^32. Scalar cf* yield 32-bit singles, efdcf* 64-bit doubles,
 * efscfd narrows a double to a single in lo, efdcfs widens a single
 * to a double. op: 0 ctsi, 1 ctui, 2 ctsiz, 3 ctuiz, 4 ctsf, 5 ctuf,
 * 6 cfsi, 7 cfui, 8 cfsf, 9 cfuf, 10 cfd/cfs. Callers write lo-only
 * for 32-bit-out (hi preserved via split storage). */
static inline uint64_t fp_spe_cvt(uint64_t in, int op, int is_dbl_in)
{
    if (!is_dbl_in) {
        uint32_t v = (uint32_t)in;
        float f = fp_f32(v);

        if (op <= 5) {
            if (fp_snan(v) && ((v >> 22) & 1u) != 0u) {
                return 0u; /* single QNaN input converts to 0 */
            }
            if (op == 0) {
                return (uint64_t)(uint32_t)fp_f2i(f, 0);
            }
            if (op == 1) {
                return (uint64_t)(uint32_t)fp_f2u(f, 0);
            }
            if (op == 2) {
                return (uint64_t)(uint32_t)fp_f2i(f, 1);
            }
            if (op == 3) {
                return (uint64_t)(uint32_t)fp_f2u(f, 1);
            }
            if (op == 4) {
                return (uint64_t)(uint32_t)fp_f2i(f * 4294967296.0f, 0);
            }
            return (uint64_t)(uint32_t)fp_f2u(f * 4294967296.0f, 0);
        }
        if (op <= 9) {
            if (op == 6) {
                return fp_u32((float)(int32_t)v);
            }
            if (op == 7) {
                return fp_u32((float)v);
            }
            if (op == 8) {
                return fp_u32((float)(int32_t)v / 4294967296.0f);
            }
            return fp_u32((float)v / 4294967296.0f);
        }
        if (fp_snan(v) && ((v >> 22) & 1u) == 0u) {
            v |= 0x400000u;
        }
        return fp_xtod(v);
    }
    {
        double d = fp_f64(in);

        if (op <= 5) {
            if (fp_isnan(in)) return 0u;
            if (op == 0) {
                return (uint64_t)(uint32_t)fp_d2i(d, 0);
            }
            if (op == 1) {
                return (uint64_t)(uint32_t)fp_d2u(d, 0);
            }
            if (op == 2) {
                return (uint64_t)(uint32_t)fp_d2i(d, 1);
            }
            if (op == 3) {
                return (uint64_t)(uint32_t)fp_d2u(d, 1);
            }
            if (op == 4) {
                return (uint64_t)(uint32_t)fp_d2i(d * 4294967296.0, 0);
            }
            return (uint64_t)(uint32_t)fp_d2u(d * 4294967296.0, 0);
        }
        if (op <= 9) {
            if (op == 6) {
                return fp_u64((double)(int32_t)(uint32_t)in);
            }
            if (op == 7) {
                return fp_u64((double)(uint32_t)in);
            }
            if (op == 8) {
                return fp_u64((double)(int32_t)(uint32_t)in / 4294967296.0);
            }
            return fp_u64((double)(uint32_t)in / 4294967296.0);
        }
        {
            uint32_t w;

            if (fp_isnan(in)) {
                w = (uint32_t)(((in >> 29) & 0x7fffffu) | 0x7f800000u |
                    ((in >> 63) << 31) | 0x400000u);
            } else {
                w = fp_u32((float)d);
            }
            return (uint64_t)w;
        }
    }
}

/* SPE MAC (EREF-best-effort; qemu-ppc SIGILLs all MAC, unverifiable
 * via oracle. Whole-word: LOW words 32x32->64; even/odd: halfword
 * pairs. s=signed, f=fractional, a=accum-rD-lo, c=accum-via-ACC,
 * t=saturate, h=high-32 (else low-32). Fractional high = prod>>31;
 * -1*-1 wraps or saturates. Whole-word zeroes rD.hi; halfword is
 * full 64-bit. evmra (rD=rA, ACC=rA) matches qemu. */
static inline uint64_t fp_spe_mac(ppc32_ctx_t *ctx, uint64_t a, uint64_t b,
    uint64_t d, int s, int f, int acc, int acp, int sat, int high, int half,
    int odd)
{
    if (half) {
        uint32_t a0 = (uint32_t)((a >> (odd ? 32u : 48u)) & 0xffffu);
        uint32_t a1 = (uint32_t)((a >> (odd ? 0u : 16u)) & 0xffffu);
        uint32_t b0 = (uint32_t)((b >> (odd ? 32u : 48u)) & 0xffffu);
        uint32_t b1 = (uint32_t)((b >> (odd ? 0u : 16u)) & 0xffffu);
        uint32_t p0 = s ? (uint32_t)((int32_t)(int16_t)a0 *
            (int32_t)(int16_t)b0) : a0 * b0;
        uint32_t p1 = s ? (uint32_t)((int32_t)(int16_t)a1 *
            (int32_t)(int16_t)b1) : a1 * b1;
        uint64_t cat = ((uint64_t)p0 << 32) | p1;

        if (acp) {
            cat += ctx->acc;
            ctx->acc = cat;
            return cat;
        }
        return ((uint64_t)(p0 + (uint32_t)(d >> 32)) << 32) |
            (uint64_t)(p1 + (uint32_t)d);
    }
    {
        uint64_t prod = s ? (uint64_t)((int64_t)(int32_t)(uint32_t)a *
            (int64_t)(int32_t)(uint32_t)b) : (uint64_t)(uint32_t)a *
            (uint64_t)(uint32_t)b;
        uint32_t sel;

        if (f) {
            if (prod == 0x4000000000000000ull) {
                sel = sat ? 0x7fffffffu : 0x80000000u;
            } else {
                sel = (uint32_t)((prod >> 31) & 0xffffffffu);
            }
        } else {
            sel = high ? (uint32_t)(prod >> 32) : (uint32_t)prod;
        }
        if (acp) {
            uint64_t old = ctx->acc;

            ctx->acc += prod;
            if (sat && ctx->acc < old) {
                return 0xffffffffu;
            }
            return (uint64_t)(high ? (uint32_t)(ctx->acc >> 32) :
                (uint32_t)ctx->acc);
        }
        if (acc) {
            if (sat) {
                int64_t sum = (int64_t)(int32_t)sel +
                    (int64_t)(int32_t)(uint32_t)d;

                if (sum > 2147483647ll) {
                    return 0x7fffffffu;
                }
                if (sum < -2147483648ll) {
                    return 0x80000000u;
                }
                return (uint64_t)(uint32_t)(int32_t)sum;
            }
            sel += (uint32_t)d;
        }
        return (uint64_t)sel;
    }
}

/* ---- primary-31 floating-point indexed (full 10-bit XO) -------------- */
#define PPC32_FPUX_LFSX 535u
#define PPC32_FPUX_LFSUX 567u
#define PPC32_FPUX_LFDX 599u
#define PPC32_FPUX_LFDUX 631u
#define PPC32_FPUX_STFSX 663u
#define PPC32_FPUX_STFSUX 695u
#define PPC32_FPUX_STFDX 727u
#define PPC32_FPUX_STFDUX 759u

/* ---- primary-59 single A-form (5-bit XO = xo & 31) ------------------- */
#define PPC32_FS_FDIVS 18u
#define PPC32_FS_FSUBS 20u
#define PPC32_FS_FADDS 21u
#define PPC32_FS_FSQRTS 22u
#define PPC32_FS_FMULS 25u
#define PPC32_FS_FMSUBS 28u
#define PPC32_FS_FMADDS 29u
#define PPC32_FS_FNMSUBS 30u
#define PPC32_FS_FNMADDS 31u

/* ---- primary-63 double A-form (5-bit XO = xo & 31, FRC = bi) --------- */
#define PPC32_FD_FDIV 18u
#define PPC32_FD_FSUB 20u
#define PPC32_FD_FADD 21u
#define PPC32_FD_FSQRT 22u
#define PPC32_FD_FSEL 23u
#define PPC32_FD_FMUL 25u
#define PPC32_FD_FMSUB 28u
#define PPC32_FD_FMADD 29u
#define PPC32_FD_FNMSUB 30u
#define PPC32_FD_FNMADD 31u

/* ---- primary-63 double X-form (full 10-bit XO) ----------------------- */
#define PPC32_FD_FCMPU 0u
#define PPC32_FD_FRSP 12u
#define PPC32_FD_FCTIW 14u
#define PPC32_FD_FCTIWZ 15u
#define PPC32_FD_FCMPO 32u
#define PPC32_FD_FNEG 40u
#define PPC32_FD_FMR 72u
#define PPC32_FD_FNABS 136u
#define PPC32_FD_FABS 264u
#define PPC32_FD_MFFS 583u
#define PPC32_FD_MTFSF 711u
#define PPC32_FD_MTFSFI 134u
#define PPC32_FD_MTFSB0 70u
#define PPC32_FD_MTFSB1 38u

/* ---- e500v2 SPE integer/logical/merge (full 11-bit XO) --------------- */
#define PPC32_SPE_EVADDW 512u
#define PPC32_SPE_EVAND 529u
#define PPC32_SPE_EVOR 535u
#define PPC32_SPE_EVXOR 534u
#define PPC32_SPE_EVSUBFW 516u
#define PPC32_SPE_EVMERGEHI 556u
#define PPC32_SPE_EVMERGELO 557u
#define PPC32_SPE_EVMERGEHILO 558u
#define PPC32_SPE_EVMERGELOHI 559u
#define PPC32_SPE_EVCMP_GTU 560u
#define PPC32_SPE_EVCMP_GTS 561u
#define PPC32_SPE_EVCMP_LTU 562u
#define PPC32_SPE_EVCMP_LTS 563u
#define PPC32_SPE_EVCMP_EQ 564u

/* ---- e500v2 SPE loads/stores (odd = D-form, even = indexed) ---------- */
#define PPC32_SPE_EVLDD 769u
#define PPC32_SPE_EVLDDX 768u
#define PPC32_SPE_EVLDW 771u
#define PPC32_SPE_EVLDWX 770u
#define PPC32_SPE_EVSTDD 801u
#define PPC32_SPE_EVSTDDX 800u
#define PPC32_SPE_EVSTDW 803u
#define PPC32_SPE_EVSTDWX 802u
#define PPC32_SPE_EVLWHE 785u
#define PPC32_SPE_EVLWHEX 784u
#define PPC32_SPE_EVLWHOU 789u
#define PPC32_SPE_EVLWHOUX 788u
#define PPC32_SPE_EVLWHOS 791u
#define PPC32_SPE_EVLWHOSX 790u
#define PPC32_SPE_EVSTWWE 825u
#define PPC32_SPE_EVSTWWEX 824u
#define PPC32_SPE_EVSTWWO 829u
#define PPC32_SPE_EVSTWWOX 828u

/* evsel base (low 3 bits carry crS): 632 + crS */
#define PPC32_SPE_EVSEL_BASE 632u

/* ---- e500v2 SPE scalar-single efs (full 11-bit XO) ------------------- */
#define PPC32_SPE_EFSADD 704u
#define PPC32_SPE_EFSSUB 705u
#define PPC32_SPE_EFSABS 708u
#define PPC32_SPE_EFSNABS 709u
#define PPC32_SPE_EFSNEG 710u
#define PPC32_SPE_EFSMUL 712u
#define PPC32_SPE_EFSDIV 713u
#define PPC32_SPE_EFSCMPGT 716u
#define PPC32_SPE_EFSCMPLT 717u
#define PPC32_SPE_EFSCMPEQ 718u
#define PPC32_SPE_EFSCFD 719u
#define PPC32_SPE_EFSCFUI 720u
#define PPC32_SPE_EFSCFSI 721u
#define PPC32_SPE_EFSCFUF 722u
#define PPC32_SPE_EFSCFSF 723u
#define PPC32_SPE_EFSCTUI 724u
#define PPC32_SPE_EFSCTSI 725u
#define PPC32_SPE_EFSCTUF 726u
#define PPC32_SPE_EFSCTSF 727u
#define PPC32_SPE_EFSCTUIZ 728u
#define PPC32_SPE_EFSCTSIZ 730u
#define PPC32_SPE_EFSTSTGT 732u
#define PPC32_SPE_EFSTSTLT 733u
#define PPC32_SPE_EFSTSTEQ 734u

/* ---- e500v2 SPE scalar-double efd (full 11-bit XO) ------------------- */
#define PPC32_SPE_EFDADD 736u
#define PPC32_SPE_EFDSUB 737u
#define PPC32_SPE_EFDABS 740u
#define PPC32_SPE_EFDNABS 741u
#define PPC32_SPE_EFDNEG 742u
#define PPC32_SPE_EFDMUL 744u
#define PPC32_SPE_EFDDIV 745u
#define PPC32_SPE_EFDCMPGT 748u
#define PPC32_SPE_EFDCMPLT 749u
#define PPC32_SPE_EFDCMPEQ 750u
#define PPC32_SPE_EFDCFS 751u
#define PPC32_SPE_EFDCFUI 752u
#define PPC32_SPE_EFDCFSI 753u
#define PPC32_SPE_EFDCFUF 754u
#define PPC32_SPE_EFDCFSF 755u
#define PPC32_SPE_EFDCTUI 756u
#define PPC32_SPE_EFDCTSI 757u
#define PPC32_SPE_EFDCTUF 758u
#define PPC32_SPE_EFDCTSF 759u
#define PPC32_SPE_EFDCTUIZ 760u
#define PPC32_SPE_EFDCTSIZ 762u
#define PPC32_SPE_EFDTSTGT 764u
#define PPC32_SPE_EFDTSTLT 765u
#define PPC32_SPE_EFDTSTEQ 766u

/* ---- e500v2 SPE vector-single evfs (full 11-bit XO) ------------------ */
#define PPC32_SPE_EVFSADD 640u
#define PPC32_SPE_EVFSSUB 641u
#define PPC32_SPE_EVFSABS 644u
#define PPC32_SPE_EVFSNABS 645u
#define PPC32_SPE_EVFSNEG 646u
#define PPC32_SPE_EVFSMUL 648u
#define PPC32_SPE_EVFSDIV 649u
#define PPC32_SPE_EVFSCMPGT 652u
#define PPC32_SPE_EVFSCMPLT 653u
#define PPC32_SPE_EVFSCMPEQ 654u
#define PPC32_SPE_EVFSCFUI 656u
#define PPC32_SPE_EVFSCFSI 657u
#define PPC32_SPE_EVFSCFUF 658u
#define PPC32_SPE_EVFSCFSF 659u
#define PPC32_SPE_EVFSCTUI 660u
#define PPC32_SPE_EVFSCTSI 661u
#define PPC32_SPE_EVFSCTUF 662u
#define PPC32_SPE_EVFSCTSF 663u
#define PPC32_SPE_EVFSCTUIZ 664u
#define PPC32_SPE_EVFSCTSIZ 666u
#define PPC32_SPE_EVFSTSTGT 668u
#define PPC32_SPE_EVFSTSTLT 669u
#define PPC32_SPE_EVFSTSTEQ 670u

/* ---- e500v2 SPE MAC (full 11-bit XO; EREF semantics, see above) ------ */
#define PPC32_SPE_EVMWHSMF 1103u
#define PPC32_SPE_EVMWHSMFA 1135u
#define PPC32_SPE_EVMWHSMIA 1133u
#define PPC32_SPE_EVMWHSMIAA 1357u
#define PPC32_SPE_EVMWHSSF 1095u
#define PPC32_SPE_EVMWHSSFA 1127u
#define PPC32_SPE_EVMWHUMIA 1132u
#define PPC32_SPE_EVMWHUMIAA 1356u
#define PPC32_SPE_EVMWHUSIAA 1348u
#define PPC32_SPE_EVMWLUMIA 1128u
#define PPC32_SPE_EVMHEGSMIAA 1321u
#define PPC32_SPE_EVMHEGUMIAA 1320u
#define PPC32_SPE_EVMHOGSMIAA 1325u
#define PPC32_SPE_EVMHOGUMIAA 1324u
#define PPC32_SPE_EVMRA 1220u

#endif /* PPC32_FP_H */
