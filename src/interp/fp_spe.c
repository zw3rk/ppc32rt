/*
 * src/interp/fp_spe.c -- e500v2 SPE single-step (Phase 3, lane L3a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from fp.c to respect the 900-line file limit; called by
 * ppc32_fp_step. Encoding tables in fp.h; qemu-ppc -cpu e500v2
 * is the ground-truth oracle.
 */
#include "interp/fp.h"

/* e500v2 SPE: D-form base in RA + 5-bit disp in RB; indexed uses
 * RA/RB; evldw == evldd; halfword forms shift by 2. */
static void fp_spe_ldst(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint32_t xo = insn->xo;
    uint32_t ea;
    if ((xo & 1u) == 0u) {
        ea = (insn->ra == 0u ? 0u : ctx->gpr[insn->ra]) +
            ctx->gpr[insn->rb];
    } else {
        unsigned sh = xo == PPC32_SPE_EVLWHE || xo == PPC32_SPE_EVLWHOU ||
            xo == PPC32_SPE_EVLWHOS || xo == PPC32_SPE_EVSTWWE ||
            xo == PPC32_SPE_EVSTWWO ? 2u : 3u;
        ea = (insn->ra == 0u ? 0u : ctx->gpr[insn->ra]) +
            ((uint32_t)insn->rb << sh);
    }
    switch (xo) {
    case PPC32_SPE_EVLDD: case PPC32_SPE_EVLDDX:
    case PPC32_SPE_EVLDW: case PPC32_SPE_EVLDWX:
        fp_gpr64_set(ctx, insn->rt, fp_ld64(ctx, ea));
        break;
    case PPC32_SPE_EVSTDD: case PPC32_SPE_EVSTDDX:
    case PPC32_SPE_EVSTDW: case PPC32_SPE_EVSTDWX:
        fp_st64(ctx, ea, fp_gpr64(ctx, insn->rt));
        break;
    case PPC32_SPE_EVLWHE:
    case PPC32_SPE_EVLWHEX:
        fp_gpr64_set(ctx, insn->rt, ((uint64_t)(ld32(ctx, ea) & 0xffff0000u)
            << 32) | (uint64_t)(ld32(ctx, ea + 2u) & 0xffff0000u));
        break;
    case PPC32_SPE_EVLWHOU:
    case PPC32_SPE_EVLWHOUX:
        fp_gpr64_set(ctx, insn->rt, ((uint64_t)(ld32(ctx, ea) >> 16)
            << 32) | (uint64_t)(ld32(ctx, ea + 2u) >> 16));
        break;
    case PPC32_SPE_EVLWHOS:
    case PPC32_SPE_EVLWHOSX: {
        int32_t h0 = (int32_t)(int16_t)(uint16_t)(ld32(ctx, ea) >> 16);
        int32_t h1 = (int32_t)(int16_t)(uint16_t)(ld32(ctx, ea + 2u) >> 16);
        fp_gpr64_set(ctx, insn->rt, ((uint64_t)(uint32_t)h0 << 32) |
            (uint64_t)(uint32_t)h1);
        break;
    }
    case PPC32_SPE_EVSTWWE:
    case PPC32_SPE_EVSTWWEX:
        st32(ctx, ea, ctx->gpr_hi[insn->rt & 31u]);
        break;
    case PPC32_SPE_EVSTWWO:
    case PPC32_SPE_EVSTWWOX:
        st32(ctx, ea, ctx->gpr[insn->rt & 31u]);
        break;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    ctx->nip += 4u;
}

/* Vector integer/logical/merge; evsubfw = B-A, evmr = evor. */
static void fp_spe_int(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = fp_gpr64(ctx, insn->ra);
    uint64_t b = fp_gpr64(ctx, insn->rb);
    uint32_t ah = (uint32_t)(a >> 32);
    uint32_t al = (uint32_t)a;
    uint32_t bh = (uint32_t)(b >> 32);
    uint32_t bl = (uint32_t)b;
    uint64_t r = 0u;
    switch (insn->xo) {
    case PPC32_SPE_EVADDW: r = ((uint64_t)(ah + bh) << 32) | (al + bl); break;
    case PPC32_SPE_EVSUBFW: r = ((uint64_t)(bh - ah) << 32) | (bl - al); break;
    case PPC32_SPE_EVAND: r = a & b; break;
    case PPC32_SPE_EVOR: r = a | b; break;
    case PPC32_SPE_EVXOR: r = a ^ b; break;
    case PPC32_SPE_EVMERGEHI: r = ((uint64_t)ah << 32) | bh; break;
    case PPC32_SPE_EVMERGELO: r = ((uint64_t)al << 32) | bl; break;
    case PPC32_SPE_EVMERGEHILO: r = ((uint64_t)ah << 32) | bl; break;
    case PPC32_SPE_EVMERGELOHI: r = ((uint64_t)al << 32) | bh; break;
    default: ctx->exit_reason = PPC32_EXIT_UNDEF; return;
    }
    fp_gpr64_set(ctx, insn->rt, r);
    ctx->nip += 4u;
}

/* evsel (matches qemu gen_evsel; hi<-A iff CR bit3, lo<-A iff bit2). */
static void fp_spe_sel(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = fp_gpr64(ctx, insn->ra);
    uint64_t b = fp_gpr64(ctx, insn->rb);
    uint32_t crf = (ctx->cr >> (4u * (7u - (insn->xo & 7u)))) & 0xfu;
    uint64_t r = ((crf & 8u) ? (a & 0xffffffff00000000ull) :
        (b & 0xffffffff00000000ull)) | ((crf & 4u) ? (a & 0xffffffffull) :
        (b & 0xffffffffull));
    fp_gpr64_set(ctx, insn->rt, r);
    ctx->nip += 4u;
}

/* Integer compares (qemu GEN_SPEOP_COMP; crD low bits reserved). */
static void fp_spe_cmp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = fp_gpr64(ctx, insn->ra);
    uint64_t b = fp_gpr64(ctx, insn->rb);
    unsigned bf = (insn->rt >> 2) & 7u;
    int hi = 0;
    int lo = 0;
    if ((insn->rt & 3u) != 0u) {
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    switch (insn->xo) {
    case PPC32_SPE_EVCMP_EQ:
        hi = (uint32_t)(a >> 32) == (uint32_t)(b >> 32);
        lo = (uint32_t)a == (uint32_t)b; break;
    case PPC32_SPE_EVCMP_GTS:
        hi = (int32_t)(a >> 32) > (int32_t)(b >> 32);
        lo = (int32_t)a > (int32_t)b; break;
    case PPC32_SPE_EVCMP_GTU:
        hi = (uint32_t)(a >> 32) > (uint32_t)(b >> 32);
        lo = (uint32_t)a > (uint32_t)b; break;
    case PPC32_SPE_EVCMP_LTS:
        hi = (int32_t)(a >> 32) < (int32_t)(b >> 32);
        lo = (int32_t)a < (int32_t)b; break;
    case PPC32_SPE_EVCMP_LTU:
        hi = (uint32_t)(a >> 32) < (uint32_t)(b >> 32);
        lo = (uint32_t)a < (uint32_t)b; break;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    ctx->cr = (ctx->cr & ~(0xfu << (4u * (7u - bf)))) |
        (fp_evcmp(hi, lo) << (4u * (7u - bf)));
    ctx->nip += 4u;
}

/* Scalar float compare bit (TRUE->0x4); single widens exactly. */
static uint32_t fp_spe_fcmp1(uint64_t a, uint64_t b, int op, int dbl)
{
    double fa = dbl ? fp_f64(a) : (double)fp_f32((uint32_t)a);
    double fb = dbl ? fp_f64(b) : (double)fp_f32((uint32_t)b);
    if (op == 0) {
        return !(fa <= fb) ? 4u : 0u;
    }
    if (op == 1) {
        return fa < fb ? 4u : 0u;
    }
    return fa == fb ? 4u : 0u;
}

/* Float compares (scalar 4-or-0; vector merges with bleed). */
static void fp_spe_fcmp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = fp_gpr64(ctx, insn->ra);
    uint64_t b = fp_gpr64(ctx, insn->rb);
    unsigned bf = (insn->rt >> 2) & 7u;
    uint32_t xo = insn->xo;
    uint32_t t = 0u;
    int dbl = 0;
    int vec = 0;
    uint32_t m;
    if ((insn->rt & 3u) != 0u) {
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    if (xo >= 716u && xo <= 718u) {
        t = xo - 716u;
    } else if (xo >= 732u && xo <= 734u) {
        t = xo - 732u;
    } else if (xo >= 748u && xo <= 750u) {
        t = xo - 748u;
        dbl = 1;
    } else if (xo >= 764u && xo <= 766u) {
        t = xo - 764u;
        dbl = 1;
    } else if (xo >= 652u && xo <= 654u) {
        t = xo - 652u;
        vec = 1;
    } else if (xo >= 668u && xo <= 670u) {
        t = xo - 668u;
        vec = 1;
    } else {
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    if (vec) {
        m = fp_fcmp_merge(fp_spe_fcmp1(a >> 32, b >> 32, (int)t, 0),
            fp_spe_fcmp1(a, b, (int)t, 0));
    } else {
        m = fp_spe_fcmp1(a, b, (int)t, dbl);
    }
    if (m > 15u) {
        fp_set_crf_bleed(ctx, bf, m);
    } else {
        ctx->cr = (ctx->cr & ~(0xfu << (4u * (7u - bf)))) |
            (m << (4u * (7u - bf)));
    }
    ctx->nip += 4u;
}

/* efs/efd/evfs arithmetic (dispatch gates base/off shapes). */
static void fp_spe_arith(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = fp_gpr64(ctx, insn->ra);
    uint64_t b = fp_gpr64(ctx, insn->rb);
    uint32_t x = insn->xo;
    uint32_t base = x >= 736u ? 736u : x >= 704u ? 704u : 640u;
    unsigned off = x - base;
    int is_abs;
    is_abs = off >= 4u && off <= 6u;
    if (!is_abs) {
        int op = off == 0u ? 0 : off == 1u ? 1 : off == 8u ? 2 : 3;
        if (base == 640u) {
            fp_gpr64_set(ctx, insn->rt, ((uint64_t)fp_efs_arith(
                (uint32_t)(a >> 32), (uint32_t)(b >> 32), op) << 32) |
                (uint64_t)fp_efs_arith((uint32_t)a, (uint32_t)b, op));
        } else if (base == 704u) {
            ctx->gpr[insn->rt & 31u] = fp_efs_arith((uint32_t)a,
                (uint32_t)b, op);
        } else {
            fp_gpr64_set(ctx, insn->rt, fp_efd_arith(a, b, op));
        }
    } else if (base == 704u) {
        uint32_t w = (uint32_t)a;
        uint32_t m = off == 4u ? 0x7fffffffu : 0x80000000u;
        ctx->gpr[insn->rt & 31u] = off == 4u ? w & m : off == 5u ?
            w | m : w ^ m;
    } else {
        uint64_t m = off == 4u ? 0x7fffffffffffffffull :
            0x8000000000000000ull;
        fp_gpr64_set(ctx, insn->rt, off == 4u ? a & m : off == 5u ?
            a | m : a ^ m);
    }
    ctx->nip += 4u;
}

/* Converts: 32-bit-out preserves hi; 64-bit-out writes full.
 * efscfd narrows a double to lo; scalar cf ops yield singles. */
static void fp_spe_conv(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t b = fp_gpr64(ctx, insn->rb);
    uint64_t r = 0u;
    int full = 0;
    uint32_t x = insn->xo;
    if (x == PPC32_SPE_EFSCFD) {
        r = fp_spe_cvt(b, 10, 1);
    } else if (x == PPC32_SPE_EFDCFS) {
        r = fp_spe_cvt(b, 10, 0);
        full = 1;
    } else if (x >= 656u && x <= 666u) {
        int vo[] = { 7, 6, 8, 9, 1, 0, 5, 4, 3, -1, 2 };
        int op = vo[x - 656u];
        if (op < 0) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
        r = ((uint64_t)(uint32_t)fp_spe_cvt(b >> 32, op, 0) << 32) |
            (uint64_t)(uint32_t)fp_spe_cvt(b, op, 0);
        full = 1;
    } else if (x >= 719u && x <= 730u) {
        int so[] = { 10, 7, 6, 8, 9, 1, 0, 5, 4, 3, -1, 2 };
        int op = so[x - 719u];
        if (op < 0) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
        r = fp_spe_cvt(b, op, 0);
    } else if (x == 751u) {
        r = fp_spe_cvt(b, 10, 1);
    } else if (x >= 752u && x <= 762u) {
        int dlo[] = { 7, 6, 8, 9, 1, 0, 5, 4, 3, -1, 2 };
        int op = dlo[x - 752u];
        if (op < 0) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
        r = fp_spe_cvt(b, op, 1);
        full = 1;
    } else {
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    if (full) {
        fp_gpr64_set(ctx, insn->rt, r);
    } else {
        ctx->gpr[insn->rt & 31u] = (uint32_t)r;
    }
    ctx->nip += 4u;
}

/* MAC (qemu SIGILLs; EREF-best-effort; evmra oracle-verified).
 * Row flags: s,f,acc,acp,sat,high,half,odd (see fp_spe_mac). */
static void fp_spe_macd(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    static const uint32_t mxs[] = { PPC32_SPE_EVMWHSMF, PPC32_SPE_EVMWHSMFA,
        PPC32_SPE_EVMWHSMIA, PPC32_SPE_EVMWHSMIAA, PPC32_SPE_EVMWHSSF,
        PPC32_SPE_EVMWHSSFA, PPC32_SPE_EVMWHUMIA, PPC32_SPE_EVMWHUMIAA,
        PPC32_SPE_EVMWHUSIAA, PPC32_SPE_EVMWLUMIA, PPC32_SPE_EVMHEGSMIAA,
        PPC32_SPE_EVMHEGUMIAA, PPC32_SPE_EVMHOGSMIAA, PPC32_SPE_EVMHOGUMIAA };
    static const uint8_t mps[][8] = { { 1, 1, 0, 0, 0, 1, 0, 0 },
        { 1, 1, 1, 0, 0, 1, 0, 0 }, { 1, 0, 1, 0, 0, 1, 0, 0 },
        { 1, 0, 0, 1, 0, 1, 0, 0 }, { 1, 1, 0, 0, 1, 1, 0, 0 },
        { 1, 1, 1, 0, 1, 1, 0, 0 }, { 0, 0, 1, 0, 0, 1, 0, 0 },
        { 0, 0, 0, 1, 0, 1, 0, 0 }, { 0, 0, 0, 1, 1, 1, 0, 0 },
        { 0, 0, 1, 0, 0, 0, 0, 0 }, { 1, 0, 0, 1, 0, 0, 1, 0 },
        { 0, 0, 0, 1, 0, 0, 1, 0 }, { 1, 0, 0, 1, 0, 0, 1, 1 },
        { 0, 0, 0, 1, 0, 0, 1, 1 } };
    uint64_t a = fp_gpr64(ctx, insn->ra);
    uint64_t b = fp_gpr64(ctx, insn->rb);
    uint64_t d = fp_gpr64(ctx, insn->rt);
    int i;

    if (insn->xo == PPC32_SPE_EVMRA) {
        if (insn->rb != 0u) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
        ctx->acc = a;
        fp_gpr64_set(ctx, insn->rt, a);
        ctx->nip += 4u;
        return;
    }
    for (i = 0; i < 14; i++) {
        if (insn->xo == mxs[i]) {
            fp_gpr64_set(ctx, insn->rt, fp_spe_mac(ctx, a, b, d, mps[i][0],
                mps[i][1], mps[i][2], mps[i][3], mps[i][4], mps[i][5],
                mps[i][6], mps[i][7]));
            ctx->nip += 4u;
            return;
        }
    }
    ctx->exit_reason = PPC32_EXIT_UNDEF;
}

/* Arithmetic-shape XOs per family base (op offsets 0,1,4,5,6,8,9). */
static int fp_arithxo(uint32_t x)
{
    uint32_t b = x >= 736u ? 736u : x >= 704u ? 704u : x >= 640u ? 640u : 0u;
    unsigned o;
    if (b == 0u || x - b > 9u) {
        return 0;
    }
    o = x - b;
    return o < 2u || (o >= 4u && o <= 6u) || o == 8u || o == 9u;
}

/* Float-compare XOs: six contiguous triples. */
static int fp_cmpxo(uint32_t x)
{
    return (x >= 716u && x <= 718u) || (x >= 732u && x <= 734u) ||
        (x >= 748u && x <= 750u) || (x >= 764u && x <= 766u) ||
        (x >= 652u && x <= 654u) || (x >= 668u && x <= 670u);
}

/* SPE dispatch (full 11-bit XO; even/odd select paired ldst ops). */
void fp_spe(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint32_t xo = insn->xo;
    if (xo >= 560u && xo <= 564u) {
        fp_spe_cmp(ctx, insn);
    } else if (xo >= 512u && xo <= 559u) {
        fp_spe_int(ctx, insn);
    } else if (xo >= PPC32_SPE_EVSEL_BASE &&
        xo < PPC32_SPE_EVSEL_BASE + 8u) {
        fp_spe_sel(ctx, insn);
    } else if ((xo >= 768u && xo <= 803u) || (xo >= 824u && xo <= 829u)) {
        fp_spe_ldst(ctx, insn);
    } else if (fp_arithxo(xo)) {
        fp_spe_arith(ctx, insn);
    } else if (fp_cmpxo(xo)) {
        fp_spe_fcmp(ctx, insn);
    } else if ((xo >= 640u && xo <= 670u) || (xo >= 704u && xo <= 734u) ||
        (xo >= 736u && xo <= 766u)) {
        fp_spe_conv(ctx, insn);
    } else {
        fp_spe_macd(ctx, insn);
    }
}
