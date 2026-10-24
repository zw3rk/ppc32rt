/*
 * src/interp/fp.c — classic-FPU + e500v2-SPE single-step (Phase 3, lane L3a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Encoding tables in fp.h; qemu-ppc oracle semantics (-cpu 750/e500v2).
 */
#include "interp/fp.h"
/* Host FP environment capture; entry rounding restored on exit. */
static int fp_begin(ppc32_ctx_t *ctx)
{
    int old = fegetround();
    fp_setrn(fp_rn(ctx));
    feclearexcept(FE_ALL_EXCEPT);
    return old;
}

/* Sticky FPSCR bits from the captured host flags; restores rounding. */
static uint32_t fp_end(int old)
{
    uint32_t st = 0u;
    if (fetestexcept(FE_INEXACT) != 0) {
        st |= F_XX_M;
    }
    if (fetestexcept(FE_OVERFLOW) != 0) {
        st |= F_OX_M;
    }
    if (fetestexcept(FE_UNDERFLOW) != 0) {
        st |= F_UX_M;
    }
    if (fetestexcept(FE_DIVBYZERO) != 0) {
        st |= F_ZX_M;
    }
    fesetround(old);
    return st;
}

/* Invalid-input QNaN result (FR|FI cleared, VX|vx raised). */
static void fp_invalid(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t vx, int single)
{
    uint64_t q = single ? fp_xtod(0x7fc00000u) : 0x7ff8000000000000ull;
    ctx->fpscr &= ~(F_FR_M | F_FI_M);
    fp_flags_arith(ctx, q, 0, 0);
    fp_raise(ctx, vx | F_VX_M);
    fp_done(ctx, insn, q);
}

/* Store quieted NaN; SNaN clears FR and raises VXSNAN|VX. */
static void fp_nanres(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, uint64_t n,
    int snan, int single)
{
    uint64_t q = single ? fp_xtod(fp_qnan32(n)) : n;
    ctx->fpscr &= ~F_FI_M;
    if (snan) {
        ctx->fpscr &= ~F_FR_M;
        fp_raise(ctx, F_VXSNAN_M | F_VX_M);
    }
    fp_flags_arith(ctx, q, 0, 0);
    fp_done(ctx, insn, q);
}

/* Commit rounded result: INEXACT, sticky bits, restore, store. */
static void fp_commit(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, uint64_t r,
    int old)
{
    int inexact = fetestexcept(FE_INEXACT) != 0;
    uint32_t st = fp_end(old);
    fp_flags_arith(ctx, r, inexact, st);
    fp_done(ctx, insn, r);
}

/* Shared classic load/store body (true single<->double conversion). */
static void fp_memop(ppc32_ctx_t *ctx, uint32_t ea, unsigned rt, int is_ld,
    int is_dbl)
{
    if (is_ld) {
        ctx->fpr[rt & 31u] = is_dbl ? fp_ld64(ctx, ea) : fp_xtod(ld32(ctx,
            ea));
    } else if (is_dbl) {
        fp_st64(ctx, ea, ctx->fpr[rt & 31u]);
    } else {
        st32(ctx, ea, fp_dtos(ctx->fpr[rt & 31u]));
    }
    ctx->nip += 4u;
}

/* ---- classic loads/stores (true conversion for lfs/stfs) ------------ */
static void fp_lsD(ppc32_ctx_t *ctx, unsigned rt, unsigned ra, int32_t d,
    int is_ld, int is_dbl, int upd)
{
    uint32_t ea = (ra == 0u ? 0u : ctx->gpr[ra]) + (uint32_t)d;
    if (upd) {
        if (ra == 0u) { ctx->exit_reason = PPC32_EXIT_UNDEF; return; }
        ctx->gpr[ra] = ea;
    }
    fp_memop(ctx, ea, rt, is_ld, is_dbl);
}

static void fp_lsX(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int is_ld,
    int is_dbl)
{
    int upd = insn->xo == PPC32_FPUX_LFSUX || insn->xo == PPC32_FPUX_LFDUX ||
        insn->xo == PPC32_FPUX_STFSUX || insn->xo == PPC32_FPUX_STFDUX;
    uint32_t ea = (insn->ra == 0u ? 0u : ctx->gpr[insn->ra]) +
        ctx->gpr[insn->rb];
    if (upd) {
        if (insn->ra == 0u) { ctx->exit_reason = PPC32_EXIT_UNDEF; return; }
        ctx->gpr[insn->ra] = ea;
    }
    fp_memop(ctx, ea, insn->rt, is_ld, is_dbl);
}

/* Classic arithmetic: op 0 add, 1 sub, 2 mul, 3 div. */
static void fp_arith(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int op,
    int single)
{
    uint64_t da = ctx->fpr[insn->ra & 31u];
    uint64_t db = ctx->fpr[insn->rb & 31u];
    uint64_t n = 0u;
    int snan = 0;
    uint64_t r;
    uint32_t sub;
    if (fp_nan2(da, db, &n, &snan)) {
        fp_nanres(ctx, insn, n, snan, single);
        return;
    }
    if (single) {
        int old = fp_begin(ctx);
        float fa = (float)fp_f64(da);
        float fb = (float)fp_f64(db);
        sub = fp_inv2s(op, fp_u32(fa), fp_u32(fb));
        if (sub != 0u) {
            fesetround(old);
            fp_invalid(ctx, insn, sub, 1);
            return;
        }
        if (op == 0) {
            r = fp_xtod(fp_u32(fa + fb));
        } else if (op == 1) {
            r = fp_xtod(fp_u32(fa - fb));
        } else if (op == 2) {
            r = fp_xtod(fp_u32(fa * fb));
        } else {
            r = fp_xtod(fp_u32(fa / fb));
        }
        fp_commit(ctx, insn, r, old);
        return;
    }
    sub = fp_inv2(op, da, db);
    if (sub != 0u) {
        fp_invalid(ctx, insn, sub, 0);
        return;
    }
    {
        double fr;
        int old = fp_begin(ctx);
        if (op == 0) {
            fr = fp_f64(da) + fp_f64(db);
        } else if (op == 1) {
            fr = fp_f64(da) - fp_f64(db);
        } else if (op == 2) {
            fr = fp_f64(da) * fp_f64(db);
        } else {
            fr = fp_f64(da) / fp_f64(db);
        }
        r = fp_u64(fr);
        fp_commit(ctx, insn, r, old);
    }
}

/* Fused multiply-add; kind: 0 madd, 1 msub, 2 nmadd, 3 nmsub. */
static void fp_fused(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int kind,
    int single)
{
    uint64_t pa = ctx->fpr[insn->ra & 31u];
    uint64_t pc = ctx->fpr[insn->bi & 31u];
    uint64_t pb = ctx->fpr[insn->rb & 31u];
    uint64_t ops[3];
    uint64_t r;
    uint64_t n = 0u;
    int nn = 0;
    int snan = 0;
    int i;
    ops[0] = pa;
    ops[1] = pc;
    ops[2] = pb;
    for (i = 0; i < 3; i++) {
        if (fp_isnan(ops[i])) {
            if (!nn) {
                n = ops[i];
            }
            nn = 1;
            if ((ops[i] & 0x8000000000000ull) == 0u) {
                snan = 1;
            }
        }
    }
    if (nn) {
        if ((n & 0x8000000000000ull) == 0u) {
            n |= 0x8000000000000ull;
        }
        fp_nanres(ctx, insn, n, snan, single);
        return;
    }
    if ((fp_iszero(pa) && fp_isinf(pc)) || (fp_iszero(pc) && fp_isinf(pa))) {
        fp_invalid(ctx, insn, F_VXIMZ_M, single);
        return;
    }
    if (!single && (fp_isinf(pa) || fp_isinf(pc)) && fp_isinf(pb)) {
        int ps = (int)(((pa ^ pc) >> 63) & 1u);
        int cs = (int)((pb >> 63) & 1u);
        int bad = (kind == 1 || kind == 3) ? (ps == cs) : (ps != cs);
        if (bad) {
            fp_invalid(ctx, insn, F_VXISI_M, 0);
            return;
        }
    }
    if (single) {
        int old = fp_begin(ctx);
        float fa = (float)fp_f64(pa);
        float fb = (float)fp_f64(pb);
        float fc = (float)fp_f64(pc);
        uint32_t sa = fp_u32(fa);
        uint32_t sb = fp_u32(fb);
        uint32_t sc = fp_u32(fc);
        float fr;
        if ((fp_szero(sa) && fp_sinf(sc)) || (fp_szero(sc) && fp_sinf(sa))) {
            fesetround(old);
            fp_invalid(ctx, insn, F_VXIMZ_M, 1);
            return;
        }
        if ((fp_sinf(sa) || fp_sinf(sc)) && fp_sinf(sb)) {
            int ps = (int)(((sa ^ sc) >> 31) & 1u);
            int cs = (int)((sb >> 31) & 1u);
            int bad = (kind == 1 || kind == 3) ? (ps == cs) : (ps != cs);
            if (bad) {
                fesetround(old);
                fp_invalid(ctx, insn, F_VXISI_M, 1);
                return;
            }
        }
        fr = fmaf(fa, fc, kind == 1 || kind == 3 ? -fb : fb);
        if (kind >= 2) {
            fr = -fr;
        }
        r = fp_xtod(fp_u32(fr));
        fp_commit(ctx, insn, r, old);
        return;
    }
    {
        double fr;
        int old = fp_begin(ctx);
        fr = fma(fp_f64(pa), fp_f64(pc), kind == 1 || kind == 3 ?
            -fp_f64(pb) : fp_f64(pb));
        if (kind >= 2) {
            fr = -fr;
        }
        r = fp_u64(fr);
        fp_commit(ctx, insn, r, old);
    }
}

/* fsqrt (750 implements it in hardware). */
static void fp_sqrt(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int single)
{
    uint64_t a = ctx->fpr[insn->rb & 31u];
    uint64_t r;
    if (fp_isnan(a)) {
        int snan = (a & 0x8000000000000ull) == 0u;
        fp_nanres(ctx, insn, snan ? a | 0x8000000000000ull : a, snan,
            single);
        return;
    }
    if ((a & 0x8000000000000000ull) != 0u && !fp_iszero(a)) {
        fp_invalid(ctx, insn, F_VXSQRT_M, single);
        return;
    }
    {
        int old = fp_begin(ctx);
        if (single) {
            r = fp_xtod(fp_u32(sqrtf((float)fp_f64(a))));
        } else {
            r = fp_u64(sqrt(fp_f64(a)));
        }
        fp_commit(ctx, insn, r, old);
    }
}

/* fsel (matches qemu helper_FSEL; NaN->FRB, +-0->FRC, else sign). */
static void fp_fsel(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = ctx->fpr[insn->ra & 31u];
    uint64_t c = ctx->fpr[insn->bi & 31u];
    uint64_t b = ctx->fpr[insn->rb & 31u];
    if (fp_isnan(a)) {
        fp_done(ctx, insn, b);
    } else if (fp_iszero(a) || (a & 0x8000000000000000ull) == 0u) {
        fp_done(ctx, insn, c);
    } else {
        fp_done(ctx, insn, b);
    }
}

/* fcmpu/fcmpo; cmpu=1 for fcmpu. Rc=1 updates CR1 (phase-3 rule). */
static void fp_fcmp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int cmpu)
{
    uint64_t a = ctx->fpr[insn->ra & 31u];
    uint64_t b = ctx->fpr[insn->rb & 31u];
    uint32_t shift = 4u * (7u - ((insn->rt >> 2) & 7u));
    uint32_t ret;
    if (fp_isnan(a) || fp_isnan(b)) {
        ret = 0x01u;
    } else if (fp_f64(a) < fp_f64(b)) {
        ret = 0x08u;
    } else if (fp_f64(a) > fp_f64(b)) {
        ret = 0x04u;
    } else {
        ret = 0x02u;
    }
    ctx->cr = (ctx->cr & ~(0xfu << shift)) | (ret << shift);
    ctx->fpscr = (ctx->fpscr & ~(0x1fu << 12)) | (ret << 12);
    if (ret == 0x01u) {
        int snan = (fp_isnan(a) && (a & 0x8000000000000ull) == 0u) ||
            (fp_isnan(b) && (b & 0x8000000000000ull) == 0u);
        if (!cmpu) {
            fp_raise(ctx, F_VXVC_M | F_VX_M);
            ctx->fpscr |= (0x01u << 16);
            if (snan) {
                fp_raise(ctx, F_VXSNAN_M | F_VX_M);
            }
        } else if (snan) {
            fp_raise(ctx, F_VXSNAN_M | F_VX_M);
        }
    }
    if (insn->rc) fp_cr1(ctx);
    ctx->nip += 4u;
}

/* fctiw[z]; sat 0x80000000 + VXCVI + FPCC=0x11 on invalid. */
static void fp_fctiw(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int toz)
{
    uint64_t a = ctx->fpr[insn->rb & 31u];
    double v = fp_f64(a);
    if (fp_isnan(a) || !isfinite(v) || v > 2147483647.0 ||
        v < -2147483648.0) {
        int snan = fp_isnan(a) && (a & 0x8000000000000ull) == 0u;
        ctx->fpscr &= ~(F_FR_M | F_FI_M);
        fp_raise(ctx, F_VXCVI_M | F_VX_M);
        if (snan) {
            fp_raise(ctx, F_VXSNAN_M | F_VX_M);
        }
        ctx->fpscr = (ctx->fpscr & ~(0x1fu << 12)) | (0x11u << 12);
        fp_done(ctx, insn, 0x0000000080000000ull);
        return;
    }
    {
        int old = fegetround();
        double rr;
        int32_t iv;
        int inexact;
        if (!toz) {
            fp_setrn(fp_rn(ctx));
            feclearexcept(FE_ALL_EXCEPT);
        }
        rr = toz ? trunc(v) : rint(v);
        inexact = rr != v;
        iv = (int32_t)rr;
        fesetround(old);
        ctx->fpr[insn->rt & 31u] = ((uint64_t)(uint32_t)iv) |
            ((uint64_t)(iv < 0 ? 0xffffffffu : 0u) << 32);
        ctx->fpscr &= ~F_FI_M;
        if (inexact) {
            fp_raise(ctx, F_XX_M);
            ctx->fpscr |= F_FI_M;
        }
        if (insn->rc) fp_cr1(ctx);
        ctx->nip += 4u;
    }
}

/* frsp; overflow saturates, SNaN raises VXSNAN only. */
static void fp_frsp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint64_t a = ctx->fpr[insn->rb & 31u];
    uint64_t r;
    if (fp_isnan(a)) {
        int snan = (a & 0x8000000000000ull) == 0u;
        fp_nanres(ctx, insn, snan ? a | 0x8000000000000ull : a, snan, 0);
        return;
    }
    {
        int old = fp_begin(ctx);
        float fr = (float)fp_f64(a);
        r = fp_xtod(fp_u32(fr));
        fp_commit(ctx, insn, r, old);
    }
}

/* fabs/fnabs/fneg/fmr (pure bit ops; FPSCR kept except Rc->CR1). */
static void fp_fmove(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int op)
{
    uint64_t a = ctx->fpr[insn->rb & 31u];
    if (op == 0) {
        fp_done(ctx, insn, a & 0x7fffffffffffffffull);
    } else if (op == 1) {
        fp_done(ctx, insn, a | 0x8000000000000000ull);
    } else if (op == 2) {
        fp_done(ctx, insn, a ^ 0x8000000000000000ull);
    } else {
        fp_done(ctx, insn, a);
    }
}

/* mffs (low 32 bits hold FPSCR). */
static void fp_mffs(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    fp_done(ctx, insn, (uint64_t)ctx->fpscr);
}

/* mtfsf (FM bit i -> nibble i; FEX/VX recomputed; Rc->CR1). */
static void fp_mtfsf(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    static const uint8_t vxsub[9] = { 24u, 23u, 22u, 21u, 20u, 19u, 10u,
        9u, 8u };
    uint32_t fm = (insn->raw >> 17) & 0xffu;
    uint32_t mask = 0u;
    uint32_t src = (uint32_t)ctx->fpr[insn->rb & 31u];
    uint32_t g;
    uint32_t vx = 0u;
    int i;
    for (i = 0; i < 8; i++) if ((fm >> i) & 1u) mask |= 0xfu << (4 * i);
    g = (ctx->fpscr & ~mask) | (src & mask);
    g &= ~(F_FEX_M | F_VX_M);
    for (i = 0; i < 9; i++) if ((g & (1u << vxsub[i])) != 0u) vx |= 1u << vxsub[i];
    if (vx != 0u) {
        g |= F_VX_M;
    }
    if ((((g >> 25) & 0x1fu) & ((g >> 3) & 0x1fu)) != 0u) {
        g |= F_FEX_M;
    }
    ctx->fpscr = g;
    if (insn->rc) fp_cr1(ctx);
    ctx->nip += 4u;
}

/* Classic dispatch: A-form XOs shared; single lacks fsel. */
static void fp_classic_ds(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    int single)
{
    uint32_t x = insn->xo & 31u;
    if (!single && x == PPC32_FD_FSEL) {
        fp_fsel(ctx, insn);
        return;
    }
    switch (x) {
    case PPC32_FD_FADD: fp_arith(ctx, insn, 0, single); break;
    case PPC32_FD_FSUB: fp_arith(ctx, insn, 1, single); break;
    case PPC32_FD_FMUL: fp_arith(ctx, insn, 2, single); break;
    case PPC32_FD_FDIV: fp_arith(ctx, insn, 3, single); break;
    case PPC32_FD_FSQRT: fp_sqrt(ctx, insn, single); break;
    case PPC32_FD_FMSUB: fp_fused(ctx, insn, 1, single); break;
    case PPC32_FD_FMADD: fp_fused(ctx, insn, 0, single); break;
    case PPC32_FD_FNMSUB: fp_fused(ctx, insn, 3, single); break;
    case PPC32_FD_FNMADD: fp_fused(ctx, insn, 2, single); break;
    default: ctx->exit_reason = PPC32_EXIT_UNDEF; break;
    }
}

static void fp_classic_x(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    switch (insn->xo) {
    case PPC32_FD_FCMPU: fp_fcmp(ctx, insn, 1); break;
    case PPC32_FD_FCMPO: fp_fcmp(ctx, insn, 0); break;
    case PPC32_FD_FRSP: fp_frsp(ctx, insn); break;
    case PPC32_FD_FCTIW: fp_fctiw(ctx, insn, 0); break;
    case PPC32_FD_FCTIWZ: fp_fctiw(ctx, insn, 1); break;
    case PPC32_FD_FNEG: fp_fmove(ctx, insn, 2); break;
    case PPC32_FD_FMR: fp_fmove(ctx, insn, 3); break;
    case PPC32_FD_FNABS: fp_fmove(ctx, insn, 1); break;
    case PPC32_FD_FABS: fp_fmove(ctx, insn, 0); break;
    case PPC32_FD_MFFS: fp_mffs(ctx, insn); break;
    case PPC32_FD_MTFSF: fp_mtfsf(ctx, insn); break;
    default: fp_classic_ds(ctx, insn, 0); break;
    }
}

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
static void fp_spe(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
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

/* Top-level dispatch (D-forms keep RC2 behavior; XO tables in fp.h). */
void ppc32_fp_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    switch (insn->op) {
    case PPC32_OP_LFS: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 1, 0, 0); break;
    case PPC32_OP_LFSU: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 1, 0, 1); break;
    case PPC32_OP_LFD: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 1, 1, 0); break;
    case PPC32_OP_LFDU: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 1, 1, 1); break;
    case PPC32_OP_STFS: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 0, 0, 0); break;
    case PPC32_OP_STFSU: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 0, 0, 1); break;
    case PPC32_OP_STFD: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 0, 1, 0); break;
    case PPC32_OP_STFDU: fp_lsD(ctx, insn->rt, insn->ra, insn->d, 0, 1, 1); break;
    case PPC32_OP_FPU_SINGLE: fp_classic_ds(ctx, insn, 1); break;
    case PPC32_OP_FPU_DOUBLE: fp_classic_x(ctx, insn); break;
    case PPC32_OP_FPU_X:
        switch (insn->xo) {
        case PPC32_FPUX_LFSX: case PPC32_FPUX_LFSUX:
            fp_lsX(ctx, insn, 1, 0); break;
        case PPC32_FPUX_LFDX: case PPC32_FPUX_LFDUX:
            fp_lsX(ctx, insn, 1, 1); break;
        case PPC32_FPUX_STFSX: case PPC32_FPUX_STFSUX:
            fp_lsX(ctx, insn, 0, 0); break;
        case PPC32_FPUX_STFDX: case PPC32_FPUX_STFDUX:
            fp_lsX(ctx, insn, 0, 1); break;
        default: ctx->exit_reason = PPC32_EXIT_UNDEF; break;
        }
        break;
    case PPC32_OP_SPE:
        fp_spe(ctx, insn);
        break;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        break;
    }
}
