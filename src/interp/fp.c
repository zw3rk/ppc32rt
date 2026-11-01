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
    if (!interp_mem_ok(ea, is_dbl ? 8U : 4U)) { fault(ctx, ea); return; }
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
    /* fmul/fmuls take the multiplier from the FRC slot (insn->bi):
     * GAS, QEMU, and silicon all place it at raw[6:10] with FRB
     * reserved-zero (oracle-proven: fmul f4,f1,f2 assembles to
     * 0xFC8100B2 and computes f1*f2). Matches the L3b emitter,
     * which already loads frc for SP_MUL. */
    uint64_t da = ctx->fpr[insn->ra & 31u];
    uint64_t db = ctx->fpr[(op == 2 ? insn->bi : insn->rb) & 31u];
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

/* fctiw[z]; oracle-grounded saturation (qemu-750/7450): positive
 * overflow (incl. +inf) -> 0x7FFFFFFF, NaN/-inf/negative overflow ->
 * 0x80000000; VXCVI + FPCC=0x11 on invalid. */
static void fp_fctiw(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int toz)
{
    uint64_t a = ctx->fpr[insn->rb & 31u];
    double v = fp_f64(a);
    if (fp_isnan(a) || !isfinite(v) || v > 2147483647.0 ||
        v < -2147483648.0) {
        int snan = fp_isnan(a) && (a & 0x8000000000000ull) == 0u;
        /* NaN fails the > test, so only true positive overflow
         * (incl. +inf) saturates high. */
        uint64_t sat =
            (v == v && v > 2147483647.0) ? 0x000000007fffffffu :
            0x0000000080000000ull;
        ctx->fpscr &= ~(F_FR_M | F_FI_M);
        fp_raise(ctx, F_VXCVI_M | F_VX_M);
        if (snan) {
            fp_raise(ctx, F_VXSNAN_M | F_VX_M);
        }
        ctx->fpscr = (ctx->fpscr & ~(0x1fu << 12)) | (0x11u << 12);
        fp_done(ctx, insn, sat);
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
        /* Rounding can carry an in-range value into 2^31 (nearest-even
         * of 2147483647.5): saturate like the oracle. */
        iv = (rr > 2147483647.0) ? 2147483647 : (int32_t)rr;
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

/* mtfsb0/mtfsb1 (XO 70/38): FPSCR bit BT (0 = MSB) <- 0/1
 * (trixie libm fesetround/feclearexcept; qemu-ppc -cpu 750 executes
 * them, so the interpreter matches the oracle bit for bit). */
static void fp_mtfsb(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, int set)
{
    uint32_t bit = 0x80000000U >> (insn->rt & 31u);

    if (set != 0) {
        ctx->fpscr |= bit;
    } else {
        ctx->fpscr &= ~bit;
    }
    if (insn->rc != 0U) {
        fp_cr1(ctx);
    }
    ctx->nip += 4u;
}

/* mtfsfi: FPSCR 4-bit field BF <- U nibble; Rc -> CR1; no flags. */
static void fp_mtfsfi(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    /* FPSCR fields number from the MSB: field 7 is bits 0-3 (RN/NI). */
    uint32_t bf = (insn->raw >> 23) & 7u;
    uint32_t u = (insn->raw >> 12) & 15u;
    uint32_t sh = 4u * (7u - bf);

    ctx->fpscr = (ctx->fpscr & ~(0xfu << sh)) | ((u & 0xfu) << sh);
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
    case PPC32_FD_MTFSFI: fp_mtfsfi(ctx, insn); break;
    case PPC32_FD_MTFSB0: fp_mtfsb(ctx, insn, 0); break;
    case PPC32_FD_MTFSB1: fp_mtfsb(ctx, insn, 1); break;
    default: fp_classic_ds(ctx, insn, 0); break;
    }
}

/* e500v2 SPE lives in fp_spe.c (fp_spe). */

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
