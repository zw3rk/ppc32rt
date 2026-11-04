/*
 * src/dbt/emit_fp.c — classic-FPU + e500v2 SPE AArch64 emitter (Phase 3, lane L3b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Baseline ARMv8.0 lowerings for SPEC 2.2 (classic FP, SPE int/float, indexed ld/st).
 * Scratch: w9-w17/w22, v0-v7 (never x18). Uncovered ops return FALLBACK.
 */

#include "dbt/emit_fp.h"

#include <stddef.h>

#include "ppc32rt.h"
#include "rt32/ppc32_a64_emit.h"

/* Classic X-form 10-bit XOs (63). */
#define FP_XO_FCMPU 0U
#define FP_XO_FRSP 12U
#define FP_XO_FCTIW 14U
#define FP_XO_FCTIWZ 15U
#define FP_XO_FCMPO 32U
#define FP_XO_FNEG 40U
#define FP_XO_FMR 72U
#define FP_XO_FNABS 136U
#define FP_XO_FABS 264U
#define FP_XO_MFFS 583U
#define FP_XO_MTFSF 711U
#define FP_XO_MTFSB0 70U
#define FP_XO_MTFSB1 38U
/* Indexed-FP XO range (31): 535..759 step 32. */
#define FP_XO_LFSX 535U
#define FP_XO_STFDUX 759U
#define FP_OFF(fr) ((uint32_t)offsetof(ppc32_ctx_t, fpr) + (uint32_t)(fr) * 8U)
#define FP_FPSCR_OFF ((uint32_t)offsetof(ppc32_ctx_t, fpscr))
#define SPE_HI_OFF(r) ((uint32_t)offsetof(ppc32_ctx_t, gpr_hi) + (uint32_t)(r) * 4U)

/* Raw 64-bit LDR/STR/REV (no X-reg helpers in rt32_a64_emit.h). */
#define FP_LDR_X(td, tb) \
    a64_emit(b, 0xF9400000U | ((unsigned)(tb) << 5) | (unsigned)(td))
#define FP_STR_X(ts, tb) \
    a64_emit(b, 0xF9000000U | ((unsigned)(tb) << 5) | (unsigned)(ts))
#define FP_REV_X(t) \
    a64_emit(b, 0xDAC00C00U | ((unsigned)(t) << 5) | (unsigned)(t))
#define FP_STR_X_OFF(ts, tb, off) \
    a64_emit(b, 0xF9000000U | (((off) / 8U) << 10) | \
        ((unsigned)(tb) << 5) | (unsigned)(ts))

/* fpr[] holds IEEE-754 double patterns; S ops convert D<->S at access.
 * Wave P12: 8-slot write-through FPR cache in d16..d23 (slot fr&7,
 * FMOV 0x1E604000 on hits); dbl traffic only, S paths invalidate. */
static void fp_ld(a64_buf_t *b, unsigned vd, unsigned fr, bool dbl)
{
    if (dbl) {
        unsigned fs = fr & 7U, fc = 16U + fs;
        if ((((b->fpr_cache_valid >> fs) & 1U) != 0U) && b->fpr_cache_reg[fs] == (uint8_t)fr) {
            if (vd != fc)
                a64_emit(b, 0x1E604000U | ((fc & 31U) << 5) | (vd & 31U));
            return;
        }
        a64_emit(b, 0xFD400000U | ((FP_OFF(fr) / 8U) << 10) | ((unsigned)A64_XCTX << 5) | (fc & 31U));
        b->fpr_cache_valid |= (uint8_t)(1U << fs);
        b->fpr_cache_reg[fs] = (uint8_t)fr;
        if (vd != fc)
            a64_emit(b, 0x1E604000U | ((fc & 31U) << 5) | (vd & 31U));
        return;
    }
    a64_emit(b, 0xFD400000U | ((FP_OFF(fr) / 8U) << 10) | ((unsigned)A64_XCTX << 5) | (vd & 31U));
    a64_emit(b, 0x1E624000U | ((vd & 31U) << 5) | (vd & 31U));
}

static void fp_st(a64_buf_t *b, unsigned fr, unsigned vs, bool dbl, bool zero_hi)
{
    unsigned r = vs & 31U;
    (void)zero_hi;
    if (dbl) {
        unsigned fs = fr & 7U, fc = 16U + fs;
        if (r != fc)
            a64_emit(b, 0x1E604000U | ((r & 31U) << 5) | fc);
        a64_emit(b, 0xFD000000U | ((FP_OFF(fr) / 8U) << 10) | ((unsigned)A64_XCTX << 5) | (fc & 31U));
        b->fpr_cache_valid |= (uint8_t)(1U << fs);
        b->fpr_cache_reg[fs] = (uint8_t)fr;
        return;
    }
    a64_emit(b, 0x1E22C000U | (r << 5) | 3U);
    a64_emit(b, 0xFD000000U | ((FP_OFF(fr) / 8U) << 10) | ((unsigned)A64_XCTX << 5) | 3U);
    if (((b->fpr_cache_valid >> (fr & 7U)) & 1U) != 0U && b->fpr_cache_reg[fr & 7U] == (uint8_t)fr)
        b->fpr_cache_valid &= (uint8_t)~(uint8_t)(1U << (fr & 7U));
}
/* SPE scalar-single traffic: low word of the GPR pair. */
static void spe_ld_s(a64_buf_t *b, unsigned vs, unsigned r)
{
    a64_emit(b, 0xBD400000U | ((ei_gpr_off(r) / 4U) << 10) |
        ((unsigned)A64_XCTX << 5) | (vs & 31U));
}

static void spe_st_s(a64_buf_t *b, unsigned r, unsigned vs)
{
    a64_emit(b, 0xBD000000U | ((ei_gpr_off(r) / 4U) << 10) |
        ((unsigned)A64_XCTX << 5) | (vs & 31U));
    b->gpr_cache_valid = 0;
}

static void fp_ld_fpscr(a64_buf_t *b, unsigned wd)
{
    a64_emit(b, 0xB9400000U | ((FP_FPSCR_OFF / 4U) << 10) |
        ((unsigned)A64_XCTX << 5) | (wd & 31U));
}

static void fp_st_fpscr(a64_buf_t *b, unsigned ws)
{
    a64_emit(b, 0xB9000000U | ((FP_FPSCR_OFF / 4U) << 10) |
        ((unsigned)A64_XCTX << 5) | (ws & 31U));
}
/* FPCR rounding sync: fpscr in EI_A/w9; clobbers w10/w11/x15/x16. */
static void fp_sync_fpcr(a64_buf_t *b)
{
    a64_emit_ubfm_w(b, EI_B, EI_A, 0U, 2U); /* w10 = fpscr[NI,RN] */
    size_t skip_msr = a64_emit_cbz_w_placeholder(b, false, EI_B);
    a64_emit(b, 0xD53B4400U | 16U); /* mrs x16, fpcr (saved copy) */
    a64_emit_ubfm_w(b, EI_B, EI_A, 0U, 0U); /* rn0 */
    a64_emit_shift_imm_w(b, EI_B, EI_B, A64_SHIFT_LSL, 1U, false, NULL);
    a64_emit_eor_reg_w(b, EI_T, EI_A, EI_A, A64_SHIFT_LSR, 1U);
    a64_emit_ubfm_w(b, EI_T, EI_T, 0U, 0U); /* rn1 ^ rn0 */
    a64_emit_orr_reg_w(b, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U); /* RMode */
    a64_emit_ubfm_w(b, EI_T, EI_A, 2U, 2U); /* NI */
    a64_emit_shift_imm_w(b, EI_T, EI_T, A64_SHIFT_LSL, 25U, false, NULL);
    a64_emit_orr_reg_w(b, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U); /* DN */
    a64_emit_mov_w(b, 15U, 16U); /* w15 = saved FPCR low word */
    a64_emit_mov_imm32(b, A64_TMP3, 0x02C00000U); /* RMode|DN clear mask */
    a64_emit_bic_reg_w(b, false, 15U, 15U, A64_TMP3, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, 15U, 15U, EI_B, A64_SHIFT_LSL, 22U);
    a64_emit(b, 0xD51B4400U | 15U); /* msr fpcr, x15 */
    a64_patch_cbz_w(b, skip_msr, b->count);
    a64_emit(b, 0xD51B4420U | 31U); /* msr fpsr, xzr */
}

static void fp_restore_fpcr(a64_buf_t *b)
{
    a64_emit_ubfm_w(b, EI_B, EI_A, 0U, 2U);
    size_t skip = a64_emit_cbz_w_placeholder(b, false, EI_B);
    a64_emit(b, 0xD51B4400U | 16U); /* msr fpcr, x16 */
    a64_patch_cbz_w(b, skip, b->count);
}

/* FPSR cumulative -> FPSCR accumulation (fpscr in w9; bit 0/IOC invokes
 * fp_inv_classify only inside the cold IOC != 0 branch, and arithmetic
 * ops (iop < 0xFE) update FR in-place before storing fpscr). */
static void fp_accum(a64_buf_t *b, unsigned iop, bool dbl)
{
    static const uint32_t masks[4] = { FP_ZX | FP_FX, FP_OX | FP_FX,
        FP_UX | FP_FX, FP_XX | FP_FX | FP_FI };
    size_t skip_all;
    size_t next;
    uint32_t bit;
    a64_emit(b, 0xD53B4420U | 10U); /* mrs x10, fpsr */
    a64_emit_ubfm_w(b, EI_T, EI_B, 0U, 4U);
    skip_all = a64_emit_cbz_w_placeholder(b, false, EI_T);
    for (bit = 1U; bit < 5U; bit++) {
        a64_emit_ubfm_w(b, EI_T, EI_B, bit, bit);
        next = a64_emit_cbz_w_placeholder(b, false, EI_T);
        a64_emit_mov_imm32(b, EI_X, masks[bit - 1U]);
        a64_emit_orr_reg_w(b, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
        a64_patch_cbz_w(b, next, b->count);
    }
    a64_emit_ubfm_w(b, EI_T, EI_B, 0U, 0U);
    next = a64_emit_cbz_w_placeholder(b, false, EI_T);
    fp_inv_classify(b, iop, dbl);
    a64_emit_orr_reg_w(b, EI_A, EI_A, 17U, A64_SHIFT_LSL, 0U);
    a64_patch_cbz_w(b, next, b->count);
    if (iop < 0xFEU) {
        fp_fr_arith(b, iop, dbl);
    }
    a64_patch_cbz_w(b, skip_all, b->count);
    fp_st_fpscr(b, EI_A);
}

/* CR1 = FPSCR[FX,FEX,VX,OX] when Rc is set (fpscr in EI_A/w9). */
static void fp_cr1(a64_buf_t *b)
{
    a64_emit_ubfm_w(b, EI_B, EI_A, 28U, 31U);
    ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    ei_cr_merge(b, EI_A, EI_B, 24U);
}

/* Shared tail: optional CR1 update, then overflow check. */
static int fp_tail(a64_buf_t *b, const ppc32_insn_t *insn)
{
    if (insn->rc != 0U) {
        fp_ld_fpscr(b, EI_A);
        fp_cr1(b);
    }
    if (b->overflow) {
        return PPC32_EMIT_FALLBACK;
    }
    return PPC32_EMIT_NEXT;
}

/* Convert tail: exception accumulation, FPCR restore, shared tail.
 * P32-R8-5: FI and FR are cleared per op here (oracle fp_flags_arith);
 * FR is re-set by fp_fr_arith (in fp_accum) or fp_fr_mag (converts). */
static int fp_conv_end(a64_buf_t *b, const ppc32_insn_t *insn,
    unsigned iop, bool dbl)
{
    a64_emit_mov_imm32(b, EI_X, FP_FI | FP_FR);
    a64_emit_bic_reg_w(b, false, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    fp_accum(b, iop, dbl);
    fp_restore_fpcr(b);
    return fp_tail(b, insn);
}
/* Guest-memory FP traffic (big-endian wire; EA already in w22).
 * Double traffic is write-through cached (lfd populates d16+slot via
 * FMOV, stfd reads it back); single paths convert and invalidate. */
static void fp_ldst_mem(a64_buf_t *b, bool is_store, bool dbl, unsigned fr)
{
    unsigned fs = fr & 7U;
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, A64_ADDR);
    if (!is_store && dbl) {
        FP_LDR_X(15U, A64_TMP2);
        FP_REV_X(15U);
        a64_emit(b, 0x9E670000U | (15U << 5) | (16U + fs));
        FP_STR_X_OFF(15U, A64_XCTX, FP_OFF(fr));
        b->fpr_cache_valid |= (uint8_t)(1U << fs);
        b->fpr_cache_reg[fs] = (uint8_t)fr;
    } else if (!is_store) {
        a64_emit_ldr_imm_w(b, 15U, A64_TMP2, 0U);
        a64_emit_rev_w(b, 15U, 15U);
        a64_emit(b, 0x1E270000U | (15U << 5) | 0U);
        fp_st(b, fr, 0U, false, false);
    } else if (dbl) {
        if ((((b->fpr_cache_valid >> fs) & 1U) != 0U) &&
            b->fpr_cache_reg[fs] == (uint8_t)fr)
            a64_emit(b, 0x9E660000U | (((16U + fs) & 31U) << 5) | 15U);
        else
            a64_emit(b, 0xF9400000U | ((unsigned)A64_XCTX << 5) | ((FP_OFF(fr) / 8U) << 10) | 15U);
        FP_REV_X(15U);
        FP_STR_X(15U, A64_TMP2);
    } else {
        fp_ld(b, 0U, fr, false);
        a64_emit(b, 0x1E260000U | (0U << 5) | 15U);
        a64_emit_rev_w(b, 15U, 15U);
        a64_emit_str_imm_w(b, 15U, A64_TMP2, 0U);
    }
}

/* D-form (is_x false) and indexed (is_x true) FP loads/stores. */
static int fp_ldst(a64_buf_t *b, const ppc32_insn_t *insn, bool is_x,
    bool is_update, bool is_store, bool dbl, uint32_t pc)
{
    if (insn->rt >= 32U || insn->rb >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    if (is_update) {
        if (insn->ra == 0U || insn->ra >= 32U) {
            return PPC32_EMIT_FALLBACK;
        }
    } else if (insn->ra >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    if (is_x) {
        ei_ea_x(b, insn->ra, insn->rb);
    } else {
        ei_ea_d(b, insn->ra, (uint32_t)insn->d);
    }
    /* P32-R5-2: guard, access, then RA update so a fault keeps RA/nip. */
    ei_guard_low(b, pc);
    fp_ldst_mem(b, is_store, dbl, insn->rt);
    if (b->overflow) {
        return PPC32_EMIT_FALLBACK;
    }
    if (is_update) {
        ei_st(b, A64_ADDR, insn->ra);
    }
    return PPC32_EMIT_NEXT;
}

/* Op ids for the shared engine (integer ids appended to SP_ ids). */
enum { SP_ADD, SP_SUB, SP_MUL, SP_DIV, SP_ABS, SP_NABS, SP_NEG, SP_SQRT,
    SP_MADD, SP_MSUB, SP_NMADD, SP_NMSUB, SP_SELM, SP_FMOV, SV_ADD = 16,
    SV_SUB, SV_AND, SV_XOR, SV_OR, SV_TRN1, SV_TRN2, SV_EXT10, SV_EXT01 };

/* [op][prec]: S, D, V; rows ADD,SUB,MUL,DIV,ABS,NABS,NEG,SQRT,MADD,MSUB,NMADD,NMSUB,SELM,FMOV. */
static const uint32_t fp_base[14][3] = {
    { 0x1E202800U, 0x1E602800U, 0x0E20D400U }, { 0x1E203800U, 0x1E603800U, 0x0EA0D400U },
    { 0x1E200800U, 0x1E600800U, 0x2E20DC00U }, { 0x1E201800U, 0x1E601800U, 0x2E20FC00U },
    { 0x1E20C000U, 0x1E60C000U, 0x0EA0B800U }, { 0U, 0U, 0U },
    { 0x1E214000U, 0x1E614000U, 0x2EA0B800U }, { 0x1E21C000U, 0x1E61C000U, 0x2EA1F800U },
    { 0x1F000000U, 0x1F400000U, 0U }, { 0x1F008000U, 0x1F408000U, 0U },
    { 0x1F200000U, 0x1F600000U, 0U }, { 0x1F208000U, 0x1F608000U, 0U },
    { 0x1E200C00U, 0x1E600C00U, 0U }, { 0x1E204000U, 0x1E604000U, 0U } };
/* Shared engine: operands in v0 (A), v1 (B), v2 (C); result in v0. */
static void fp_calc(a64_buf_t *b, unsigned op, unsigned prec,
    unsigned vm, unsigned va)
{
    uint32_t base = fp_base[op][prec];
    /* Vn is the true leg, Vm the false leg (native-verified). */
    if (op <= (unsigned)SP_DIV) {
        a64_emit(b, base | ((vm & 31U) << 16) | ((va & 31U) << 5) | 0U);
    } else if (op == (unsigned)SP_ABS || op == (unsigned)SP_NEG ||
        op == (unsigned)SP_SQRT || op == (unsigned)SP_FMOV) {
        a64_emit(b, base | (0U << 5) | 0U);
    } else if (op == (unsigned)SP_NABS) {
        a64_emit(b, fp_base[SP_ABS][prec] | (0U << 5) | 0U);
        a64_emit(b, fp_base[SP_NEG][prec] | (0U << 5) | 0U);
    } else {
        a64_emit(b, base | ((vm & 31U) << 16) | ((va & 31U) << 10) | 0U);
    }
}

/* Classic A-form 5-bit XO -> engine op; 0xFF = invalid. */
static const uint8_t fp_a_op[32] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    3U, 0xFF, 1U, 0U, 7U, 12U, 0xFF, 2U, 0xFF, 0xFF, 9U, 8U, 11U, 10U };

/* Rounding prologue/epilogue for one arithmetic op (fpscr in w9). */
static int fp_round_end(a64_buf_t *b, const ppc32_insn_t *insn,
    unsigned vd, unsigned iop, bool dbl)
{
    fp_fprf(b, vd, dbl);
    return fp_conv_end(b, insn, iop, dbl);
}

/* Classic A-form arithmetic (primaries 59/63); prec 0 = S, 1 = D. */
static int fp_arith(a64_buf_t *b, const ppc32_insn_t *insn, unsigned prec)
{
    uint8_t op = fp_a_op[insn->xo & 0x1FU];
    unsigned rt = insn->rt;
    unsigned ra = insn->ra;
    unsigned rb = insn->rb;
    unsigned frc = insn->bi;
    bool dbl = prec == 1U;
    if (op == 0xFFU || rt >= 32U || ra >= 32U || rb >= 32U ||
        frc >= 32U ||
        ((op == (uint8_t)SP_ADD || op == (uint8_t)SP_SUB ||
        op == (uint8_t)SP_DIV) && frc != 0U) ||
        (op == (uint8_t)SP_MUL && rb != 0U) ||
        (op == (uint8_t)SP_SQRT && (ra != 0U || frc != 0U))) {
        return PPC32_EMIT_FALLBACK;
    }
    if (op == (uint8_t)SP_SELM) {
        /* fcmp can set FPSR.IOC on SNaN: save/restore FPSR around it. */
        fp_ld_fpscr(b, EI_A);
        fp_ld(b, 0U, ra, dbl);
        fp_ld(b, 1U, rb, dbl);
        fp_ld(b, 2U, frc, dbl);
        a64_emit(b, 0xD53B4420U | 10U); /* mrs x10, fpsr */
        a64_emit(b, (dbl ? 0x1E602008U : 0x1E202008U) | (0U << 5));
        /* FCSSEL true->Vn(v1=FRB), false->Vm(v2=FRC). */
        a64_emit(b, fp_base[SP_SELM][prec] |
            ((uint32_t)A64_COND_MI << 12) | (2U << 16) | (1U << 5) | 0U);
        a64_emit(b, 0xD51B4420U | 10U); /* msr fpsr, x10 */
        a64_emit(b, 0xD5033FDFU); /* isb */
        fp_st(b, rt, 0U, dbl, !dbl);
        return fp_tail(b, insn);
    }
    if (!b->fp_batch_open) {
        fp_ld_fpscr(b, EI_A);
        fp_sync_fpcr(b);
    }
    if (op == (uint8_t)SP_SQRT) {
        fp_ld(b, 0U, rb, dbl);
    } else if (op == (uint8_t)SP_MUL) {
        fp_ld(b, 0U, ra, dbl);
        fp_ld(b, 2U, frc, dbl);
    } else {
        fp_ld(b, 0U, ra, dbl);
        fp_ld(b, 1U, rb, dbl);
        if (op >= (uint8_t)SP_MADD && op <= (uint8_t)SP_NMSUB) {
            fp_ld(b, 2U, frc, dbl);
        }
    }
    if (!(b->fp_next_is_arith && insn->rc == 0U)) {
        a64_emit(b, 0x1E604000U | (0U << 5) | 7U); /* fmov d7, d0 */
    }
    if (op >= (uint8_t)SP_MADD && op <= (uint8_t)SP_NMSUB) {
        fp_calc(b, op, prec, 2U, 1U);
    } else if (op == (uint8_t)SP_MUL) {
        fp_calc(b, op, prec, 2U, 0U);
    } else {
        fp_calc(b, op, prec, 1U, 0U);
    }
    fp_st(b, rt, 0U, dbl, !dbl);
    if (b->fp_next_is_arith && insn->rc == 0U) {
        b->fp_batch_open = true; return PPC32_EMIT_NEXT;
    }
    if (b->fp_batch_open) { fp_ld_fpscr(b, EI_A); b->fp_batch_open = false; }
    return fp_round_end(b, insn, 0U, (unsigned)op, dbl);
}
/* fcmpu/fcmpo: CR[bf] = [LT,GT,EQ,UN] from A64 NZCV. */
static int fp_cmp(a64_buf_t *b, const ppc32_insn_t *insn)
{
    uint32_t bf;
    if (insn->rt >= 32U || insn->ra >= 32U || insn->rb >= 32U ||
        (insn->xo != FP_XO_FCMPU && insn->xo != FP_XO_FCMPO)) {
        return PPC32_EMIT_FALLBACK;
    }
    bf = (insn->rt >> 2U) & 7U;
    fp_ld_fpscr(b, EI_A);
    a64_emit(b, 0xD51B4420U | 31U); /* msr fpsr, xzr (fresh flags) */
    a64_emit(b, 0xD5033FDFU); /* isb */
    fp_ld(b, 0U, insn->ra, true);
    fp_ld(b, 1U, insn->rb, true);
    a64_emit(b, 0x1E602000U | (1U << 16) | (0U << 5)); /* fcmp d0, d1 */
    a64_emit(b, 0xD53B4200U | 10U); /* mrs x10, nzcv */
    fp_nzcv_field(b);
    ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    ei_cr_merge(b, EI_A, EI_R, (7U - bf) * 4U);
    fp_ld_fpscr(b, EI_A);
    if (insn->xo == FP_XO_FCMPO) {
        /* Unordered fcmpo is invalid even for QNaN: VXVC|VX. */
        size_t skip_un = 0U;
        a64_emit_ubfm_w(b, EI_T, EI_R, 0U, 0U); /* T = UN */
        skip_un = a64_emit_cbz_w_placeholder(b, false, EI_T);
        a64_emit_mov_imm32(b, EI_X, FP_VXVC | FP_VX | FP_FX);
        a64_emit_orr_reg_w(b, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
        a64_patch_cbz_w(b, skip_un, b->count);
    }
    /* P32-R8-4: FPSCR[FPCC] = compare field; C (bit 16) is preserved. */
    a64_emit_mov_imm32(b, EI_T2, 0xF000U);
    a64_emit_bic_reg_w(b, false, EI_A, EI_A, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_R, A64_SHIFT_LSL, 12U);
    fp_accum(b, 0xFFU, true);
    return fp_tail(b, insn);
}

/* fmr/fabs/fnabs/fneg: pure moves, no FPSCR traffic. */
static int fp_move(a64_buf_t *b, const ppc32_insn_t *insn)
{
    uint8_t op = (insn->xo == FP_XO_FMR) ? (uint8_t)SP_FMOV :
        (insn->xo == FP_XO_FABS) ? (uint8_t)SP_ABS :
        (insn->xo == FP_XO_FNEG) ? (uint8_t)SP_NEG :
        (insn->xo == FP_XO_FNABS) ? (uint8_t)SP_NABS : 0xFFU;
    if (op == 0xFFU || insn->rt >= 32U || insn->rb >= 32U ||
        insn->ra != 0U) {
        return PPC32_EMIT_FALLBACK;
    }
    fp_ld(b, 0U, insn->rb, true);
    fp_calc(b, op, 1U, 0U, 0U);
    fp_st(b, insn->rt, 0U, true, false);
    return fp_tail(b, insn);
}

static int fp_mffs(a64_buf_t *b, const ppc32_insn_t *insn)
{
    if (insn->rt >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    fp_ld_fpscr(b, EI_A);
    FP_STR_X_OFF(EI_A, A64_XCTX, FP_OFF(insn->rt));
    if (insn->rc != 0U) {
        fp_cr1(b);
    }
    if (b->overflow) {
        return PPC32_EMIT_FALLBACK;
    }
    return PPC32_EMIT_NEXT;
}

/* mtfsb0/mtfsb1 (XO 70/38): FPSCR bit BT (0 = MSB) <- 0/1. */
static int fp_mtfsb(a64_buf_t *b, const ppc32_insn_t *insn, int set)
{
    if (insn->rt >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    fp_ld_fpscr(b, EI_A);
    a64_emit_mov_imm32(b, EI_X, 0x80000000U >> (insn->rt & 31U));
    if (set != 0) {
        a64_emit_orr_reg_w(b, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    } else {
        a64_emit_bic_reg_w(b, false, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    }
    fp_st_fpscr(b, EI_A);
    return fp_tail(b, insn);
}

/* mtfsf with FLM mask (L/W bits set fall back). */
static int fp_mtfsf(a64_buf_t *b, const ppc32_insn_t *insn)
{
    uint32_t flm = (insn->raw >> 17U) & 0xFFU;
    uint32_t mask = 0U;
    uint32_t i;
    if (insn->rb >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    if (((insn->raw >> 16U) & 1U) != 0U || ((insn->raw >> 25U) & 1U) != 0U) {
        return PPC32_EMIT_FALLBACK;
    }
    for (i = 0U; i < 8U; i++) {
        mask |= (((flm >> (7U - i)) & 1U) != 0U) ?
            0xF0000000U >> (i * 4U) : 0U;
    }
    a64_emit_ldr_imm_w(b, EI_B, A64_XCTX, FP_OFF(insn->rb));
    fp_ld_fpscr(b, EI_A);
    a64_emit_mov_imm32(b, EI_X, mask);
    a64_emit_bic_reg_w(b, false, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    fp_st_fpscr(b, EI_A);
    return fp_tail(b, insn);
}
/* ---- e500v2 SPE (exact 11-bit XO match; Rc folded into XO) ---- */

static void spe_ld_pair(a64_buf_t *b, unsigned vd, unsigned r)
{
    a64_emit_ldr_imm_w(b, 15U, A64_XCTX, ei_gpr_off(r));
    a64_emit_ldr_imm_w(b, 16U, A64_XCTX, SPE_HI_OFF(r));
    a64_emit(b, 0xAA008000U | (16U << 16) | (15U << 5) | 15U);
    a64_emit(b, 0x9E670000U | (15U << 5) | (vd & 31U));
}

static void spe_st_pair(a64_buf_t *b, unsigned r, unsigned vs)
{
    a64_emit(b, 0x9E660000U | ((vs & 31U) << 5) | 15U);
    a64_emit_str_imm_w(b, 15U, A64_XCTX, ei_gpr_off(r));
    a64_emit(b, 0xD3400000U | (32U << 16) | (63U << 10) |
        (15U << 5) | 16U);
    a64_emit_str_imm_w(b, 16U, A64_XCTX, SPE_HI_OFF(r));
    b->gpr_cache_valid = 0;
}

/* XO -> engine op; prec derives from the XO band. */
struct spe_entry {
    uint32_t xo;
    uint8_t op;
};
static const struct spe_entry spe_table[] = {
    { 512U, SV_ADD }, { 516U, SV_SUB }, { 529U, SV_AND }, { 534U, SV_XOR },
    { 535U, SV_OR }, { 556U, SV_TRN2 }, { 557U, SV_TRN1 }, { 558U, SV_EXT10 },
    { 559U, SV_EXT01 }, { 704U, SP_ADD }, { 705U, SP_SUB }, { 708U, SP_ABS },
    { 709U, SP_NABS }, { 710U, SP_NEG }, { 712U, SP_MUL }, { 713U, SP_DIV },
    { 706U, SP_MADD }, { 707U, SP_MSUB }, { 714U, SP_NMADD }, { 715U, SP_NMSUB },
    { 736U, SP_ADD }, { 737U, SP_SUB }, { 740U, SP_ABS }, { 741U, SP_NABS },
    { 742U, SP_NEG }, { 744U, SP_MUL }, { 745U, SP_DIV }, { 640U, SP_ADD },
    { 641U, SP_SUB }, { 644U, SP_ABS }, { 645U, SP_NABS }, { 646U, SP_NEG },
    { 648U, SP_MUL }, { 649U, SP_DIV }, { 647U, SP_SQRT } };

/*
 * To-float engine. in: 0 = S (pair low), 1 = D (pair), 2 = fpr D,
 * 3 = W (pair low), 4 = X (pair). cvt base takes Rn (11 for W/X).
 */
static int spe_cvtf(a64_buf_t *b, const ppc32_insn_t *insn, unsigned in,
    uint32_t base, bool out_dbl)
{
    fp_ld_fpscr(b, EI_A);
    fp_sync_fpcr(b);
    if (in == 0U) {
        spe_ld_s(b, 0U, insn->rb);
    } else if (in == 1U) {
        spe_ld_pair(b, 0U, insn->rb);
    } else if (in == 2U) {
        fp_ld(b, 0U, insn->rb, true);
    } else if (in == 3U) {
        a64_emit_ldr_imm_w(b, 11U, A64_XCTX, ei_gpr_off(insn->rb));
    } else {
        spe_ld_pair(b, 3U, insn->rb);
        a64_emit(b, 0x9E660000U | (3U << 5) | 11U);
        a64_emit(b, 0xD3400000U | (32U << 16) | (63U << 10) |
            (11U << 5) | 15U);
        a64_emit(b, 0xAA008000U | (15U << 16) | (11U << 5) | 11U);
    }
    if (in == 2U) {
        /* P32-R8-5: save the full double before any S-write (an S-write
         * zeroes D-high, so D7 must precede the narrow below). */
        a64_emit(b, 0x1E604000U | (0U << 5) | 7U); /* fmov d7, d0 */
    }
    a64_emit(b, base | (((in >= 3U) ? 11U : 0U) << 5) | 0U);
    if (out_dbl) {
        spe_st_pair(b, insn->rt, 0U);
        fp_restore_fpcr(b);
        return fp_tail(b, insn);
    }
    if (in == 2U) { /* frsp: narrow D->S (base line above, P32-R8-3),
                     * then widen back to double. */
        int rc;
        a64_emit(b, 0x1E22C000U | (0U << 5) | 0U); /* fcvt d0, s0 */
        fp_st(b, insn->rt, 0U, true, false);
        rc = fp_round_end(b, insn, 0U, 0xFFU, true);
        fp_fr_mag(b, 7U, 0U, false); /* P32-R8-5: FR iff widened > orig */
        return rc;
    }
    spe_st_s(b, insn->rt, 0U);
    fp_restore_fpcr(b);
    return fp_tail(b, insn);
}

/*
 * To-int engine. in: 0 = S (pair low), 1 = D (pair), 2 = fpr D.
 * Result is int32 (w11) unless wide (int64 in x11, D input only).
 */
static int spe_cvti(a64_buf_t *b, const ppc32_insn_t *insn, unsigned in,
    bool rnd, bool u, bool wide)
{
    bool dbl = (in != 0U);
    fp_ld_fpscr(b, EI_A);
    fp_sync_fpcr(b);
    if (in == 0U) {
        spe_ld_s(b, 0U, insn->rb);
    } else if (in == 1U) {
        spe_ld_pair(b, 0U, insn->rb);
    } else {
        fp_ld(b, 0U, insn->rb, true);
    }
    if (in == 2U) {
        /* P32-R8-5: save the exact input for the FR rounded-up test. */
        a64_emit(b, 0x1E604000U | (0U << 5) | 7U); /* fmov d7, d0 */
    }
    if (rnd) {
        a64_emit(b, dbl ? 0x1E67C000U : 0x1E27C000U); /* frinti */
    }
    if (wide) {
        a64_emit(b, (u ? 0x9E790000U : 0x9E780000U) | (0U << 5) | 11U);
    } else {
        a64_emit(b, (dbl ? (u ? 0x1E790000U : 0x1E780000U) :
            (u ? 0x1E390000U : 0x1E380000U)) | (0U << 5) | 11U);
    }
    { /* Invalid converts (FPSR.IOC): NaN via VS; ARM saturates range. */
        bool input_dbl = (in != 0U) || wide;
        size_t skip;
        if (wide) {
            a64_emit(b, 0x1E602000U); /* fcmp d0, d0 */
            a64_emit(b, u ? 0x9280000DU : 0xD2F0000DU);
            a64_emit(b, 0x9A800000U | (11U << 16) |
                ((uint32_t)A64_COND_VS << 12) | (13U << 5) | 11U);
        } else {
            a64_emit(b, input_dbl ? 0x1E602000U : 0x1E202000U);
            if (u) {
                a64_emit(b, 0x12800000U | 13U); /* movn w13, #0 */
            } else {
                a64_emit_movz_w(b, 13U, 0x8000U, 1U);
            }
            a64_emit_csel_w(b, 11U, 13U, 11U, A64_COND_VS);
        }
        a64_emit(b, 0xD5033FDFU); /* isb */
        a64_emit(b, 0xD53B4420U | 10U); /* mrs x10, fpsr */
        a64_emit_ubfm_w(b, EI_T, 10U, 0U, 0U); /* T = IOC */
        skip = a64_emit_cbz_w_placeholder(b, false, EI_T);
        a64_emit_mov_imm32(b, EI_X, FP_VXCVI | FP_VX | FP_FX);
        a64_emit_orr_reg_w(b, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
        if (in == 2U) { /* classic fctiw/z: FPCC=0x11 on invalid. */
            a64_emit_mov_imm32(b, EI_X, 0x11U);
            a64_emit(b, 0x33000000U | (20U << 16) | (4U << 10) |
                (EI_X << 5) | EI_A); /* bfi w9, w14, #12, #5 */
        }
        a64_patch_cbz_w(b, skip, b->count);
    }
    if (wide || (in == 1U && dbl && !u)) {
        /* 64-bit pattern across the pair (sign-extended if signed). */
        if (!wide) {
            a64_emit(b, 0x93407C00U | (11U << 5) | 11U); /* sxtw */
        }
        a64_emit_str_imm_w(b, 11U, A64_XCTX, ei_gpr_off(insn->rt));
        a64_emit(b, 0xD3400000U | (32U << 16) | (63U << 10) |
            (11U << 5) | 12U);
        a64_emit_str_imm_w(b, 12U, A64_XCTX, SPE_HI_OFF(insn->rt));
        b->gpr_cache_valid = 0;
    } else if (in == 2U) { /* classic fctiw keeps the FPR destination */
        int rc;
        a64_emit(b, 0x93407C00U | (11U << 5) | 11U); /* sxtw */
        FP_STR_X_OFF(11U, A64_XCTX, FP_OFF(insn->rt));
        b->fpr_cache_valid &= (uint8_t)~(uint8_t)(1U << (insn->rt & 7U));
        rc = fp_conv_end(b, insn, 0xFEU, true);
        fp_fr_mag(b, 7U, 11U, true); /* P32-R8-5: FR iff |int|>|exact| */
        return rc;
    } else {
        spe_st_s(b, insn->rt, 11U);
    }
    fp_restore_fpcr(b);
    return fp_tail(b, insn);
}

static int spe_scalar(a64_buf_t *b, const ppc32_insn_t *insn)
{
    uint32_t xo = insn->xo;
    uint32_t i;
    uint8_t op = 0xFFU;
    /* prec: 3 = I pair (<560), 2 = V pair (<652), 0 = S word (<716). */
    uint8_t prec = (xo < 560U) ? 3U : ((xo < 652U) ? 2U :
        ((xo < 716U) ? 0U : 1U));
    if (insn->rt >= 32U || insn->ra >= 32U || insn->rb >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    for (i = 0U; i < sizeof(spe_table) / sizeof(spe_table[0]); i++) {
        if (spe_table[i].xo == xo) {
            op = spe_table[i].op;
            break;
        }
    }
    if (op != 0xFFU) {
        /* Arithmetic: v0 = A, v1 = B, v2 = C/D(old). */
        if (prec == 3U) {
            /* Integer pair ops (no rounding state touched). */
            static const uint32_t sv_base[] = { 0x0EA08400U, 0x2EA08400U,
                0x0E201C00U, 0x2E201C00U, 0x0EA01C00U, 0x0E802800U,
                0x0E806800U, 0x2E002000U, 0x2E002000U };
            spe_ld_pair(b, 0U, insn->ra);
            spe_ld_pair(b, 1U, insn->rb);
            if (op == (uint8_t)SV_SUB || op == (uint8_t)SV_TRN1 ||
                op == (uint8_t)SV_TRN2 || op == (uint8_t)SV_EXT01) {
                /* evsubfw/evmergehi/evmergelo/evmergelohi: Vn=v1, Vm=v0. */
                a64_emit(b, sv_base[op - SV_ADD] | (0U << 16) |
                    (1U << 5) | 0U);
            } else {
                a64_emit(b, sv_base[op - SV_ADD] | (1U << 16) | 0U);
            }
            spe_st_pair(b, insn->rt, 0U);
            if (b->overflow) {
                return PPC32_EMIT_FALLBACK;
            }
            return PPC32_EMIT_NEXT;
        }
        fp_ld_fpscr(b, EI_A);
        fp_sync_fpcr(b);
        if (prec == 0U) {
            spe_ld_s(b, 0U, insn->ra);
            if (op != (uint8_t)SP_ABS && op != (uint8_t)SP_NABS &&
                op != (uint8_t)SP_NEG) {
                spe_ld_s(b, 1U, insn->rb);
            }
            if (op >= (uint8_t)SP_MADD && op <= (uint8_t)SP_NMSUB) {
                spe_ld_s(b, 2U, insn->rt);
                fp_calc(b, op, 0U, 1U, 2U);
            } else {
                fp_calc(b, op, 0U, 1U, 0U);
            }
            spe_st_s(b, insn->rt, 0U);
            fp_restore_fpcr(b);
            return fp_tail(b, insn);
        }
        spe_ld_pair(b, 0U, insn->ra);
        if (op != (uint8_t)SP_ABS && op != (uint8_t)SP_NABS &&
            op != (uint8_t)SP_NEG && op != (uint8_t)SP_SQRT) {
            spe_ld_pair(b, 1U, insn->rb);
        }
        fp_calc(b, op, prec == 1U ? 1U : 2U, 1U, 0U);
        spe_st_pair(b, insn->rt, 0U);
        fp_restore_fpcr(b);
        return fp_tail(b, insn);
    }
    /* Converts: ramax gates RA (wide XOs take RA 0/1, others RA 0). */
    static const struct { uint32_t xo; uint8_t in; uint32_t base; uint8_t out; uint8_t ramax; } cvtf[] = {
        { 719U, 0U, 0x1E22C000U, 1U, 0U }, { 751U, 1U, 0x1E624000U, 0U, 0U },
        { 720U, 3U, 0x1E230000U, 0U, 0U }, { 721U, 3U, 0x1E220000U, 0U, 0U },
        { 752U, 3U, 0x1E630000U, 1U, 1U }, { 753U, 3U, 0x1E620000U, 1U, 1U } };
    static const struct { uint32_t xo; uint8_t in; uint8_t rnd; uint8_t u; uint8_t ramax; } cvti[] = {
        { 724U, 0U, 1U, 1U, 0U }, { 725U, 0U, 1U, 0U, 0U }, { 728U, 0U, 0U, 1U, 0U },
        { 730U, 0U, 0U, 0U, 0U }, { 756U, 1U, 1U, 1U, 0U }, { 757U, 1U, 1U, 0U, 0U },
        { 760U, 1U, 0U, 1U, 1U }, { 762U, 1U, 0U, 0U, 1U } };
    for (i = 0U; i < sizeof(cvtf) / sizeof(cvtf[0]); i++) {
        if (cvtf[i].xo == xo && insn->ra <= cvtf[i].ramax) {
            unsigned in = cvtf[i].in;
            uint32_t base = cvtf[i].base;
            if (in == 3U && insn->ra == 1U) {
                in = 4U; /* full 64-bit pair, sf bit set */
                base |= 0x80000000U;
            }
            return spe_cvtf(b, insn, in, base, cvtf[i].out != 0U);
        }
    }
    for (i = 0U; i < sizeof(cvti) / sizeof(cvti[0]); i++) {
        if (cvti[i].xo == xo && insn->ra <= cvti[i].ramax) {
            return spe_cvti(b, insn, cvti[i].in, cvti[i].rnd != 0U,
                cvti[i].u != 0U, insn->ra == 1U);
        }
    }
    fp_restore_fpcr(b);
    return PPC32_EMIT_FALLBACK;
}
/* Indexed SPE 64-bit loads/stores (X-form only). */
static int spe_mem_x(a64_buf_t *b, const ppc32_insn_t *insn, uint32_t pc)
{
    bool is_store = (insn->xo == 800U || insn->xo == 802U);
    if (insn->rt >= 32U || insn->rb >= 32U || insn->ra >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    ei_ea_x(b, insn->ra, insn->rb);
    ei_guard_low(b, pc);
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, A64_ADDR);
    if (!is_store) {
        a64_emit(b, 0xF9400000U | ((unsigned)A64_TMP2 << 5) | 15U);
        FP_REV_X(15U);
        a64_emit_str_imm_w(b, 15U, A64_XCTX, ei_gpr_off(insn->rt));
        a64_emit(b, 0xD3400000U | (32U << 16) | (63U << 10) |
            (15U << 5) | 16U);
        a64_emit_str_imm_w(b, 16U, A64_XCTX, SPE_HI_OFF(insn->rt));
        b->gpr_cache_valid = 0;
    } else {
        a64_emit_ldr_imm_w(b, 15U, A64_XCTX, ei_gpr_off(insn->rt));
        a64_emit_ldr_imm_w(b, 16U, A64_XCTX, SPE_HI_OFF(insn->rt));
        a64_emit(b, 0xAA008000U | (16U << 16) | (15U << 5) | 15U);
        FP_REV_X(15U);
        a64_emit(b, 0xF9000000U | ((unsigned)A64_TMP2 << 5) | 15U);
    }
    if (b->overflow) {
        return PPC32_EMIT_FALLBACK;
    }
    return PPC32_EMIT_NEXT;
}

/* ---- top-level dispatch ---- */

static int fp_indexed(a64_buf_t *b, const ppc32_insn_t *insn, uint32_t pc)
{
    /* XOs 535..759 step 32: k bit0 = update, bit1 = double, bit2 = store. */
    uint32_t k;
    if (insn->xo < FP_XO_LFSX || insn->xo > FP_XO_STFDUX ||
        ((insn->xo - FP_XO_LFSX) & 31U) != 0U) {
        return PPC32_EMIT_FALLBACK;
    }
    k = (insn->xo - FP_XO_LFSX) >> 5U;
    return fp_ldst(b, insn, true, (k & 1U) != 0U, (k & 4U) != 0U,
        (k & 2U) != 0U, pc);
}

static int fp_classic(a64_buf_t *b, const ppc32_insn_t *insn, bool is_double)
{
    if (!is_double) {
        return fp_arith(b, insn, 0U);
    }
    /* X-form matches on the full 10-bit XO; anything else is A-form
     * (fp_arith validates the low 5 bits and field constraints). */
    switch (insn->xo) {
    case FP_XO_FCMPU: case FP_XO_FCMPO:
        return fp_cmp(b, insn);
    case FP_XO_FRSP: /* frsp: D -> S (fpr source) */
    case FP_XO_FCTIW: /* fctiw: D -> S32 (fpr source) */
    case FP_XO_FCTIWZ:
        if (insn->rt >= 32U || insn->ra != 0U || insn->rb >= 32U) {
            return PPC32_EMIT_FALLBACK;
        }
        if (insn->xo == FP_XO_FRSP) {
            return spe_cvtf(b, insn, 2U, 0x1E624000U, false);
        }
        return spe_cvti(b, insn, 2U, insn->xo == FP_XO_FCTIW, false,
            false);
    case FP_XO_FNEG: case FP_XO_FMR: case FP_XO_FNABS: case FP_XO_FABS:
        return fp_move(b, insn);
    case FP_XO_MFFS:
        return fp_mffs(b, insn);
    case FP_XO_MTFSB0:
        return fp_mtfsb(b, insn, 0);
    case FP_XO_MTFSB1:
        return fp_mtfsb(b, insn, 1);
    case FP_XO_MTFSF:
        return fp_mtfsf(b, insn);
    default:
        return fp_arith(b, insn, 1U);
    }
}
int ppc32_emit_fp(ppc32_emit_ctx_t *e, const ppc32_insn_t *insn,
    uint32_t pc)
{
    a64_buf_t *b = e->buf;
    if (insn == NULL) {
        return PPC32_EMIT_FALLBACK;
    }
    /* D-form primaries are consecutive: bit0 = update, bit1 = double,
     * bit2 = store. */
    if (insn->op >= (uint32_t)PPC32_OP_LFS &&
        insn->op <= (uint32_t)PPC32_OP_STFDU) {
        uint32_t k = insn->op - (uint32_t)PPC32_OP_LFS;
        return fp_ldst(b, insn, false, (k & 1U) != 0U, (k & 4U) != 0U,
            (k & 2U) != 0U, pc);
    }
    switch (insn->op) {
    case PPC32_OP_FPU_X:
        return fp_indexed(b, insn, pc);
    case PPC32_OP_FPU_SINGLE:
        return fp_classic(b, insn, false);
    case PPC32_OP_FPU_DOUBLE:
        return fp_classic(b, insn, true);
    case PPC32_OP_SPE:
        if (insn->xo == 768U || insn->xo == 770U || insn->xo == 800U ||
            insn->xo == 802U) {
            return spe_mem_x(b, insn, pc);
        }
        return spe_scalar(b, insn);
    default:
        return PPC32_EMIT_FALLBACK;
    }
}
