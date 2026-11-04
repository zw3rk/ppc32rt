/*
 * src/dbt/emit_fp_class.c — NZCV/FPRF classify helpers (Phase 3, lane L3b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from emit_fp.c (file-size discipline): exact FPRF
 * classification shared by the compare and arithmetic emitters.
 */

#include "dbt/emit_fp.h"

#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"
#include "rt32/ppc32_a64_emit.h"
#include "dbt/emit_int.h"

/* NZCV (w10) -> PPC [LT,GT,EQ,UN] in EI_R/w11; clobbers w10-w14. */
void fp_nzcv_field(a64_buf_t *b)
{
    a64_emit_ubfm_w(b, EI_R, EI_B, 28U, 31U); /* [V,C,Z,N] */
    a64_emit_ubfm_w(b, EI_T, EI_R, 1U, 1U); /* C */
    a64_emit_ubfm_w(b, EI_T2, EI_R, 2U, 2U); /* Z */
    a64_emit_bic_reg_w(b, false, EI_T, EI_T, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_ubfm_w(b, EI_X, EI_R, 0U, 0U); /* V */
    a64_emit_bic_reg_w(b, false, EI_T, EI_T, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_T, EI_T, A64_SHIFT_LSL, 2U, false, NULL);
    a64_emit_ubfm_w(b, EI_T2, EI_R, 3U, 3U); /* N */
    a64_emit_shift_imm_w(b, EI_T2, EI_T2, A64_SHIFT_LSL, 3U, false, NULL);
    a64_emit_ubfm_w(b, EI_X, EI_R, 2U, 2U); /* Z */
    a64_emit_shift_imm_w(b, EI_X, EI_X, A64_SHIFT_LSL, 1U, false, NULL);
    a64_emit_orr_reg_w(b, EI_B, EI_T2, EI_T, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_B, EI_B, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_ubfm_w(b, EI_R, EI_R, 0U, 0U); /* V */
    a64_emit_orr_reg_w(b, EI_R, EI_B, EI_R, A64_SHIFT_LSL, 0U);
}

/* Exact FPRF of the result in Dvd/Svd into fpscr (w9); no FPSR use:
 * LT/GT/EQ/UN come from fcmp+NZCV; the class bit from the exponent.
 * P32-R8-2: C matches the oracle (fp_fprf64/fp_fprf32): set for QNaN,
 * denormals, and -0; clear for Inf, normals, and +0. The CSETs above
 * clobber x12/w12, so the pattern is reloaded before the mantissa,
 * sign, and quiet extracts below. x16 holds the saved FPCR across
 * fp_sync_fpcr/fp_restore_fpcr, so sign/quiet use w15; w10 is dead
 * after the mantissa CSET and holds the denormal flag. */
void fp_fprf(a64_buf_t *b, unsigned vd, bool dbl)
{
    uint32_t xmax = dbl ? 0x7FFU : 0xFFU;
    uint32_t cmp = dbl ? 0xF1000000U : 0x71000000U;

    a64_emit(b, (dbl ? 0x1E602008U : 0x1E202008U) | ((vd & 31U) << 5));
    a64_emit(b, 0xD53B4200U | 10U); /* mrs x10, nzcv */
    fp_nzcv_field(b); /* w11 = [LT,GT,EQ,UN] */
    if (dbl) {
        a64_emit(b, 0x9E660000U | ((vd & 31U) << 5) | 12U);
        a64_emit(b, 0xD3400000U | (52U << 16) | (62U << 10) |
            (12U << 5) | 10U);
    } else {
        a64_emit(b, 0x1E260000U | ((vd & 31U) << 5) | 12U);
        a64_emit(b, 0x53000000U | (23U << 16) | (30U << 10) |
            (12U << 5) | 10U);
    }
    a64_emit(b, cmp | (xmax << 10) | (10U << 5) | 31U);
    ei_cset(b, EI_T, A64_COND_EQ); /* isMaxExp */
    a64_emit(b, cmp | (10U << 5) | 31U);
    ei_cset(b, EI_T2, A64_COND_EQ); /* isZeroExp */
    if (dbl) {
        a64_emit(b, 0x9E660000U | ((vd & 31U) << 5) | 12U);
        a64_emit(b, 0xD3400000U | (51U << 10) | (12U << 5) | 10U);
    } else {
        a64_emit(b, 0x1E260000U | ((vd & 31U) << 5) | 12U);
        a64_emit(b, 0x53000000U | (22U << 10) | (12U << 5) | 10U);
    }
    a64_emit(b, cmp | (10U << 5) | 31U);
    ei_cset(b, EI_X, A64_COND_EQ); /* isMantZero */
    a64_emit_bic_reg_w(b, false, EI_B, EI_T2, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_and_reg_w(b, false, EI_T2, EI_T2, EI_X, A64_SHIFT_LSL, 0U);
    if (dbl) {
        a64_emit(b, 0xD3400000U | (63U << 16) | (63U << 10) |
            (12U << 5) | 15U); /* w15 = sign */
    } else {
        a64_emit(b, 0x53000000U | (31U << 16) | (31U << 10) |
            (12U << 5) | 15U); /* w15 = sign */
    }
    a64_emit_and_reg_w(b, false, EI_T2, EI_T2, 15U, A64_SHIFT_LSL, 0U);
    if (dbl) {
        a64_emit(b, 0xD3400000U | (51U << 16) | (51U << 10) |
            (12U << 5) | 15U); /* w15 = quiet */
    } else {
        a64_emit(b, 0x53000000U | (22U << 16) | (22U << 10) |
            (12U << 5) | 15U); /* w15 = quiet */
    }
    a64_emit_bic_reg_w(b, false, EI_T, EI_T, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_and_reg_w(b, false, EI_T, EI_T, 15U, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_T, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_T, EI_T, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_T, EI_T, A64_SHIFT_LSL, 4U, false, NULL);
    a64_emit_orr_reg_w(b, EI_R, EI_R, EI_T, A64_SHIFT_LSL, 0U);
    a64_emit_mov_imm32(b, EI_X, FP_FPRF_MASK);
    a64_emit_bic_reg_w(b, false, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_R, A64_SHIFT_LSL, 12U);
}

/* Guest FPSCR traffic for the post-store FR fixups below (same encoding
 * as the emit_fp.c statics). */
void fp_fpscr_ld(a64_buf_t *b, unsigned wd)
{
    uint32_t off = (uint32_t)offsetof(ppc32_ctx_t, fpscr);

    a64_emit(b, 0xB9400000U | ((off / 4U) << 10) |
        ((unsigned)A64_XCTX << 5) | (wd & 31U));
}

void fp_fpscr_st(a64_buf_t *b, unsigned ws)
{
    uint32_t off = (uint32_t)offsetof(ppc32_ctx_t, fpscr);

    a64_emit(b, 0xB9000000U | ((off / 4U) << 10) |
        ((unsigned)A64_XCTX << 5) | (ws & 31U));
}

/* wdst = (pattern in xsrc is Inf); clobbers w10. Selects 64/32-bit
 * extracts with dbl. xsrc is only read (UBFM), never written. */
static void fp_isinf(a64_buf_t *b, unsigned xsrc, unsigned wdst, bool dbl)
{
    if (dbl) {
        a64_emit(b, 0xD3400000U | (52U << 16) | (62U << 10) |
            ((xsrc & 31U) << 5) | 10U);
        a64_emit(b, 0xF1000000U | (0x7FFU << 10) | (10U << 5) | 31U);
    } else {
        a64_emit(b, 0x53000000U | (23U << 16) | (30U << 10) |
            ((xsrc & 31U) << 5) | 10U);
        a64_emit(b, 0x71000000U | (0xFFU << 10) | (10U << 5) | 31U);
    }
    ei_cset(b, wdst, A64_COND_EQ); /* isMaxExp */
    if (dbl) {
        a64_emit(b, 0xD3400000U | (51U << 10) | ((xsrc & 31U) << 5) | 10U);
    } else {
        a64_emit(b, 0x53000000U | (22U << 10) | ((xsrc & 31U) << 5) | 10U);
    }
    a64_emit(b, (dbl ? 0xF1000000U : 0x71000000U) | (10U << 5) | 31U);
    ei_cset(b, EI_X, A64_COND_EQ); /* isMantZero */
    a64_emit_and_reg_w(b, false, wdst, wdst, EI_X, A64_SHIFT_LSL, 0U);
}

/* P32-R8-6: classify the IOC mask for an op (iop: 0 add, 1 sub, 2 mul,
 * 3 div, 7 sqrt, 0xFE cvti, else VXSNAN) from saved A (v7) and B
 * (v1/v2) into w17 (A64_TMP2) inside the cold IOC != 0 branch of
 * fp_accum. Uses x11 as the pattern source for fp_isinf so it never
 * aliases the w10/w14 temporaries or w12/w13 outputs. */
void fp_inv_classify(a64_buf_t *b, unsigned iop, bool dbl)
{
    unsigned v2 = (iop == 2U) ? 2U : 1U;
    uint32_t fcmp0 = dbl ? 0x1E602008U : 0x1E202008U;
    uint32_t fcmp = dbl ? 0x1E602000U : 0x1E202000U;
    uint32_t fmov = dbl ? 0x9E660000U : 0x1E260000U;
    size_t skip;

    if (iop == 0xFEU) {
        a64_emit_mov_imm32(b, 17U, FP_VXCVI | FP_VX | FP_FX);
        return;
    }
    a64_emit_mov_imm32(b, 17U, FP_VXSNAN | FP_VX | FP_FX);
    if (iop == 7U) {
        a64_emit(b, fcmp0 | (7U << 5)); /* fcmp A(v7), #0 */
        skip = a64_emit_b_cond_placeholder(b, A64_COND_PL);
        a64_emit_mov_imm32(b, 17U, FP_VXSQRT | FP_VX | FP_FX);
        a64_patch_b_cond(b, skip, b->count);
        return;
    }
    if (iop > 3U) {
        return;
    }
    if (iop <= 1U) {
        /* VXISI: both infinities, opposite (add) or same (sub) signs. */
        a64_emit(b, fmov | (7U << 5) | 11U);
        fp_isinf(b, 11U, EI_T2, dbl);
        a64_emit(b, fmov | (v2 << 5) | 11U);
        fp_isinf(b, 11U, EI_T, dbl);
        a64_emit(b, fcmp | (v2 << 16) | (7U << 5)); /* fcmp A, B */
        ei_cset(b, 15U, (iop == 0U) ? A64_COND_NE : A64_COND_EQ);
        a64_emit_and_reg_w(b, false, EI_T2, EI_T2, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_and_reg_w(b, false, EI_T2, EI_T2, 15U, A64_SHIFT_LSL, 0U);
        skip = a64_emit_cbz_w_placeholder(b, false, EI_T2);
        a64_emit_mov_imm32(b, 17U, FP_VXISI | FP_VX | FP_FX);
        a64_patch_cbz_w(b, skip, b->count);
    } else if (iop == 2U) {
        /* VXIMZ: 0*Inf either way round. */
        a64_emit(b, fmov | (7U << 5) | 11U);
        fp_isinf(b, 11U, EI_T2, dbl); /* infA */
        a64_emit(b, fcmp0 | (7U << 5)); /* fcmp A, #0 */
        ei_cset(b, 15U, A64_COND_EQ); /* zeroA */
        a64_emit(b, fmov | (v2 << 5) | 11U);
        fp_isinf(b, 11U, EI_T, dbl); /* infB */
        a64_emit(b, fcmp0 | (v2 << 5)); /* fcmp B, #0 */
        ei_cset(b, EI_X, A64_COND_EQ); /* zeroB */
        a64_emit_and_reg_w(b, false, 15U, 15U, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_and_reg_w(b, false, EI_X, EI_X, EI_T2, A64_SHIFT_LSL, 0U);
        a64_emit_orr_reg_w(b, EI_T2, 15U, EI_X, A64_SHIFT_LSL, 0U);
        skip = a64_emit_cbz_w_placeholder(b, false, EI_T2);
        a64_emit_mov_imm32(b, 17U, FP_VXIMZ | FP_VX | FP_FX);
        a64_patch_cbz_w(b, skip, b->count);
    } else {
        size_t skip2;

        /* VXZDZ: 0/0; VXIDI: Inf/Inf. */
        a64_emit(b, fcmp0 | (7U << 5)); /* fcmp A, #0 */
        ei_cset(b, EI_T2, A64_COND_EQ); /* zeroA */
        a64_emit(b, fcmp0 | (v2 << 5)); /* fcmp B, #0 */
        ei_cset(b, EI_T, A64_COND_EQ); /* zeroB */
        a64_emit_and_reg_w(b, false, EI_T2, EI_T2, EI_T, A64_SHIFT_LSL, 0U);
        skip = a64_emit_cbz_w_placeholder(b, false, EI_T2);
        a64_emit_mov_imm32(b, 17U, FP_VXZDZ | FP_VX | FP_FX);
        a64_patch_cbz_w(b, skip, b->count);
        a64_emit(b, fmov | (7U << 5) | 11U);
        fp_isinf(b, 11U, EI_T2, dbl); /* infA */
        a64_emit(b, fmov | (v2 << 5) | 11U);
        fp_isinf(b, 11U, EI_T, dbl); /* infB */
        a64_emit_and_reg_w(b, false, EI_T2, EI_T2, EI_T, A64_SHIFT_LSL, 0U);
        skip2 = a64_emit_cbz_w_placeholder(b, false, EI_T2);
        a64_emit_mov_imm32(b, 17U, FP_VXIDI | FP_VX | FP_FX);
        a64_patch_cbz_w(b, skip2, b->count);
    }
}

/* P32-R8-5: FR fixup for arithmetic (oracle fp_rounded_up), called inside
 * fp_accum when FPSR is non-zero with fpscr in w9 (EI_A) and FI (bit 17)
 * already reflecting IXC. For RN mode, ADD/SUB/MUL/DIV/SQRT compute the
 * exact rounding residual via FastTwoSum / FMSUB / FNMSUB without
 * touching FPCR or issuing ISB; FMA ops (op >= 8) fall back to RZ redo.
 * Clobbers w10-w15, x21, v4-v6. */
void fp_fr_arith(a64_buf_t *b, unsigned op, bool dbl)
{
    uint32_t fabsop = dbl ? 0x1E60C000U : 0x1E20C000U;
    uint32_t fcmpop = dbl ? 0x1E602000U : 0x1E202000U;
    uint32_t fcmp0 = dbl ? 0x1E602008U : 0x1E202008U;
    uint32_t fcsel = dbl ? 0x1E600C00U : 0x1E200C00U;
    uint32_t fsubop = dbl ? 0x1E603800U : 0x1E203800U;
    uint32_t fmsub = dbl ? 0x1F408000U : 0x1F008000U;
    uint32_t fnmsub = dbl ? 0x1F608000U : 0x1F208000U;
    size_t skip_ixc;
    size_t to_not_rn;
    size_t to_rz;
    size_t to_join;
    size_t skip_fr;

    a64_emit_ubfm_w(b, EI_T, EI_A, 17U, 17U); /* T = FI (IXC) */
    skip_ixc = a64_emit_cbz_w_placeholder(b, false, EI_T);
    a64_emit_ubfm_w(b, EI_T2, EI_A, 0U, 1U); /* T2 = RN mode */
    to_not_rn = a64_emit_cbz_w_placeholder(b, true, EI_T2);
    if (op <= 1U) {
        /* ADD/SUB: FastTwoSum exact residual T = R - H vs L. */
        if (op == 1U) {
            a64_emit(b, (dbl ? 0x1E614000U : 0x1E214000U) | (1U << 5) | 4U);
        } else {
            a64_emit(b, 0x1E604000U | (1U << 5) | 4U);
        }
        a64_emit(b, fabsop | (7U << 5) | 5U); /* fabs v5, v7 (|A|) */
        a64_emit(b, fabsop | (4U << 5) | 6U); /* fabs v6, v4 (|B'|) */
        a64_emit(b, fcmpop | (6U << 16) | (5U << 5));
        a64_emit(b, fcsel | (4U << 16) | ((uint32_t)A64_COND_GE << 12) |
            (7U << 5) | 5U); /* v5 = H */
        a64_emit(b, fcsel | (7U << 16) | ((uint32_t)A64_COND_GE << 12) |
            (4U << 5) | 6U); /* v6 = L */
        a64_emit(b, fsubop | (5U << 16) | (0U << 5) | 5U); /* T = R - H */
        a64_emit(b, fcmp0 | (0U << 5)); /* fcmp R, #0.0 */
        a64_emit(b, fcsel | (6U << 16) | ((uint32_t)A64_COND_GT << 12) |
            (5U << 5) | 4U);
        a64_emit(b, fcsel | (5U << 16) | ((uint32_t)A64_COND_GT << 12) |
            (6U << 5) | 6U);
        a64_emit(b, fcmpop | (6U << 16) | (4U << 5));
        ei_cset(b, EI_T, A64_COND_GT);
    } else {
        size_t to_fast = 0U;
        uint32_t fbase = dbl ? 0x1E600000U : 0x1E200000U;
        uint32_t redo;
        if (op == 2U) {
            redo = (fbase | 0x0800U) | (2U << 16) | (7U << 5) | 5U;
            a64_emit(b, fabsop | (0U << 5) | 6U); /* fabs v6, v0 (|R|) */
            a64_emit(b, fabsop | (7U << 5) | 5U); /* fabs v5, v7 (|A|) */
            a64_emit(b, fabsop | (2U << 5) | 4U); /* fabs v4, v2 (|B|) */
            a64_emit(b, fmsub | (4U << 16) | (6U << 10) | (5U << 5) | 5U);
        } else if (op == 3U) {
            redo = (fbase | 0x1800U) | (1U << 16) | (7U << 5) | 5U;
            a64_emit(b, fabsop | (0U << 5) | 6U); /* fabs v6, v0 (|R|) */
            a64_emit(b, fabsop | (7U << 5) | 5U); /* fabs v5, v7 (|A|) */
            a64_emit(b, fabsop | (1U << 5) | 4U); /* fabs v4, v1 (|B|) */
            a64_emit(b, fnmsub | (4U << 16) | (5U << 10) | (6U << 5) | 5U);
        } else if (op == 7U) {
            redo = (fbase | 0x1C000U) | (7U << 5) | 5U;
            a64_emit(b, fnmsub | (0U << 16) | (7U << 10) | (0U << 5) | 5U);
        } else {
            redo = (dbl ? 0x1F400000U : 0x1F000000U) |
                (((op - 8U) & 2U) << 20) | (((op - 8U) & 1U) << 15) |
                (2U << 16) | (1U << 10) | (7U << 5) | 5U;
        }
        if (op < 8U) {
            a64_emit(b, fcmp0 | (5U << 5));
            ei_cset(b, EI_T, A64_COND_GT);
            to_fast = a64_emit_b_cond_placeholder(b, A64_COND_NE);
        }
        a64_emit(b, 0x1E604000U | (0U << 5) | 6U); /* fmov d6, d0 */
        a64_emit(b, 0xD53B4400U | 15U); /* mrs x15, fpcr */
        a64_emit_mov_imm32(b, 21U, 0x00C00000U); /* RMode mask */
        a64_emit_orr_reg_w(b, 15U, 15U, 21U, A64_SHIFT_LSL, 0U); /* RZ */
        a64_emit(b, 0xD51B4400U | 15U); /* msr fpcr, x15 */
        a64_emit(b, 0xD5033FDFU); /* isb */
        a64_emit(b, redo); /* RZ result -> v5 */
        a64_emit_bic_reg_w(b, false, 15U, 15U, 21U, A64_SHIFT_LSL, 0U);
        a64_emit(b, 0xD51B4400U | 15U); /* msr fpcr, x15 */
        a64_emit(b, 0xD5033FDFU); /* isb */
        a64_emit(b, fabsop | (6U << 5) | 6U);
        a64_emit(b, fabsop | (5U << 5) | 5U);
        a64_emit(b, fcmpop | (5U << 16) | (6U << 5));
        ei_cset(b, EI_T, A64_COND_HI);
        if (op < 8U) {
            a64_patch_b_cond(b, to_fast, b->count);
        }
    }
    to_join = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, to_not_rn, b->count);
    ei_cmp_imm(b, EI_T2, 1U); /* RZ never rounds up */
    to_rz = a64_emit_b_cond_placeholder(b, A64_COND_EQ);
    a64_emit(b, fcmp0 | (0U << 5)); /* fcmp result, #0 */
    ei_cset(b, EI_T, A64_COND_GT); /* RP: result > +0 */
    ei_cset(b, EI_X, A64_COND_MI); /* RM: result < -0 */
    ei_cmp_imm(b, EI_T2, 2U); /* RP? */
    a64_emit_csel_w(b, EI_T, EI_T, EI_X, A64_COND_EQ);
    a64_patch_b_cond(b, to_join, b->count);
    skip_fr = a64_emit_cbz_w_placeholder(b, false, EI_T);
    a64_emit_mov_imm32(b, EI_X, FP_FR);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    a64_patch_cbz_w(b, skip_fr, b->count);
    a64_patch_b_cond(b, to_rz, b->count);
    a64_patch_cbz_w(b, skip_ixc, b->count);
}

/* P32-R8-5: post-store FR fixup for converts (frsp/fctiw): FR iff the
 * converted magnitude exceeds the saved original. to_int selects
 * SCVTF W(round_v)->D5 first, otherwise the double result is moved
 * from round_v. Skips invalid (IOC) and exact (!IXC) ops, so NaN and
 * saturation cases keep FR cleared. Clobbers w10, w12-w14. */
void fp_fr_mag(a64_buf_t *b, unsigned orig_v, unsigned round_v, bool to_int)
{
    size_t skip_ioc;
    size_t skip_ixc;
    size_t skip_fr;

    fp_fpscr_ld(b, EI_A);
    a64_emit(b, 0xD53B4420U | 10U); /* mrs x10, fpsr */
    a64_emit_ubfm_w(b, EI_T, EI_B, 0U, 0U); /* T = IOC */
    skip_ioc = a64_emit_cbz_w_placeholder(b, true, EI_T);
    a64_emit_ubfm_w(b, EI_T, EI_B, 4U, 4U); /* T = IXC */
    skip_ixc = a64_emit_cbz_w_placeholder(b, false, EI_T);
    if (to_int) {
        a64_emit_scvtf_w_to_d(b, 5U, round_v);
    } else if (round_v != 5U) {
        a64_emit(b, 0x1E604000U | ((round_v & 31U) << 5) | 5U);
    }
    a64_emit(b, 0x1E604000U | ((orig_v & 31U) << 5) | 6U);
    a64_emit(b, 0x1E60C000U | (5U << 5) | 5U); /* fabs d5, d5 */
    a64_emit(b, 0x1E60C000U | (6U << 5) | 6U); /* fabs d6, d6 */
    a64_emit(b, 0x1E602000U | (6U << 16) | (5U << 5)); /* fcmp d5, d6 */
    ei_cset(b, EI_T, A64_COND_HI);
    skip_fr = a64_emit_cbz_w_placeholder(b, false, EI_T);
    a64_emit_mov_imm32(b, EI_X, FP_FR);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    a64_patch_cbz_w(b, skip_ioc, b->count);
    a64_patch_cbz_w(b, skip_ixc, b->count);
    a64_patch_cbz_w(b, skip_fr, b->count);
    fp_fpscr_st(b, EI_A);
}
