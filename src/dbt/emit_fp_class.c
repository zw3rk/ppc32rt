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
 * LT/GT/EQ/UN come from fcmp+NZCV; the class bit from the exponent. */
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
        a64_emit(b, 0xD3400000U | (51U << 10) | (12U << 5) | 10U);
    } else {
        a64_emit(b, 0x53000000U | (22U << 10) | (12U << 5) | 10U);
    }
    a64_emit(b, cmp | (10U << 5) | 31U);
    ei_cset(b, EI_X, A64_COND_EQ); /* isMantZero */
    a64_emit_and_reg_w(b, false, EI_T, EI_T, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_bic_reg_w(b, false, EI_T2, EI_T2, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_T, EI_T, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_T, EI_T, A64_SHIFT_LSL, 4U, false, NULL);
    a64_emit_orr_reg_w(b, EI_R, EI_R, EI_T, A64_SHIFT_LSL, 0U);
    a64_emit_mov_imm32(b, EI_X, FP_FPRF_MASK);
    a64_emit_bic_reg_w(b, false, EI_A, EI_A, EI_X, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_R, A64_SHIFT_LSL, 12U);
}
