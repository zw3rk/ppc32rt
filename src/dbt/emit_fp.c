/*
 * src/dbt/emit_fp.c — classic-FPU data-movement emitter (RC2 subset).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * See emit_fp.h. Lane L3b owns FP arithmetic/SPE and extends this file.
 * Conventions mirror interp/fp.c: fpr[fr] lives at ctx+0x128 as a u64
 * bit pattern; guest FP data is big-endian (REV/REV32 on every access).
 */

#include "dbt/emit_fp.h"

#include <stddef.h>

#include "ppc32rt.h"
#include "rt32/ppc32_a64_emit.h"

#define FP_OFF(fr) ((uint32_t)offsetof(ppc32_ctx_t, fpr) + (uint32_t)(fr) * 8U)

/* Raw 64-bit LDR/STR/REV (no X-reg helpers in rt32_a64_emit.h). */
#define FP_LDR_X(td, tb) \
    a64_emit(b, 0xF9400000U | ((unsigned)(tb) << 5) | (unsigned)(td))
#define FP_STR_X(ts, tb) \
    a64_emit(b, 0xF9000000U | ((unsigned)(tb) << 5) | (unsigned)(ts))
#define FP_REV_X(t) \
    a64_emit(b, 0xDAC00C00U | ((unsigned)(t) << 5) | (unsigned)(t))
#define FP_LDR_X_OFF(td, tb, off) \
    a64_emit(b, 0xF9400000U | (((off) / 8U) << 10) | \
        ((unsigned)(tb) << 5) | (unsigned)(td))
#define FP_STR_X_OFF(ts, tb, off) \
    a64_emit(b, 0xF9000000U | (((off) / 8U) << 10) | \
        ((unsigned)(tb) << 5) | (unsigned)(ts))

int ppc32_emit_fp(ppc32_emit_ctx_t *e, const ppc32_insn_t *insn,
    uint32_t pc)
{
    a64_buf_t *b = e->buf;
    bool is_update = false;
    bool is_store = false;
    bool is_double = false;

    (void)pc;
    if (insn == NULL || insn->rt >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    switch (insn->op) {
    case PPC32_OP_LFS:
        break;
    case PPC32_OP_LFSU:
        is_update = true;
        break;
    case PPC32_OP_LFD:
        is_double = true;
        break;
    case PPC32_OP_LFDU:
        is_double = true;
        is_update = true;
        break;
    case PPC32_OP_STFS:
        is_store = true;
        break;
    case PPC32_OP_STFSU:
        is_store = true;
        is_update = true;
        break;
    case PPC32_OP_STFD:
        is_store = true;
        is_double = true;
        break;
    case PPC32_OP_STFDU:
        is_store = true;
        is_double = true;
        is_update = true;
        break;
    default:
        return PPC32_EMIT_FALLBACK;
    }
    if (is_update) {
        if (insn->ra == 0U || insn->ra >= 32U) {
            return PPC32_EMIT_FALLBACK;
        }
    } else if (insn->ra >= 32U) {
        return PPC32_EMIT_FALLBACK;
    }
    /* EA into w22 (A64_ADDR), host address into x17 (A64_TMP2). */
    ei_ea_d(b, insn->ra, (uint32_t)insn->d);
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, A64_ADDR);
    if (!is_store) {
        if (is_double) {
            /* x15 = BE bytes; REV; store u64 pattern to fpr[rt]. */
            FP_LDR_X(15U, A64_TMP2);
            FP_REV_X(15U);
            FP_STR_X_OFF(15U, A64_XCTX, FP_OFF(insn->rt));
        } else {
            /* w15 = BE word; REV32; zero-extended u64 to fpr[rt]. */
            a64_emit_ldr_imm_w(b, 15U, A64_TMP2, 0U);
            a64_emit_rev_w(b, 15U, 15U);
            FP_STR_X_OFF(15U, A64_XCTX, FP_OFF(insn->rt));
        }
    } else {
        if (is_double) {
            FP_LDR_X_OFF(15U, A64_XCTX, FP_OFF(insn->rt));
            FP_REV_X(15U);
            FP_STR_X(15U, A64_TMP2);
        } else {
            FP_LDR_X_OFF(15U, A64_XCTX, FP_OFF(insn->rt));
            a64_emit_rev_w(b, 15U, 15U);
            a64_emit_str_imm_w(b, 15U, A64_TMP2, 0U);
        }
    }
    if (is_update) {
        ei_st(b, A64_ADDR, insn->ra);
    }
    if (b->overflow) {
        return PPC32_EMIT_FALLBACK;
    }
    return PPC32_EMIT_NEXT;
}
