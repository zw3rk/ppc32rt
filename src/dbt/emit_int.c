/*
 * src/dbt/emit_int.c — AArch64 integer instruction emitter (Phase 2, lane L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per-op lowerings consumed via ppc32_emit_int (see emit_int.h for the
 * contract, register discipline, and shared helpers). Semantics mirror
 * src/interp/interp.c; anything without a native lowering returns
 * PPC32_EMIT_FALLBACK.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"
#include "interp/decode.h"
#include "ppc32_a64_emit.h"
#include "dbt/emit_int.h"

void ppc32_emit_begin(ppc32_emit_ctx_t *e, ppc32_ctx_t *ctx, a64_buf_t *buf)
{
    e->buf = buf;
    e->ctx = ctx;
}

void ppc32_emit_fallback(ppc32_emit_ctx_t *e, uint32_t pc)
{
    a64_emit_exit_undef(e->buf, pc);
}

/* ---- D-form ALU immediates ---- */

static int ei_addi(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t imm = (uint32_t)in->si;

    if (in->op == PPC32_OP_ADDIS) {
        imm <<= 16U;
    }
    if (in->ra == 0U) {
        a64_emit_mov_imm32(b, EI_R, imm); /* li/lis */
    } else {
        ei_ld(b, EI_A, in->ra);
        a64_emit_mov_imm32(b, EI_B, imm);
        a64_emit_add_reg_w(b, false, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    }
    ei_st(b, EI_R, in->rt);
    return PPC32_EMIT_NEXT;
}

/* addic/addic./subfic: carry out via adds/subs, then XER.CA. */
static int ei_addic(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->ra);
    a64_emit_mov_imm32(b, EI_B, (uint32_t)in->si);
    if (in->op == PPC32_OP_SUBFIC) {
        a64_emit_sub_reg_w(b, true, EI_R, EI_B, EI_A, A64_SHIFT_LSL, 0U);
    } else {
        a64_emit_add_reg_w(b, true, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    }
    ei_st(b, EI_R, in->rt);
    ei_xer_ca_from_c(b);
    if (in->op == PPC32_OP_ADDIC_DOT) {
        ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
        ei_set_cr0(b, EI_R, EI_X);
    }
    return PPC32_EMIT_NEXT;
}

static int ei_mulli(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->ra);
    a64_emit_mov_imm32(b, EI_B, (uint32_t)in->si);
    a64_emit_madd_w(b, EI_R, EI_A, EI_B, A64_ZR);
    ei_st(b, EI_R, in->rt);
    return PPC32_EMIT_NEXT;
}

/* andi/andis set CR0; ori/oris/xori/xoris do not. Dest is RA. */
static int ei_logical_imm(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t imm = in->ui;

    if (in->op != PPC32_OP_ANDI && in->op != PPC32_OP_ORI &&
        in->op != PPC32_OP_XORI) {
        imm <<= 16U;
    }
    ei_ld(b, EI_A, in->rs);
    a64_emit_mov_imm32(b, EI_B, imm);
    if (in->op == PPC32_OP_ANDI || in->op == PPC32_OP_ANDIS) {
        a64_emit_and_reg_w(b, false, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    } else if (in->op == PPC32_OP_ORI || in->op == PPC32_OP_ORIS) {
        a64_emit_orr_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    } else {
        a64_emit_eor_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    }
    ei_st(b, EI_R, in->ra);
    if (in->op == PPC32_OP_ANDI || in->op == PPC32_OP_ANDIS) {
        ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
        ei_set_cr0(b, EI_R, EI_X);
    }
    return PPC32_EMIT_NEXT;
}

/* L=1 (64-bit) has no lowering: interp UNDEFs it, so we fall back. */
static int ei_cmp(a64_buf_t *b, const ppc32_insn_t *in)
{
    unsigned ltcond;
    unsigned gtcond;

    if ((in->rt & 1U) != 0U) {
        return PPC32_EMIT_FALLBACK;
    }
    ei_ld(b, EI_A, in->ra);
    if (in->op == PPC32_OP_CMP || in->op == PPC32_OP_CMPL) {
        ei_ld(b, EI_B, in->rb);
    } else if (in->op == PPC32_OP_CMPI) {
        a64_emit_mov_imm32(b, EI_B, (uint32_t)in->si);
    } else {
        a64_emit_mov_imm32(b, EI_B, in->ui);
    }
    ei_cmp_reg(b, EI_A, EI_B);
    if (in->op == PPC32_OP_CMP || in->op == PPC32_OP_CMPI) {
        ltcond = A64_COND_LT;
        gtcond = A64_COND_GT;
    } else {
        ltcond = A64_COND_CC;
        gtcond = A64_COND_HI;
    }
    ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
    ei_set_crf(b, in->rt >> 2U, ltcond, gtcond, EI_X);
    return PPC32_EMIT_NEXT;
}

/* ---- XO-form add/sub with CA / OV / CR0 (neg folds in as a case) ---- */

static int ei_addsub_xo(a64_buf_t *b, const ppc32_insn_t *in)
{
    bool is_sub = in->op == PPC32_OP_SUBF || in->op == PPC32_OP_SUBFC ||
        in->op == PPC32_OP_SUBFE || in->op == PPC32_OP_SUBFME ||
        in->op == PPC32_OP_SUBFZE || in->op == PPC32_OP_NEG;

    if (in->op != PPC32_OP_NEG) {
        ei_ld(b, EI_A, in->ra);
        ei_ld(b, EI_B, in->rb);
    } else {
        ei_ld(b, EI_A, in->ra);
    }
    switch (in->op) {
    case PPC32_OP_ADD:
        a64_emit_add_reg_w(b, false, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        break;
    case PPC32_OP_ADDC:
        a64_emit_add_reg_w(b, true, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        ei_xer_ca_from_c(b);
        break;
    case PPC32_OP_SUBF:
        a64_emit_sub_reg_w(b, false, EI_R, EI_B, EI_A, A64_SHIFT_LSL, 0U);
        break;
    case PPC32_OP_SUBFC:
        a64_emit_sub_reg_w(b, true, EI_R, EI_B, EI_A, A64_SHIFT_LSL, 0U);
        ei_xer_ca_from_c(b);
        break;
    case PPC32_OP_NEG:
        a64_emit_sub_reg_w(b, false, EI_R, A64_ZR, EI_A, A64_SHIFT_LSL, 0U);
        ei_cmp_imm(b, EI_A, 0U);
        ei_cset(b, EI_B, A64_COND_EQ); /* CA = (a == 0) */
        ei_xer_ca_reg(b, EI_B);
        break;
    case PPC32_OP_ADDE:
        /* R = A+B+CA_old; C = carry(A+B) | carry((A+B)+CA_old). The
         * adc carry-in would double-count carry(A+B) (RC2: qsort
         * mis-sorted once __internal_syscall_cancel ran), so both
         * carries are materialized and ORed instead. */
        ei_ld_ca(b, EI_T);
        a64_emit_add_reg_w(b, false, EI_T2, EI_A, EI_B, A64_SHIFT_LSL,
            0U);
        a64_emit_add_reg_w(b, true, EI_R, EI_T2, EI_T, A64_SHIFT_LSL,
            0U);
        ei_cset(b, EI_X, A64_COND_CS); /* X = carry(T2+CA_old) */
        ei_cmp_reg(b, EI_T2, EI_A); /* C = (T2>=A) = !carry(A+B) */
        ei_cset(b, EI_T, A64_COND_CC); /* T = carry(A+B) */
        a64_emit_orr_reg_w(b, EI_T, EI_X, EI_T, A64_SHIFT_LSL, 0U);
        ei_xer_ca_reg(b, EI_T);
        break;
    case PPC32_OP_SUBFE: /* R = (B-A) - (1-CA). The first sub may
        * borrow (B<A) and the flags-free sub drops that borrow, so the
        * second sub's carry alone is wrong (RC2: subfe CA stuck at 1
        * whenever B<A, e.g. the addic/subfe zero-test idiom with input
        * 0 in _int_malloc/_IO paths). CA = C1 & C2 with C1 = (B>=A)
        * from the first sub and C2 = (t>=1-CA) from the second: when
        * B<A the true difference is negative and can never reach
        * (1-CA) in {0,1}, so C1 gates correctly. */
        ei_ld_ca(b, EI_T);
        a64_emit_sub_reg_w(b, true, EI_R, EI_B, EI_A, A64_SHIFT_LSL, 0U);
        ei_cset(b, EI_T2, A64_COND_CS); /* T2 = C1 = (B>=A) */
        a64_emit_mov_imm32(b, EI_X, 1U);
        a64_emit_sub_reg_w(b, false, EI_X, EI_X, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_sub_reg_w(b, true, EI_R, EI_R, EI_X, A64_SHIFT_LSL, 0U);
        ei_cset(b, EI_X, A64_COND_CS); /* X = C2 = (t>=1-CA) */
        a64_emit_and_reg_w(b, false, EI_T, EI_T2, EI_X, A64_SHIFT_LSL, 0U);
        ei_xer_ca_reg(b, EI_T);
        break;
    case PPC32_OP_ADDZE:
        ei_ld_ca(b, EI_T);
        a64_emit_add_reg_w(b, true, EI_R, EI_A, EI_T, A64_SHIFT_LSL, 0U);
        ei_xer_ca_from_c(b);
        break;
    case PPC32_OP_SUBFZE:
        ei_ld_ca(b, EI_T);
        a64_emit_mvn_reg_w(b, EI_R, EI_A, A64_SHIFT_LSL, 0U);
        a64_emit_add_reg_w(b, true, EI_R, EI_R, EI_T, A64_SHIFT_LSL, 0U);
        ei_xer_ca_from_c(b);
        break;
    case PPC32_OP_ADDME: /* r = a + CA - 1; carry = (a != 0 || CA) */
        ei_ld_ca(b, EI_T);
        a64_emit_orr_reg_w(b, EI_B, EI_A, EI_T, A64_SHIFT_LSL, 0U);
        ei_cmp_imm(b, EI_B, 0U);
        ei_cset(b, EI_B, A64_COND_NE);
        a64_emit_mov_imm32(b, EI_T2, 1U);
        a64_emit_sub_reg_w(b, false, EI_T2, EI_T2, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_sub_reg_w(b, false, EI_R, EI_A, EI_T2, A64_SHIFT_LSL, 0U);
        ei_xer_ca_reg(b, EI_B);
        break;
    default: /* SUBFME: r = ~a - (1 - CA); carry = (~a|CA) != 0 */
        ei_ld_ca(b, EI_T);
        a64_emit_mvn_reg_w(b, EI_R, EI_A, A64_SHIFT_LSL, 0U);
        a64_emit_orr_reg_w(b, EI_B, EI_R, EI_T, A64_SHIFT_LSL, 0U);
        ei_cmp_imm(b, EI_B, 0U);
        ei_cset(b, EI_B, A64_COND_NE);
        a64_emit_mov_imm32(b, EI_T2, 1U);
        a64_emit_sub_reg_w(b, false, EI_T2, EI_T2, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_sub_reg_w(b, false, EI_R, EI_R, EI_T2, A64_SHIFT_LSL, 0U);
        ei_xer_ca_reg(b, EI_B);
        break;
    }
    if (in->oe != 0U) {
        if (is_sub && in->op != PPC32_OP_SUBFC && in->op != PPC32_OP_SUBFE &&
            in->op != PPC32_OP_SUBF && in->op != PPC32_OP_NEG) {
            /* SUBFME/SUBFZE: ov = (r>>31) != (~a>>31). */
            a64_emit_shift_imm_w(b, EI_T, EI_A, A64_SHIFT_LSR, 31U, false,
                NULL);
            a64_emit_shift_imm_w(b, EI_A, EI_R, A64_SHIFT_LSR, 31U, false,
                NULL);
            a64_emit_eor_reg_w(b, EI_A, EI_A, EI_T, A64_SHIFT_LSL, 0U);
            a64_emit_mov_imm32(b, EI_B, 1U);
            a64_emit_eor_reg_w(b, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        } else if (is_sub) {
            ei_sub_ov(b, EI_A, EI_B, EI_R);
        } else {
            ei_add_ov(b, EI_A, EI_B, EI_R);
        }
        ei_xer_ov_reg(b, EI_A);
    }
    if (in->oe != 0U && in->op == PPC32_OP_NEG) {
        a64_emit_mov_imm32(b, EI_B, 0x80000000U);
        ei_cmp_reg(b, EI_A, EI_B);
        ei_cset(b, EI_B, A64_COND_EQ);
        ei_xer_ov_reg(b, EI_B);
    }
    ei_finish(b, EI_R, in->rt, in->rc);
    return PPC32_EMIT_NEXT;
}

/* ---- multiply / divide ---- */

static int ei_mulh(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->ra);
    ei_ld(b, EI_B, in->rb);
    if (in->op == PPC32_OP_MULHWU) {
        a64_emit_umaddl_x(b, EI_A, EI_A, EI_B, A64_ZR);
    } else {
        a64_emit_smaddl_x(b, EI_A, EI_A, EI_B, A64_ZR);
    }
    ei_lsr_x32(b);
    a64_emit_mov_w(b, EI_R, EI_B);
    ei_finish(b, EI_R, in->rt, in->rc);
    return PPC32_EMIT_NEXT;
}

static int ei_mullw(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->ra);
    ei_ld(b, EI_B, in->rb);
    a64_emit_madd_w(b, EI_R, EI_A, EI_B, A64_ZR);
    ei_st(b, EI_R, in->rt);
    if (in->oe != 0U) {
        /* ov = (prod >> 32) != sign(r). */
        a64_emit_smaddl_x(b, EI_A, EI_A, EI_B, A64_ZR);
        ei_lsr_x32(b);
        a64_emit_shift_imm_w(b, EI_T, EI_R, A64_SHIFT_ASR, 31U, false, NULL);
        ei_cmp_reg(b, EI_B, EI_T);
        ei_cset(b, EI_B, A64_COND_NE);
        ei_xer_ov_reg(b, EI_B);
    }
    if (in->rc != 0U) {
        ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
        ei_set_cr0(b, EI_R, EI_X);
    }
    return PPC32_EMIT_NEXT;
}

/* SDIV/UDIV by zero yield 0 on AArch64 (no trap), matching interp;
 * INT_MIN/-1 saturates to INT_MIN, also matching. divwu+OE clears OV. */
static int ei_divw(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->ra);
    ei_ld(b, EI_B, in->rb);
    if (in->op == PPC32_OP_DIVW) {
        a64_emit_sdiv_w(b, EI_R, EI_A, EI_B);
    } else {
        a64_emit_udiv_w(b, EI_R, EI_A, EI_B);
    }
    ei_st(b, EI_R, in->rt);
    if (in->oe != 0U) {
        if (in->op == PPC32_OP_DIVW) {
            a64_emit_mov_imm32(b, EI_T, 0x80000000U);
            ei_cmp_reg(b, EI_A, EI_T);
            ei_cset(b, EI_T, A64_COND_EQ);
            a64_emit_mov_imm32(b, EI_T2, 0xFFFFFFFFU);
            ei_cmp_reg(b, EI_B, EI_T2);
            ei_cset(b, EI_T2, A64_COND_EQ);
            a64_emit_and_reg_w(b, false, EI_T, EI_T, EI_T2, A64_SHIFT_LSL,
                0U);
            ei_xer_ov_reg(b, EI_T);
        } else {
            a64_emit_movz_w(b, EI_T, 0U, 0U);
            ei_xer_ov_reg(b, EI_T);
        }
    }
    if (in->rc != 0U) {
        ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
        ei_set_cr0(b, EI_R, EI_X);
    }
    return PPC32_EMIT_NEXT;
}

/* ---- XO logicals (dest RA), extsb/extsh/cntlzw, shifts, rotates ---- */

static int ei_logical_xo(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->rs);
    ei_ld(b, EI_B, in->rb);
    switch (in->op) {
    case PPC32_OP_AND:
        a64_emit_and_reg_w(b, false, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        break;
    case PPC32_OP_ANDC:
        a64_emit_bic_reg_w(b, false, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        break;
    case PPC32_OP_ORC:
        a64_emit_orn_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        break;
    case PPC32_OP_XOR:
        a64_emit_eor_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        break;
    case PPC32_OP_NAND:
    case PPC32_OP_NOR:
    case PPC32_OP_EQV:
        if (in->op == PPC32_OP_NAND) {
            a64_emit_and_reg_w(b, false, EI_R, EI_A, EI_B, A64_SHIFT_LSL,
                0U);
        } else if (in->op == PPC32_OP_NOR) {
            a64_emit_orr_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_eor_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        }
        a64_emit_mvn_reg_w(b, EI_R, EI_R, A64_SHIFT_LSL, 0U);
        break;
    default: /* PPC32_OP_OR */
        a64_emit_orr_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_LSL, 0U);
        break;
    }
    ei_finish(b, EI_R, in->ra, in->rc);
    return PPC32_EMIT_NEXT;
}

static int ei_ext_clz(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->rs);
    if (in->op == PPC32_OP_EXTSB) {
        a64_emit_sbfm_w(b, EI_R, EI_A, 0U, 7U);
    } else if (in->op == PPC32_OP_EXTSH) {
        a64_emit_sbfm_w(b, EI_R, EI_A, 0U, 15U);
    } else {
        a64_emit_clz_w(b, EI_R, EI_A);
    }
    ei_finish(b, EI_R, in->ra, in->rc);
    return PPC32_EMIT_NEXT;
}

/* slw/srw: n = rb & 63; n >= 32 yields 0 (LSLV alone wraps mod 32). */
static int ei_shift_w(a64_buf_t *b, const ppc32_insn_t *in)
{
    ei_ld(b, EI_A, in->rs);
    ei_ld(b, EI_B, in->rb);
    a64_emit_mov_imm32(b, EI_R, 63U);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_R, A64_SHIFT_LSL, 0U);
    a64_emit_shift_reg_w(b, EI_R, EI_A, EI_B,
        in->op == PPC32_OP_SLW ? A64_SHIFT_LSL : A64_SHIFT_LSR);
    ei_cmp_imm(b, EI_B, 32U);
    a64_emit_csel_w(b, EI_R, EI_R, A64_ZR, A64_COND_CC);
    ei_finish(b, EI_R, in->ra, in->rc);
    return PPC32_EMIT_NEXT;
}

/* sraw/srawi with the dropped-bit CA rule; n==0 rides the general path
 * (r=s, CA=0) exactly like interp. */
static int ei_sraw(a64_buf_t *b, const ppc32_insn_t *in, bool is_imm)
{
    ei_ld(b, EI_A, in->rs);
    if (is_imm) {
        a64_emit_mov_imm32(b, EI_B, in->rb);
    } else {
        ei_ld(b, EI_B, in->rb);
        a64_emit_mov_imm32(b, EI_R, 63U);
        a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_R, A64_SHIFT_LSL, 0U);
    }
    ei_cmp_imm(b, EI_B, 0U); /* nzn = (n != 0): CA gate */
    ei_cset(b, EI_T, A64_COND_NE);
    a64_emit_shift_reg_w(b, EI_T2, EI_A, EI_B, A64_SHIFT_ASR);
    a64_emit_shift_imm_w(b, EI_R, EI_A, A64_SHIFT_ASR, 31U, false, NULL);
    ei_cmp_imm(b, EI_B, 32U); /* r = (n>=32) ? signfill : asrv(s,n) */
    a64_emit_csel_w(b, EI_R, EI_R, EI_T2, A64_COND_CS);
    /* dropped = (s << (n>=32 ? 0 : 32-n)) != 0; CA = s<0 && nzn && dropped */
    a64_emit_mov_imm32(b, EI_T2, 32U);
    a64_emit_sub_reg_w(b, false, EI_T2, EI_T2, EI_B, A64_SHIFT_LSL, 0U);
    a64_emit_csel_w(b, EI_T2, A64_ZR, EI_T2, A64_COND_CS);
    a64_emit_shift_reg_w(b, EI_B, EI_A, EI_T2, A64_SHIFT_LSL);
    ei_cmp_imm(b, EI_B, 0U);
    ei_cset(b, EI_B, A64_COND_NE);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_T, EI_A, A64_SHIFT_ASR, 31U, false, NULL);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    ei_xer_ca_reg(b, EI_B);
    ei_finish(b, EI_R, in->ra, in->rc);
    return PPC32_EMIT_NEXT;
}

/* rlwinm/rlwimi/rlwnm; mask folded at emit time (MB>ME wraps). */
static int ei_rotate(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t mask = ei_ppc_mask(in->bo, in->bi);

    ei_ld(b, EI_A, in->rs);
    if (in->op == PPC32_OP_RLWNM) {
        ei_ld(b, EI_B, in->rb); /* sh = rb & 31 via RORV(32 - sh) */
        a64_emit_mov_imm32(b, EI_T, 31U);
        a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_mov_imm32(b, EI_T, 32U);
        a64_emit_sub_reg_w(b, false, EI_T, EI_T, EI_B, A64_SHIFT_LSL, 0U);
        a64_emit_shift_reg_w(b, EI_R, EI_A, EI_T, A64_SHIFT_ROR);
    } else if (in->rb == 0U) {
        a64_emit_mov_w(b, EI_R, EI_A);
    } else {
        a64_emit_mov_imm32(b, EI_B, (32U - in->rb) & 31U);
        a64_emit_shift_reg_w(b, EI_R, EI_A, EI_B, A64_SHIFT_ROR);
    }
    a64_emit_mov_imm32(b, EI_T, mask);
    a64_emit_and_reg_w(b, false, EI_R, EI_R, EI_T, A64_SHIFT_LSL, 0U);
    if (in->op == PPC32_OP_RLWIMI) {
        ei_ld(b, EI_B, in->ra);
        a64_emit_bic_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
        a64_emit_orr_reg_w(b, EI_R, EI_R, EI_B, A64_SHIFT_LSL, 0U);
    }
    ei_finish(b, EI_R, in->ra, in->rc);
    return PPC32_EMIT_NEXT;
}

/* ---- branches, traps, sc, lwarx/stwcx., dcbz, dispatch ---- */

static uint32_t ei_branch_target(const ppc32_insn_t *in, uint32_t pc,
    uint32_t disp)
{
    uint32_t target;

    if (((in->raw >> 1U) & 1U) != 0U) {
        target = disp;
    } else {
        target = pc + disp;
    }
    return target & ~3U;
}

static int ei_b(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc)
{
    if ((in->raw & 1U) != 0U) {
        ei_store_lr(b, pc + 4U);
    }
    a64_emit_exit_branch(b, ei_branch_target(in, pc, (uint32_t)in->li));
    return PPC32_EMIT_END;
}

static int ei_bc(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc)
{
    uint32_t next = pc + 4U;
    size_t to_taken;

    ei_branch_taken(b, in->bo, in->bi);
    if ((in->raw & 1U) != 0U) {
        ei_store_lr(b, next);
    }
    to_taken = a64_emit_cbz_w_placeholder(b, true, EI_B);
    a64_emit_exit_branch(b, next);
    a64_patch_cbz_w(b, to_taken, b->count);
    a64_emit_exit_branch(b, ei_branch_target(in, pc, (uint32_t)in->bd));
    return PPC32_EMIT_END;
}

/* bclr/bcctr: runtime target in LR/CTR; LK stores next nip on both paths. */
static int ei_bcxr(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc,
    bool is_ctr)
{
    uint32_t next = pc + 4U;
    size_t to_taken;

    ei_ctx_ld(b, A64_TMP0, is_ctr ?
        (uint32_t)offsetof(ppc32_ctx_t, ctr) :
        (uint32_t)offsetof(ppc32_ctx_t, lr));
    if (is_ctr) {
        ei_branch_taken(b, (uint8_t)(in->bo | 4U), in->bi);
    } else {
        ei_branch_taken(b, in->bo, in->bi);
    }
    to_taken = a64_emit_cbz_w_placeholder(b, true, EI_B);
    if ((in->raw & 1U) != 0U) {
        ei_store_lr(b, next);
    }
    a64_emit_exit_branch(b, next);
    a64_patch_cbz_w(b, to_taken, b->count);
    if ((in->raw & 1U) != 0U) {
        ei_store_lr(b, next);
    }
    a64_emit_exit_branch_reg(b, A64_TMP0);
    return PPC32_EMIT_END;
}

/* tw/twi: one cmp, then one inverted-cond skip per TO bit over the inline
 * trap exit. Falls through (NEXT) when no trap fires. */
static int ei_trap(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc)
{
    uint32_t to = in->rt;
    size_t cont[5];
    unsigned ncont = 0U;
    uint32_t i;

    if (to == 0U) {
        return PPC32_EMIT_NEXT;
    }
    ei_ld(b, EI_A, in->ra);
    if (in->op == PPC32_OP_TWI) {
        a64_emit_mov_imm32(b, EI_B, (uint32_t)in->si);
    } else {
        ei_ld(b, EI_B, in->rb);
    }
    ei_cmp_reg(b, EI_A, EI_B);
    if ((to & 16U) != 0U) {
        cont[ncont++] = a64_emit_b_cond_placeholder(b, A64_COND_PL);
    }
    if ((to & 8U) != 0U) {
        cont[ncont++] = a64_emit_b_cond_placeholder(b, A64_COND_LE);
    }
    if ((to & 4U) != 0U) {
        cont[ncont++] = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    }
    if ((to & 2U) != 0U) {
        cont[ncont++] = a64_emit_b_cond_placeholder(b, A64_COND_CS);
    }
    if ((to & 1U) != 0U) {
        cont[ncont++] = a64_emit_b_cond_placeholder(b, A64_COND_LS);
    }
    a64_emit_exit_trap(b, pc);
    for (i = 0U; i < ncont; i++) {
        a64_patch_b_cond(b, cont[i], b->count);
    }
    return PPC32_EMIT_NEXT;
}

static int ei_sc(a64_buf_t *b, uint32_t pc)
{
    /* res_invalidate: clear the reservation and bump the epoch. */
    a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX,
        (uint32_t)offsetof(ppc32_ctx_t, res_valid));
    ei_epoch_bump(b);
    /* exit_arg carries r0 (nr); x15 carries the next nip. */
    ei_ld(b, EI_A, 0U);
    ei_ctx_st(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, exit_arg));
    a64_emit_mov_pc32(b, A64_TMP0, pc + 4U);
    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_SYSCALL, 0U);
    a64_emit_ret(b);
    return PPC32_EMIT_END;
}

/* lwarx via LDAXR (+REV): EA must be word-aligned else fallback. */
static int ei_lwarx(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc,
    ppc32_emit_ctx_t *e)
{
    size_t patch_mis;
    size_t patch_skip;
    size_t fb_idx;

    ei_ea_x(b, in->ra, in->rb);
    a64_emit_mov_imm32(b, EI_A, 3U);
    a64_emit_and_reg_w(b, true, A64_ZR, A64_ADDR, EI_A, A64_SHIFT_LSL, 0U);
    patch_mis = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, A64_ADDR);
    a64_emit_ldxr_w(b, EI_B, A64_TMP2);
    a64_emit_rev_w(b, EI_B, EI_B);
    ei_st(b, EI_B, in->rt);
    a64_emit_mov_imm32(b, EI_A, 0xFFFFFFFCU);
    a64_emit_and_reg_w(b, false, EI_A, A64_ADDR, EI_A, A64_SHIFT_LSL, 0U);
    ei_ctx_st(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, res_addr));
    ei_ctx_st(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, res_val));
    a64_emit_mov_imm32(b, EI_A, 1U);
    a64_emit_strb_imm_w(b, EI_A, A64_XCTX,
        (uint32_t)offsetof(ppc32_ctx_t, res_valid));
    patch_skip = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    fb_idx = b->count;
    ppc32_emit_fallback(e, pc);
    a64_patch_b_cond(b, patch_mis, fb_idx);
    a64_patch_b_cond(b, patch_skip, b->count);
    return PPC32_EMIT_NEXT;
}

/* stwcx. via STLXR: CR0 = [EQ=ok, SO]; reservation cleared either way. */
static int ei_stwcx(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc,
    ppc32_emit_ctx_t *e)
{
    size_t patch_mis;
    size_t patch_skip;
    size_t patch_noval;
    size_t patch_nomatch;
    size_t patch_done;
    size_t fb_idx;
    size_t fail_idx;

    ei_ea_x(b, in->ra, in->rb);
    a64_emit_mov_imm32(b, EI_A, 3U);
    a64_emit_and_reg_w(b, true, A64_ZR, A64_ADDR, EI_A, A64_SHIFT_LSL, 0U);
    patch_mis = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    a64_emit_ldrb_imm_w(b, EI_A, A64_XCTX,
        (uint32_t)offsetof(ppc32_ctx_t, res_valid));
    patch_noval = a64_emit_cbz_w_placeholder(b, false, EI_A);
    ei_ctx_ld(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, res_addr));
    a64_emit_mov_imm32(b, EI_T, 0xFFFFFFFCU);
    a64_emit_and_reg_w(b, false, EI_T, A64_ADDR, EI_T, A64_SHIFT_LSL, 0U);
    ei_cmp_reg(b, EI_T, EI_B);
    patch_nomatch = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    /* Match: exclusive store, then ok = (status == 0). */
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, A64_ADDR);
    ei_ld(b, EI_T, in->rs);
    a64_emit_rev_w(b, EI_T, EI_T);
    a64_emit_stxr_w(b, EI_T2, EI_T, A64_TMP2);
    ei_cmp_imm(b, EI_T2, 0U);
    ei_cset(b, EI_T, A64_COND_EQ);
    patch_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    /* Mismatch paths: ok = 0. */
    fail_idx = b->count;
    a64_emit_movz_w(b, EI_T, 0U, 0U);
    a64_patch_cbz_w(b, patch_noval, fail_idx);
    a64_patch_b_cond(b, patch_nomatch, fail_idx);
    /* Shared tail: clear reservation, bump epoch, set CR0. */
    a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX,
        (uint32_t)offsetof(ppc32_ctx_t, res_valid));
    ei_epoch_bump(b);
    a64_emit_shift_imm_w(b, EI_T, EI_T, A64_SHIFT_LSL, 29U, false, NULL);
    ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_shift_imm_w(b, EI_B, EI_X, A64_SHIFT_LSR, 3U, false, NULL);
    a64_emit_mov_imm32(b, EI_T2, 0x10000000U);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_T, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    ei_ctx_ld(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, cr));
    a64_emit_mov_imm32(b, EI_T2, 0xF0000000U);
    a64_emit_bic_reg_w(b, false, EI_B, EI_B, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    ei_ctx_st(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, cr));
    patch_skip = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    fb_idx = b->count;
    ppc32_emit_fallback(e, pc);
    a64_patch_b_cond(b, patch_mis, fb_idx);
    a64_patch_b_cond(b, patch_done, fail_idx + 1U); /* over movz to tail */
    a64_patch_b_cond(b, patch_skip, b->count);
    return PPC32_EMIT_NEXT;
}

static int ei_dcbz(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t k;

    ei_ea_x(b, in->ra, in->rb);
    a64_emit_mov_imm32(b, EI_A, 31U);
    a64_emit_bic_reg_w(b, false, A64_ADDR, A64_ADDR, EI_A, A64_SHIFT_LSL,
        0U);
    for (k = 0U; k < 8U; k++) {
        if (k != 0U) {
            a64_emit_add_imm_w(b, false, A64_ADDR, A64_ADDR, 4U, 0U);
        }
        a64_emit_guest_str_w(b, A64_ZR, A64_ADDR);
    }
    return PPC32_EMIT_NEXT;
}

int ppc32_emit_int(ppc32_emit_ctx_t *e, const ppc32_insn_t *insn, uint32_t pc)
{
    a64_buf_t *b = e->buf;

    if (insn == NULL) {
        return PPC32_EMIT_FALLBACK;
    }
    switch (insn->op) {
    case PPC32_OP_ADDI:
    case PPC32_OP_ADDIS:
        return ei_addi(b, insn);
    case PPC32_OP_ADDIC:
    case PPC32_OP_ADDIC_DOT:
    case PPC32_OP_SUBFIC:
        return ei_addic(b, insn);
    case PPC32_OP_MULLI:
        return ei_mulli(b, insn);
    case PPC32_OP_ANDI:
    case PPC32_OP_ANDIS:
    case PPC32_OP_ORI:
    case PPC32_OP_ORIS:
    case PPC32_OP_XORI:
    case PPC32_OP_XORIS:
        return ei_logical_imm(b, insn);
    case PPC32_OP_CMP:
    case PPC32_OP_CMPL:
    case PPC32_OP_CMPI:
    case PPC32_OP_CMPLI:
        return ei_cmp(b, insn);
    case PPC32_OP_ADD:
    case PPC32_OP_ADDC:
    case PPC32_OP_ADDE:
    case PPC32_OP_ADDME:
    case PPC32_OP_ADDZE:
    case PPC32_OP_SUBF:
    case PPC32_OP_SUBFC:
    case PPC32_OP_SUBFE:
    case PPC32_OP_SUBFME:
    case PPC32_OP_SUBFZE:
    case PPC32_OP_NEG:
        return ei_addsub_xo(b, insn);
    case PPC32_OP_MULLW:
        return ei_mullw(b, insn);
    case PPC32_OP_MULHW:
    case PPC32_OP_MULHWU:
        return ei_mulh(b, insn);
    case PPC32_OP_DIVW:
    case PPC32_OP_DIVWU:
        return ei_divw(b, insn);
    case PPC32_OP_AND:
    case PPC32_OP_ANDC:
    case PPC32_OP_OR:
    case PPC32_OP_ORC:
    case PPC32_OP_XOR:
    case PPC32_OP_NAND:
    case PPC32_OP_NOR:
    case PPC32_OP_EQV:
        return ei_logical_xo(b, insn);
    case PPC32_OP_EXTSB:
    case PPC32_OP_EXTSH:
    case PPC32_OP_CNTLZW:
        return ei_ext_clz(b, insn);
    case PPC32_OP_SLW:
    case PPC32_OP_SRW:
        return ei_shift_w(b, insn);
    case PPC32_OP_SRAW:
        return ei_sraw(b, insn, false);
    case PPC32_OP_SRAWI:
        return ei_sraw(b, insn, true);
    case PPC32_OP_RLWINM:
    case PPC32_OP_RLWIMI:
    case PPC32_OP_RLWNM:
        return ei_rotate(b, insn);
    case PPC32_OP_CR:
        return ei_cr_op(b, insn);
    case PPC32_OP_MCRF:
        return ei_mcrf(b, insn);
    case PPC32_OP_MCRXR:
        return ei_mcrxr(b, insn);
    case PPC32_OP_MFCR:
        ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
        ei_st(b, EI_A, insn->rt);
        return PPC32_EMIT_NEXT;
    case PPC32_OP_MTCRF:
        return ei_mtcrf(b, insn);
    case PPC32_OP_MFSPR:
    case PPC32_OP_MTSPR:
        return ei_spr(b, insn);
    case PPC32_OP_B:
        return ei_b(b, insn, pc);
    case PPC32_OP_BC:
        return ei_bc(b, insn, pc);
    case PPC32_OP_BCLR:
        return ei_bcxr(b, insn, pc, false);
    case PPC32_OP_BCCTR:
        return ei_bcxr(b, insn, pc, true);
    case PPC32_OP_LWZ:
    case PPC32_OP_LBZ:
    case PPC32_OP_STW:
    case PPC32_OP_STB:
    case PPC32_OP_LHZ:
    case PPC32_OP_LHA:
    case PPC32_OP_STH:
    case PPC32_OP_LWZU:
    case PPC32_OP_LBZU:
    case PPC32_OP_STWU:
    case PPC32_OP_STBU:
    case PPC32_OP_LHZU:
    case PPC32_OP_LHAU:
    case PPC32_OP_STHU:
        return ei_mem(b, insn, false);
    case PPC32_OP_LMW:
    case PPC32_OP_STMW:
        return ei_multi(b, insn, pc, e);
    case PPC32_OP_LSWI:
    case PPC32_OP_STSWI:
        return ei_string(b, insn);
    case PPC32_OP_LWZX:
    case PPC32_OP_LWZUX:
    case PPC32_OP_LBZX:
    case PPC32_OP_LBZUX:
    case PPC32_OP_STWX:
    case PPC32_OP_STWUX:
    case PPC32_OP_STBX:
    case PPC32_OP_STBUX:
    case PPC32_OP_LHZX:
    case PPC32_OP_LHZUX:
    case PPC32_OP_LHAX:
    case PPC32_OP_LHAUX:
    case PPC32_OP_STHX:
    case PPC32_OP_STHUX:
    case PPC32_OP_LWBRX:
    case PPC32_OP_LHBRX:
    case PPC32_OP_STWBRX:
    case PPC32_OP_STHBRX:
        return ei_mem(b, insn, true);
    case PPC32_OP_LWARX:
        return ei_lwarx(b, insn, pc, e);
    case PPC32_OP_STWCX:
        return ei_stwcx(b, insn, pc, e);
    case PPC32_OP_TWI:
    case PPC32_OP_TW:
        return ei_trap(b, insn, pc);
    case PPC32_OP_SC:
        return ei_sc(b, pc);
    case PPC32_OP_SYNC:
    case PPC32_OP_DCBT:
        return PPC32_EMIT_NEXT; /* cache-hint / barrier nop */
    case PPC32_OP_DCBZ:
        return ei_dcbz(b, insn);
    default:
        /* UNDEF, FPU/SPE families, MULHDU, LSWX/STSWX: no native
         * lowering; the runner single-steps via interp. */
        return PPC32_EMIT_FALLBACK;
    }
}
