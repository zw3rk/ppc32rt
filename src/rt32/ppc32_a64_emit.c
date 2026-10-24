/*
 * src/rt32/ppc32_a64_emit.c — Direct 32-bit AArch64 instruction encoder (part 1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from i686rt/src/rt32/rt32_a64_emit.c (itself vendored
 * from a32rt/src/a64_emit.c @ d84feb3, SPEC D13): mechanical renames,
 * retyped on ppc32_ctx_t. Fast-dispatch exits retargeted to the PPC32
 * layout (pending_signals, ras_top, ras, ibtc via offsetof(); identity
 * cache key / ppc32_ibtc_hash, no Thumb T bit). Part 1: moves, integer
 * ALU/logic/shifts/bitfields/multiply/divide, NZCV helpers, guest and
 * context memory accessors, guest FP memory accessors, FP converts.
 * Part 2 (ppc32_a64_emit2.c): crypto, exclusives/barriers, branches and
 * block exits, DSP helpers. Never read or write x18.
 */

#include "ppc32_a64_emit.h"


void a64_emit_movz_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw)
{
    a64_emit(b, 0x52800000U | ((hw & 1U) << 21) | ((uint32_t)imm16 << 5) | (rd & 31U));
}

void a64_emit_movk_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw)
{
    a64_emit(b, 0x72800000U | ((hw & 1U) << 21) | ((uint32_t)imm16 << 5) | (rd & 31U));
}

void a64_emit_mov_imm32(a64_buf_t *b, unsigned rd, uint32_t val)
{
    uint16_t lo = (uint16_t)(val & 0xFFFFU);
    uint16_t hi = (uint16_t)(val >> 16);
    if (lo == 0U && hi != 0U) {
        a64_emit_movz_w(b, rd, hi, 1U);
        return;
    }
    a64_emit_movz_w(b, rd, lo, 0U);
    if (hi != 0U) {
        a64_emit_movk_w(b, rd, hi, 1U);
    }
}

void a64_emit_mov_pc32(a64_buf_t *b, unsigned rd, uint32_t pc_val)
{
    /* Emit high halfword first (MOVZ hw=1) followed by low halfword (MOVK hw=0).
     * Normal a64_emit_mov_imm32 never emits MOVK hw=0, making guest-PC immediates
     * 100% self-identifying in AOT code streams for base-address relocation. */
    a64_emit_movz_w(b, rd, (uint16_t)(pc_val >> 16U), 1U);
    a64_emit_movk_w(b, rd, (uint16_t)(pc_val & 0xFFFFU), 0U);
}

void a64_emit_mov_w(a64_buf_t *b, unsigned rd, unsigned rm)
{
    if (rd == rm) {
        return;
    }
    a64_emit_orr_reg_w(b, rd, A64_ZR, rm, A64_SHIFT_LSL, 0U);
}

void a64_emit_mvn_reg_w(a64_buf_t *b, unsigned rd, unsigned rm, unsigned shift, unsigned amount)
{
    a64_emit_orn_reg_w(b, rd, A64_ZR, rm, shift, amount);
}

void a64_emit_add_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn,
                        uint16_t imm12, unsigned sh)
{
    uint32_t s = set_flags ? (1U << 29) : 0U;
    a64_emit(b, 0x11000000U | s | ((sh & 1U) << 22) | (((uint32_t)imm12 & 0xFFFU) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_sub_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn,
                        uint16_t imm12, unsigned sh)
{
    uint32_t s = set_flags ? (1U << 29) : 0U;
    a64_emit(b, 0x51000000U | s | ((sh & 1U) << 22) | (((uint32_t)imm12 & 0xFFFU) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_add_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    uint32_t s = set_flags ? (1U << 29) : 0U;
    a64_emit(b, 0x0B000000U | s | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_sub_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    uint32_t s = set_flags ? (1U << 29) : 0U;
    a64_emit(b, 0x4B000000U | s | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_adc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t s = set_flags ? (1U << 29) : 0U;
    a64_emit(b, 0x1A000000U | s | ((rm & 31U) << 16) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_sbc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm)
{
    uint32_t s = set_flags ? (1U << 29) : 0U;
    a64_emit(b, 0x5A000000U | s | ((rm & 31U) << 16) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_add_uxtw_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned rm_w)
{
    /* ADD Xd, Xn, Wm, UXTW #0 */
    a64_emit(b, 0x8B204000U | ((rm_w & 31U) << 16) | ((rn_x & 31U) << 5) | (rd_x & 31U));
}

void a64_emit_and_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    uint32_t base = set_flags ? 0x6A000000U : 0x0A000000U;
    a64_emit(b, base | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_bic_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    uint32_t base = set_flags ? 0x6A200000U : 0x0A200000U;
    a64_emit(b, base | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_orr_reg_w(a64_buf_t *b, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    a64_emit(b, 0x2A000000U | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_orn_reg_w(a64_buf_t *b, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    a64_emit(b, 0x2A200000U | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_eor_reg_w(a64_buf_t *b, unsigned rd, unsigned rn,
                        unsigned rm, unsigned shift, unsigned amount)
{
    a64_emit(b, 0x4A000000U | ((shift & 3U) << 22) | ((rm & 31U) << 16) |
                    ((amount & 31U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_shift_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift_type)
{
    a64_emit(b, 0x1AC02000U | ((rm & 31U) << 16) | ((shift_type & 3U) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_arm_shift_reg_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned src_s,
                              unsigned shift_type, bool want_carry)
{
    /* amt = src_s & 0xFF in A64_ADDR (0..255) */
    a64_emit_ubfm_w(b, A64_ADDR, src_s, 0U, 7U);

    if (want_carry) {
        /* am1 = amt - 1 in A64_TMP3 (0..254 when amt > 0; 0xFFFFFFFF when amt == 0) */
        a64_emit_sub_imm_w(b, false, A64_TMP3, A64_ADDR, 1U, 0U);
        if (shift_type == A64_SHIFT_LSL || shift_type == A64_SHIFT_LSR) {
            unsigned bit = (shift_type == A64_SHIFT_LSL) ? 31U : 0U;
            a64_emit_shift_reg_w(b, A64_TMP2, src_m, A64_TMP3, shift_type);
            a64_emit_ubfm_w(b, A64_TMP2, A64_TMP2, bit, bit);
            a64_emit_sub_reg_w(b, false, A64_TMP3, A64_ZR, A64_TMP3, A64_SHIFT_LSR, 5U);
            a64_emit_bic_reg_w(b, false, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSR, 31U);
        } else if (shift_type == A64_SHIFT_ASR) {
            a64_emit_sub_reg_w(b, false, A64_TMP2, A64_ZR, A64_TMP3, A64_SHIFT_LSR, 5U);
            a64_emit_orr_reg_w(b, A64_TMP3, A64_TMP3, A64_TMP2, A64_SHIFT_ASR, 31U);
            a64_emit_shift_reg_w(b, A64_TMP2, src_m, A64_TMP3, A64_SHIFT_LSR);
            a64_emit_ubfm_w(b, A64_TMP2, A64_TMP2, 0U, 0U);
        } else {
            a64_emit_shift_reg_w(b, A64_TMP2, src_m, A64_TMP3, A64_SHIFT_LSR);
            a64_emit_ubfm_w(b, A64_TMP2, A64_TMP2, 0U, 0U);
        }
        /* When amt == 0, carry_out = old_C (preserving NZCV and A64_TMP0) */
        a64_emit_mrs_nzcv(b, A64_TMP3);
        a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 29U, 29U);
        a64_emit_bfm_w(b, A64_TMP2, A64_TMP3, 31U, 0U);
        a64_emit_sub_imm_w(b, false, A64_TMP3, A64_ADDR, 1U, 0U);
        a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 31U, 31U);
        a64_emit_shift_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSR);
        a64_emit_ubfm_w(b, A64_TMP2, A64_TMP2, 0U, 0U);
    }

    if (shift_type == A64_SHIFT_LSL || shift_type == A64_SHIFT_LSR) {
        a64_emit_sub_reg_w(b, false, A64_TMP3, A64_ZR, A64_ADDR, A64_SHIFT_LSR, 5U);
        a64_emit_shift_reg_w(b, dst_w, src_m, A64_ADDR, shift_type);
        a64_emit_bic_reg_w(b, false, dst_w, dst_w, A64_TMP3, A64_SHIFT_ASR, 31U);
    } else if (shift_type == A64_SHIFT_ASR) {
        a64_emit_sub_reg_w(b, false, A64_TMP3, A64_ZR, A64_ADDR, A64_SHIFT_LSR, 5U);
        a64_emit_orr_reg_w(b, A64_TMP3, A64_ADDR, A64_TMP3, A64_SHIFT_ASR, 31U);
        a64_emit_shift_reg_w(b, dst_w, src_m, A64_TMP3, A64_SHIFT_ASR);
    } else {
        a64_emit_shift_reg_w(b, dst_w, src_m, A64_ADDR, A64_SHIFT_ROR);
    }
}

void a64_emit_shift_imm_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned shift_type,
                          unsigned imm5, bool want_carry, unsigned *out_carry_reg)
{
    if (out_carry_reg) {
        *out_carry_reg = A64_ZR;
    }
    if (shift_type == A64_SHIFT_LSL) {
        if (imm5 == 0U) {
            a64_emit_mov_w(b, dst_w, src_m);
        } else {
            if (want_carry && out_carry_reg) {
                a64_emit_ubfm_w(b, A64_TMP2, src_m, 32U - imm5, 32U - imm5);
                *out_carry_reg = A64_TMP2;
            }
            a64_emit_ubfm_w(b, dst_w, src_m, (32U - imm5) & 31U, 31U - imm5);
        }
    } else if (shift_type == A64_SHIFT_LSR) {
        if (imm5 == 0U) {
            /* LSR #0 (immediate) is identity: UBFM #0,31. */
            if (want_carry && out_carry_reg) {
                a64_emit_ubfm_w(b, A64_TMP2, src_m, 31U, 31U);
                *out_carry_reg = A64_TMP2;
            }
            a64_emit_mov_w(b, dst_w, src_m);
        } else {
            if (want_carry && out_carry_reg) {
                a64_emit_ubfm_w(b, A64_TMP2, src_m, imm5 - 1U, imm5 - 1U);
                *out_carry_reg = A64_TMP2;
            }
            a64_emit_ubfm_w(b, dst_w, src_m, imm5, 31U);
        }
    } else if (shift_type == A64_SHIFT_ASR) {
        unsigned amt = (imm5 == 0U) ? 31U : imm5;
        if (want_carry && out_carry_reg) {
            unsigned cbit = (imm5 == 0U) ? 31U : (imm5 - 1U);
            a64_emit_ubfm_w(b, A64_TMP2, src_m, cbit, cbit);
            *out_carry_reg = A64_TMP2;
        }
        a64_emit_sbfm_w(b, dst_w, src_m, amt, 31U);
    } else {
        if (imm5 == 0U) {
            /* RRX: (C << 31) | (src_m >> 1), carry_out = src_m[0] */
            if (want_carry && out_carry_reg) {
                a64_emit_ubfm_w(b, A64_TMP2, src_m, 0U, 0U);
                *out_carry_reg = A64_TMP2;
            }
            a64_emit_mrs_nzcv(b, A64_TMP3);
            a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 29U, 29U);
            a64_emit_ubfm_w(b, dst_w, src_m, 1U, 31U);
            a64_emit_orr_reg_w(b, dst_w, dst_w, A64_TMP3, A64_SHIFT_LSL, 31U);
        } else {
            if (want_carry && out_carry_reg) {
                a64_emit_ubfm_w(b, A64_TMP2, src_m, imm5 - 1U, imm5 - 1U);
                *out_carry_reg = A64_TMP2;
            }
            a64_emit(b, 0x13800000U | ((src_m & 31U) << 16) | ((imm5 & 31U) << 10) |
                            ((src_m & 31U) << 5) | (dst_w & 31U));
        }
    }
}

void a64_emit_ubfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms)
{
    a64_emit(b, 0x53000000U | ((immr & 31U) << 16) | ((imms & 31U) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_sbfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms)
{
    a64_emit(b, 0x13000000U | ((immr & 31U) << 16) | ((imms & 31U) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_bfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms)
{
    a64_emit(b, 0x33000000U | ((immr & 31U) << 16) | ((imms & 31U) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}


void a64_emit_ubfx_x_to_w(a64_buf_t *b, unsigned rd_w, unsigned rn_x, unsigned lsb, unsigned width)
{
    /* 64-bit UBFM Xd, Xn, #lsb, #(lsb + width - 1) */
    unsigned immr = lsb & 63U;
    unsigned imms = (lsb + width - 1U) & 63U;
    a64_emit(b, 0xD3400000U | (immr << 16) | (imms << 10) | ((rn_x & 31U) << 5) | (rd_w & 31U));
}

void a64_emit_bfi_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned lsb, unsigned width)
{
    /* 64-bit BFM Xd, Xn, #((64 - lsb) & 63), #(width - 1) */
    unsigned immr = (64U - lsb) & 63U;
    unsigned imms = (width - 1U) & 63U;
    a64_emit(b, 0xB3400000U | (immr << 16) | (imms << 10) | ((rn_x & 31U) << 5) | (rd_x & 31U));
}

void a64_emit_clz_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x5AC01000U | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_rbit_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x5AC00000U | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_rev_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x5AC00800U | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_rev16_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x5AC00400U | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_madd_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra)
{
    a64_emit(b, 0x1B000000U | ((rm & 31U) << 16) | ((ra & 31U) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_msub_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra)
{
    a64_emit(b, 0x1B008000U | ((rm & 31U) << 16) | ((ra & 31U) << 10) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_umaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x)
{
    a64_emit(b, 0x9BA00000U | ((rm_w & 31U) << 16) | ((ra_x & 31U) << 10) |
                    ((rn_w & 31U) << 5) | (rd_x & 31U));
}

void a64_emit_smaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x)
{
    a64_emit(b, 0x9B200000U | ((rm_w & 31U) << 16) | ((ra_x & 31U) << 10) |
                    ((rn_w & 31U) << 5) | (rd_x & 31U));
}

void a64_emit_smsubl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x)
{
    a64_emit(b, 0x9B208000U | ((rm_w & 31U) << 16) | ((ra_x & 31U) << 10) |
                    ((rn_w & 31U) << 5) | (rd_x & 31U));
}

void a64_emit_udiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x1AC00800U | ((rm & 31U) << 16) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_sdiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x1AC00C00U | ((rm & 31U) << 16) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_crc32_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned sz, unsigned c_bit)
{
    a64_emit(b, 0x1AC04000U | ((rm & 31U) << 16) | ((c_bit & 1U) << 12) |
                    ((sz & 3U) << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_csel_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond)
{
    a64_emit(b, 0x1A800000U | ((rm & 31U) << 16) | ((cond & 15U) << 12) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

void a64_emit_csneg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond)
{
    a64_emit(b, 0x5A800400U | ((rm & 31U) << 16) | ((cond & 15U) << 12) |
                    ((rn & 31U) << 5) | (rd & 31U));
}

/* a64_emit_set_q_cond() was dropped: the ARM CPSR Q saturation flag
 * has no PowerPC counterpart. */

void a64_emit_mrs_nzcv(a64_buf_t *b, unsigned rt)
{
    a64_emit(b, 0xD53B4200U | (rt & 31U));
}

void a64_emit_msr_nzcv(a64_buf_t *b, unsigned rt)
{
    a64_emit(b, 0xD51B4200U | (rt & 31U));
}

/*
 * Logical flag helpers:
 *   Guest logical ops with S=1 set N and Z from the 32-bit result,
 *   optionally update C from the barrel-shifter carry-out, and leave V unchanged.
 */
void a64_emit_update_nz_keep_cv(a64_buf_t *b, unsigned res_reg)
{
    /* Save old C and V in TMP3[29:28], compute new N and Z via ANDS wzr, res_reg, res_reg */
    a64_emit_mrs_nzcv(b, A64_TMP3);
    a64_emit_and_reg_w(b, true, A64_ZR, res_reg, res_reg, A64_SHIFT_LSL, 0U);
    a64_emit_mrs_nzcv(b, A64_TMP2);
    /* Merge old C and V (bits 29:28 of TMP3) into TMP2 (which has C=0, V=0) */
    a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 28U, 29U); /* TMP3 = old_CV[1:0] */
    a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSL, 28U);
    a64_emit_msr_nzcv(b, A64_TMP2);
}

void a64_emit_update_nzc_keep_v_imm(a64_buf_t *b, unsigned res_reg, unsigned carry_bit)
{
    a64_emit_mrs_nzcv(b, A64_TMP3);
    a64_emit_and_reg_w(b, true, A64_ZR, res_reg, res_reg, A64_SHIFT_LSL, 0U);
    a64_emit_mrs_nzcv(b, A64_TMP2);
    /* Keep old V (bit 28 of TMP3) */
    a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 28U, 28U);
    a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSL, 28U);
    if (carry_bit & 1U) {
        /* Set C (bit 29) */
        a64_emit_movz_w(b, A64_TMP3, 0x2000U, 1U);
        a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSL, 0U);
    }
    a64_emit_msr_nzcv(b, A64_TMP2);
}

void a64_emit_update_nzc_keep_v_reg(a64_buf_t *b, unsigned res_reg, unsigned carry_reg)
{
    a64_emit_mrs_nzcv(b, A64_TMP3);
    a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 28U, 28U);
    a64_emit_bfm_w(b, A64_TMP3, carry_reg, 31U, 0U);
    a64_emit_and_reg_w(b, true, A64_ZR, res_reg, res_reg, A64_SHIFT_LSL, 0U);
    a64_emit_mrs_nzcv(b, A64_TMP2);
    a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSL, 28U);
    a64_emit_msr_nzcv(b, A64_TMP2);
}

void a64_emit_logical_flags(a64_buf_t *b, unsigned res_reg, bool has_imm_carry,
                            unsigned imm_carry, unsigned shift_carry_reg)
{
    if (has_imm_carry) {
        a64_emit_update_nzc_keep_v_imm(b, res_reg, imm_carry);
    } else if (shift_carry_reg != A64_ZR) {
        a64_emit_update_nzc_keep_v_reg(b, res_reg, shift_carry_reg);
    } else {
        a64_emit_update_nz_keep_cv(b, res_reg);
    }
}

/* No guest-FP host-register cache: guest FP state lives in ctx->fpr[]
 * (PPC32_CTX_FPR_OFFSET); the DBT spills/fills A64 S/D registers around
 * each block. */

static void emit_guest_mem(a64_buf_t *b, uint32_t opc, unsigned rt, unsigned addr_w)
{
    a64_emit(b, opc | ((addr_w & 31U) << 16) | (A64_XG << 5) | (rt & 31U));
}

/* Guest memory accesses: [xG, wAddr, uxtw #0] */
void a64_emit_guest_ldr_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0xB8604800U, rt, addr_w);
}

void a64_emit_guest_str_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0xB8204800U, rt, addr_w);
}

void a64_emit_guest_ldrd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w)
{
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, addr_w);
    if (rt != rt2) {
        a64_emit(b, 0x29400000U | ((rt2 & 31U) << 10) | (A64_TMP2 << 5) | (rt & 31U));
    } else {
        a64_emit(b, 0xB9400000U | (1U << 10) | (A64_TMP2 << 5) | (rt & 31U));
    }
}

void a64_emit_guest_strd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w)
{
    a64_emit_add_uxtw_x(b, A64_TMP2, A64_XG, addr_w);
    a64_emit(b, 0x29000000U | ((rt2 & 31U) << 10) | (A64_TMP2 << 5) | (rt & 31U));
}

void a64_emit_guest_ldrb_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0x38604800U, rt, addr_w);
}

void a64_emit_guest_ldrsb_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0x38A04800U, rt, addr_w);
}

void a64_emit_guest_strb_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0x38204800U, rt, addr_w);
}

void a64_emit_guest_ldrh_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0x78604800U, rt, addr_w);
}

void a64_emit_guest_ldrsh_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0x78A04800U, rt, addr_w);
}

void a64_emit_guest_strh_w(a64_buf_t *b, unsigned rt, unsigned addr_w)
{
    emit_guest_mem(b, 0x78204800U, rt, addr_w);
}

static void emit_ctx_mem_imm(a64_buf_t *b, uint32_t opc, unsigned shift, bool is_store,
                             unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    (void)is_store;
    uint32_t uimm12 = (byte_offset >> shift) & 0xFFFU;
    a64_emit(b, opc | (uimm12 << 10) | ((rn_x & 31U) << 5) | (rt & 31U));
}

/* Host unsigned-offset loads/stores */
void a64_emit_ldrb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    emit_ctx_mem_imm(b, 0x39400000U, 0U, false, rt, rn_x, byte_offset);
}

void a64_emit_strb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    emit_ctx_mem_imm(b, 0x39000000U, 0U, true, rt, rn_x, byte_offset);
}

void a64_emit_ldrh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    emit_ctx_mem_imm(b, 0x79400000U, 1U, false, rt, rn_x, byte_offset);
}

void a64_emit_strh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    emit_ctx_mem_imm(b, 0x79000000U, 1U, true, rt, rn_x, byte_offset);
}

void a64_emit_ldr_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    emit_ctx_mem_imm(b, 0xB9400000U, 2U, false, rt, rn_x, byte_offset);
}

void a64_emit_str_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset)
{
    emit_ctx_mem_imm(b, 0xB9000000U, 2U, true, rt, rn_x, byte_offset);
}

/* Guest-FP context accessors (vfp_ldr_ctx/vfp_str_ctx and
 * a64_emit_ldr/str_{s,d,q}_ctx) were dropped with the VFP register cache. */

void a64_emit_guest_ldr_s(a64_buf_t *b, unsigned vt, unsigned addr_w)
{
    emit_guest_mem(b, 0xBC604800U, vt, addr_w);
}

void a64_emit_guest_str_s(a64_buf_t *b, unsigned vt, unsigned addr_w)
{
    emit_guest_mem(b, 0xBC204800U, vt, addr_w);
}

void a64_emit_guest_ldr_d(a64_buf_t *b, unsigned vt, unsigned addr_w)
{
    emit_guest_mem(b, 0xFC604800U, vt, addr_w);
}

void a64_emit_guest_str_d(a64_buf_t *b, unsigned vt, unsigned addr_w)
{
    emit_guest_mem(b, 0xFC204800U, vt, addr_w);
}

/* Scalar FP instructions */
void a64_emit_fmov_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w)
{
    a64_emit(b, 0x1E270000U | ((rn_w & 31U) << 5) | (vd & 31U));
}

void a64_emit_fmov_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn)
{
    a64_emit(b, 0x1E260000U | ((vn & 31U) << 5) | (rd_w & 31U));
}

void a64_emit_fcvt_s_to_d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E22C000U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_fcvt_d_to_s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E624000U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_fcvtzs_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn)
{
    a64_emit(b, 0x1E380000U | ((vn & 31U) << 5) | (rd_w & 31U));
}

void a64_emit_fcvtzu_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn)
{
    a64_emit(b, 0x1E390000U | ((vn & 31U) << 5) | (rd_w & 31U));
}

void a64_emit_fcvtzs_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn)
{
    a64_emit(b, 0x1E780000U | ((vn & 31U) << 5) | (rd_w & 31U));
}

void a64_emit_fcvtzu_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn)
{
    a64_emit(b, 0x1E790000U | ((vn & 31U) << 5) | (rd_w & 31U));
}

void a64_emit_scvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w)
{
    a64_emit(b, 0x1E220000U | ((rn_w & 31U) << 5) | (vd & 31U));
}

void a64_emit_ucvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w)
{
    a64_emit(b, 0x1E230000U | ((rn_w & 31U) << 5) | (vd & 31U));
}

void a64_emit_scvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w)
{
    a64_emit(b, 0x1E620000U | ((rn_w & 31U) << 5) | (vd & 31U));
}

void a64_emit_ucvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w)
{
    a64_emit(b, 0x1E630000U | ((rn_w & 31U) << 5) | (vd & 31U));
}
