/*
 * src/dbt/emit_int.h — AArch64 integer instruction emitter API (Phase 2, lane L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lower every Phase-1 Book I integer instruction (src/interp/decode.h)
 * to AArch64 words via the frozen rt32 encoder (src/rt32/ppc32_a64_emit.h).
 * Consumed by the L2b block translator: L2b decodes each guest word with
 * ppc_decode, calls ppc32_emit_int once per instruction with the guest
 * PC, and ends the block when the result is PPC32_EMIT_END or
 * PPC32_EMIT_FALLBACK.
 *
 * NOTE (L2b integration assumption): src/dbt/dbt.h does not exist yet on
 * this lane's base. L2b should reuse this exact callback signature
 * instead of declaring a parallel one:
 *   int (*emit_cb)(ppc32_emit_ctx_t *, const ppc32_insn_t *, uint32_t);
 * returning PPC32_EMIT_NEXT / PPC32_EMIT_END / PPC32_EMIT_FALLBACK.
 * ppc32_emit_fallback emits the interp-single-step exit L2b needs for
 * the FALLBACK case (a64_emit_exit_undef at that PC).
 *
 * Design rules (mirroring src/interp/interp.c exactly):
 * - Big-endian guest: every multi-byte guest access gets an explicit
 *   REV (32-bit) or REV16 (16-bit) fix-up; *brx forms skip it.
 * - Guest addresses wrap in 32-bit W registers before adding xG: all
 *   memory traffic goes through [x20, w22, uxtw] (A64_ADDR == 22).
 * - Guest GPRs live in ctx->gpr[] (SPEC 2.1); no guest state is kept
 *   live in host registers across instructions. Within one instruction,
 *   w9..w14 are operand/flag temporaries. w0..w7 are never touched
 *   (L2b's guest-live window), x18 is never touched, and x19 (xCtx) /
 *   x20 (xG) keep their frozen roles.
 * - XER (SO/OV/CA) and CR0/CR-field updates mirror interp.c, including
 *   the sraw dropped-bit CA rule and MB>ME wrap masks.
 * - Anything without a native lowering (FPU/SPE families, MULHDU,
 *   LSWX/STSWX, privileged SPRs, cmp/cmpl L=1, ra==0 update forms)
 *   returns PPC32_EMIT_FALLBACK: L2b emits ppc32_emit_fallback and lets
 *   interp_step handle (or fault on) that word. Unknown ops are never
 *   miscompiled into native sequences.
 *
 * The static-inline emission helpers below live in the header (same
 * pattern as src/interp/interp.h): the per-op emitters in emit_int.c
 * share them, and L2b's future dbt.c may reuse them for block prologues.
 * Like interp.h, everything row reads ctx only for constant folding and
 * never side-effects guest state at emit time.
 */

#ifndef PPC32RT_DBT_EMIT_INT_H
#define PPC32RT_DBT_EMIT_INT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"
#include "interp/decode.h"
#include "ppc32_a64_emit.h"

/* Per-instruction emission outcome for the L2b block translator. */
enum {
    PPC32_EMIT_NEXT = 0,    /* native code emitted, block continues */
    PPC32_EMIT_END = 1,     /* block-ending exit emitted (branch/sc/trap) */
    PPC32_EMIT_FALLBACK = -1 /* no native lowering; L2b emits fallback */
};

/* Emission context. buf/ctx are borrowed, never owned; ctx is read for
 * constant folding only, never side-effected at emit time. */
typedef struct ppc32_emit_ctx {
    a64_buf_t  *buf;
    ppc32_ctx_t *ctx;
} ppc32_emit_ctx_t;

void ppc32_emit_begin(ppc32_emit_ctx_t *e, ppc32_ctx_t *ctx, a64_buf_t *buf);

/* Lower one decoded instruction at guest PC `pc`. Returns
 * PPC32_EMIT_NEXT / PPC32_EMIT_END / PPC32_EMIT_FALLBACK (see above).
 * May set buf->overflow on very long unrolled sequences (lmw/stmw from
 * r0, full-width lswi/stswi); L2b must treat overflow like FALLBACK. */
int ppc32_emit_int(ppc32_emit_ctx_t *e, const ppc32_insn_t *insn, uint32_t pc);

/* Emit the fallback exit for `pc` (UNDEF reason; the runner single-steps
 * that word with interp_step and resumes). Used by L2b on FALLBACK and
 * by emit_int itself for runtime-detected fallback paths. */
void ppc32_emit_fallback(ppc32_emit_ctx_t *e, uint32_t pc);

/* XER bit positions (E02): SO=0x80000000, OV=0x40000000, CA=0x20000000. */
#define EI_XER_SO 0x80000000U
#define EI_XER_OV 0x40000000U
#define EI_XER_CA 0x20000000U

/* Scratch map inside one instruction (nothing survives it): w9..w14
 * hold operands/flags; w22 is the guest effective address; w15/w16 are
 * transient (never live across a helper that uses A64_TMP* internally).
 * w0..w7, x18, x19, x20 are never touched. */
#define EI_A  9U
#define EI_B  10U
#define EI_R  11U
#define EI_T  12U
#define EI_T2 13U
#define EI_X  14U /* cached XER / CR-field base */

/* ---- tiny helpers ---- */

static inline uint32_t ei_gpr_off(unsigned r)
{
    return (uint32_t)r * 4U;
}

static inline void ei_ld(a64_buf_t *b, unsigned wd, unsigned rs)
{
    a64_emit_ldr_imm_w(b, wd, A64_XCTX, ei_gpr_off(rs));
}

static inline void ei_st(a64_buf_t *b, unsigned ws, unsigned rd)
{
    a64_emit_str_imm_w(b, ws, A64_XCTX, ei_gpr_off(rd));
}

static inline void ei_ctx_ld(a64_buf_t *b, unsigned wd, uint32_t off)
{
    a64_emit_ldr_imm_w(b, wd, A64_XCTX, off);
}

static inline void ei_ctx_st(a64_buf_t *b, unsigned ws, uint32_t off)
{
    a64_emit_str_imm_w(b, ws, A64_XCTX, off);
}

/* CSET Wd, cond = CSINC Wd, WZR, WZR, invert(cond): one word, no flags. */
static inline void ei_cset(a64_buf_t *b, unsigned rd, unsigned cond)
{
    a64_emit(b, 0x1A800400U | (31U << 16) | ((((cond) ^ 1U) & 15U) << 12) |
        (31U << 5) | ((rd) & 31U));
}

static inline void ei_cmp_reg(a64_buf_t *b, unsigned a, unsigned c)
{
    a64_emit_sub_reg_w(b, true, A64_ZR, a, c, A64_SHIFT_LSL, 0U);
}

static inline void ei_cmp_imm(a64_buf_t *b, unsigned rn, uint16_t imm12)
{
    a64_emit_sub_imm_w(b, true, A64_ZR, rn, imm12, 0U);
}

/* LSR X10, X9, #32 as one word (mulh upper-half extract). */
static inline void ei_lsr_x32(a64_buf_t *b)
{
    a64_emit(b, 0xD3400000U | (1U << 22) | (32U << 16) | (63U << 10) |
        (9U << 5) | 10U);
}

/* Bump ctx->reservation_epoch (stwcx./sc path; res_valid cleared by the
 * caller). Raw 64-bit words mirroring the exit sequences in
 * ppc32_a64_emit2.c; x9/x21 are dead at every call site. */
static inline void ei_epoch_bump(a64_buf_t *b)
{
    uint32_t off = (uint32_t)offsetof(ppc32_ctx_t, reservation_epoch);

    a64_emit_mov_imm32(b, A64_TMP3, off);
    a64_emit(b, 0x8B000000U | (A64_TMP3 << 16) | (A64_XCTX << 5) | A64_TMP3);
    a64_emit(b, 0xF9400000U | (A64_TMP3 << 5) | 9U);
    a64_emit(b, 0x91000400U | (9U << 5) | 9U);
    a64_emit(b, 0xF9000000U | (A64_TMP3 << 5) | 9U);
}

/* CR0 = [LT,GT,EQ from signed result, SO copied live from XER.SO].
 * res holds the ALU result; xer must be preloaded into EI_X.
 * Clobbers w9..w13; res may alias w9..w14. */
static inline void ei_set_cr0(a64_buf_t *b, unsigned res, unsigned xer)
{
    a64_emit_mov_w(b, EI_T2, res);
    ei_cmp_imm(b, EI_T2, 0U);
    ei_cset(b, EI_A, A64_COND_MI);
    ei_cset(b, EI_B, A64_COND_NE);
    a64_emit_bic_reg_w(b, false, EI_R, EI_B, EI_A, A64_SHIFT_LSL, 0U);
    ei_cset(b, EI_T, A64_COND_EQ);
    a64_emit_shift_imm_w(b, EI_A, EI_A, A64_SHIFT_LSL, 31U, false, NULL);
    a64_emit_shift_imm_w(b, EI_R, EI_R, A64_SHIFT_LSL, 30U, false, NULL);
    a64_emit_shift_imm_w(b, EI_T, EI_T, A64_SHIFT_LSL, 29U, false, NULL);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_R, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_T, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_B, xer, A64_SHIFT_LSR, 3U, false, NULL);
    a64_emit_mov_imm32(b, EI_R, 0x10000000U);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_R, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    ei_ctx_ld(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, cr));
    a64_emit_mov_imm32(b, EI_R, 0xF0000000U);
    a64_emit_bic_reg_w(b, false, EI_B, EI_B, EI_R, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_B, EI_B, EI_A, A64_SHIFT_LSL, 0U);
    ei_ctx_st(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, cr));
}

/* CR field bf = [LT,GT,EQ from an already-executed cmp, SO from XER].
 * ltcond/gtcond pick signed (LT/GT) or unsigned (CC/HI) comparison. */
static inline void ei_set_crf(a64_buf_t *b, uint32_t bf, unsigned ltcond,
    unsigned gtcond, unsigned xer)
{
    uint32_t s = (7U - (bf & 7U)) * 4U;

    ei_cset(b, EI_A, ltcond);
    ei_cset(b, EI_B, gtcond);
    ei_cset(b, EI_R, A64_COND_EQ);
    a64_emit_shift_imm_w(b, EI_A, EI_A, A64_SHIFT_LSL, s + 3U, false, NULL);
    a64_emit_shift_imm_w(b, EI_B, EI_B, A64_SHIFT_LSL, s + 2U, false, NULL);
    a64_emit_shift_imm_w(b, EI_R, EI_R, A64_SHIFT_LSL, s + 1U, false, NULL);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_R, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_B, xer, A64_SHIFT_LSR, 31U, false, NULL);
    a64_emit_shift_imm_w(b, EI_B, EI_B, A64_SHIFT_LSL, s, false, NULL);
    a64_emit_orr_reg_w(b, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    ei_ctx_ld(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, cr));
    a64_emit_mov_imm32(b, EI_R, 0xFU << s);
    a64_emit_bic_reg_w(b, false, EI_B, EI_B, EI_R, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_B, EI_B, EI_A, A64_SHIFT_LSL, 0U);
    ei_ctx_st(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, cr));
}

/* XER.CA = A64 carry flag (C) after adds/subs. */
static inline void ei_xer_ca_from_c(a64_buf_t *b)
{
    ei_cset(b, EI_A, A64_COND_CS);
    ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_mov_imm32(b, EI_B, EI_XER_CA);
    a64_emit_bic_reg_w(b, false, EI_X, EI_X, EI_B, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_X, EI_X, EI_A, A64_SHIFT_LSL, 29U);
    ei_ctx_st(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
}

/* XER.CA = 0/1 value already in `bit`. The mask must NOT live in EI_B:
 * every caller passes bit==EI_B, so loading the mask there destroys the
 * value (RC2: srawi CA stuck at 0). TMP3 (x21) is scratch (see
 * ei_epoch_bump) and safe here. */
static inline void ei_xer_ca_reg(a64_buf_t *b, unsigned bit)
{
    ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_mov_imm32(b, A64_TMP3, EI_XER_CA);
    a64_emit_bic_reg_w(b, false, EI_X, EI_X, A64_TMP3, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_X, EI_X, bit, A64_SHIFT_LSL, 29U);
    ei_ctx_st(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
}

/* XER = (XER & ~OV) | (ov ? OV|SO : 0): OV cleared/set, SO sticky-set. */
static inline void ei_xer_ov_reg(a64_buf_t *b, unsigned ov)
{
    ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_mov_imm32(b, A64_TMP3, EI_XER_OV);
    a64_emit_bic_reg_w(b, false, EI_X, EI_X, A64_TMP3, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_X, EI_X, ov, A64_SHIFT_LSL, 30U);
    a64_emit_orr_reg_w(b, EI_X, EI_X, ov, A64_SHIFT_LSL, 31U);
    ei_ctx_st(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
}

/* 32-bit wrap EA for D-forms into w22. d is the sign-extended displacement. */
static inline void ei_ea_d(a64_buf_t *b, unsigned ra, uint32_t d)
{
    if (ra == 0U) {
        a64_emit_mov_imm32(b, A64_ADDR, d);
        return;
    }
    ei_ld(b, EI_A, ra);
    a64_emit_mov_imm32(b, EI_B, d);
    a64_emit_add_reg_w(b, false, A64_ADDR, EI_A, EI_B, A64_SHIFT_LSL, 0U);
}

/* 32-bit wrap EA for X-forms (ra==0 means literal 0) into w22. */
static inline void ei_ea_x(a64_buf_t *b, unsigned ra, unsigned rb)
{
    ei_ld(b, EI_B, rb);
    if (ra == 0U) {
        a64_emit_mov_w(b, A64_ADDR, EI_B);
        return;
    }
    ei_ld(b, EI_A, ra);
    a64_emit_add_reg_w(b, false, A64_ADDR, EI_A, EI_B, A64_SHIFT_LSL, 0U);
}

/* RC4 low-guard fault: EA is in w22; fault (nip = pc, fault_addr = EA)
 * when EA < PPC32_LOW_GUARD_SIZE, so the driver delivers SIGSEGV instead
 * of the host faulting on the PROT_NONE guard window. Single subs against
 * #0x10000 (16, lsl #12); no scratch reg, AArch64 flags dead at every
 * call site (EA computation leaves none live). Multi-byte/string ops
 * check the base EA only: EAs advance upward from the base, so a base at
 * or above the guard cannot descend into it short of 4 GiB wrap-around
 * (out of scope, same as the interpreter). */
static inline void ei_guard_low(a64_buf_t *b, uint32_t pc)
{
    size_t to_ok;

    a64_emit_sub_imm_w(b, true, A64_ZR, A64_ADDR, 16U, 1U);
    to_ok = a64_emit_b_cond_placeholder(b, A64_COND_CS);
    a64_emit_exit_fault(b, pc, A64_ADDR);
    a64_patch_b_cond(b, to_ok, b->count);
}

/* Load XER.CA (bit 29) as a 0/1 value into `rd`. Clobbers EI_T2. */
static inline void ei_ld_ca(a64_buf_t *b, unsigned rd)
{
    ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_shift_imm_w(b, rd, EI_X, A64_SHIFT_LSR, 29U, false, NULL);
    a64_emit_mov_imm32(b, EI_T2, 1U);
    a64_emit_and_reg_w(b, false, rd, rd, EI_T2, A64_SHIFT_LSL, 0U);
}

/* ((x ^ r) & (y ^ r)) >> 31: add overflow bit into EI_A. */
static inline void ei_add_ov(a64_buf_t *b, unsigned x, unsigned y, unsigned r)
{
    a64_emit_eor_reg_w(b, EI_A, x, r, A64_SHIFT_LSL, 0U);
    a64_emit_eor_reg_w(b, EI_B, y, r, A64_SHIFT_LSL, 0U);
    a64_emit_and_reg_w(b, false, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_A, EI_A, A64_SHIFT_LSR, 31U, false, NULL);
}

/* ((a ^ r) & (a ^ b)) >> 31: sub overflow bit into EI_A. */
static inline void ei_sub_ov(a64_buf_t *b, unsigned x, unsigned y, unsigned r)
{
    a64_emit_eor_reg_w(b, EI_A, x, r, A64_SHIFT_LSL, 0U);
    a64_emit_eor_reg_w(b, EI_B, x, y, A64_SHIFT_LSL, 0U);
    a64_emit_and_reg_w(b, false, EI_A, EI_A, EI_B, A64_SHIFT_LSL, 0U);
    a64_emit_shift_imm_w(b, EI_A, EI_A, A64_SHIFT_LSR, 31U, false, NULL);
}

/* Extract CR bit `bi` (0..31, full bit number) into EI_B. Clobbers EI_T2. */
static inline void ei_ld_crbit(a64_buf_t *b, unsigned cr, unsigned bi)
{
    a64_emit_shift_imm_w(b, EI_B, cr, A64_SHIFT_LSR, 31U - (bi & 31U),
        false, NULL);
    a64_emit_mov_imm32(b, EI_T2, 1U);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T2, A64_SHIFT_LSL, 0U);
}

/* Rotate/mask helper with MB>ME wrap (E02): MB<=ME selects [MB,ME];
 * MB>ME selects [MB,31]+[0,ME]. MB/ME are emit-time immediates. */
static inline uint32_t ei_ppc_mask(uint32_t mb, uint32_t me)
{
    uint32_t ml = 0xFFFFFFFFU >> (mb & 31U);
    uint32_t mh = ((me & 31U) == 31U) ? 0U : (0xFFFFFFFFU >> ((me & 31U) + 1U));
    uint32_t x = ml ^ mh;

    if ((mb & 31U) <= (me & 31U)) {
        return x;
    }
    return ~x;
}

/* Store gpr[rt] = res, then CR0 from res when rc is set. */
static inline void ei_finish(a64_buf_t *b, unsigned res, unsigned rt,
    unsigned rc)
{
    ei_st(b, res, rt);
    if (rc != 0U) {
        ei_ctx_ld(b, EI_X, (uint32_t)offsetof(ppc32_ctx_t, xer));
        ei_set_cr0(b, res, EI_X);
    }
}

/* LK path shared by b/bc/bclr/bctr: lr = next, mark block as a call. */
static inline void ei_store_lr(a64_buf_t *b, uint32_t next)
{
    a64_emit_mov_imm32(b, EI_A, next);
    ei_ctx_st(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, lr));
    b->is_call = true;
}

/* Merge a 4-bit value into CR field bf (shift s): cr = (cr&~m)|(v<<s).
 * NOTE: EI_R is NOT usable as the mask temp -- fp fcmp passes val in
 * EI_R (RC3: always produced CR=0). EI_T2 is dead at every call site. */
static inline void ei_cr_merge(a64_buf_t *b, unsigned cr, unsigned val,
    uint32_t s)
{
    a64_emit_mov_imm32(b, EI_T2, 0xFU << s);
    a64_emit_bic_reg_w(b, false, cr, cr, EI_T2, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, cr, cr, val, A64_SHIFT_LSL, s);
    ei_ctx_st(b, cr, (uint32_t)offsetof(ppc32_ctx_t, cr));
}

/* taken = ctr_ok && cond_ok into EI_B. Clobbers EI_A/EI_B/EI_T. */
static inline void ei_branch_taken(a64_buf_t *b, uint8_t bo, uint8_t bi)
{
    a64_emit_movz_w(b, EI_B, 1U, 0U);
    if ((bo & 4U) == 0U) {
        ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, ctr));
        a64_emit_sub_imm_w(b, false, EI_A, EI_A, 1U, 0U);
        ei_ctx_st(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, ctr));
        ei_cmp_imm(b, EI_A, 0U);
        ei_cset(b, EI_T, ((bo & 2U) != 0U) ? A64_COND_EQ : A64_COND_NE);
        a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    }
    if ((bo & 16U) == 0U) {
        ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
        a64_emit_shift_imm_w(b, EI_A, EI_A, A64_SHIFT_LSR,
            31U - (bi & 31U), false, NULL);
        a64_emit_mov_imm32(b, EI_T, 1U);
        a64_emit_and_reg_w(b, false, EI_A, EI_A, EI_T, A64_SHIFT_LSL, 0U);
        ei_cmp_imm(b, EI_A, ((bo & 8U) != 0U) ? 1U : 0U);
        ei_cset(b, EI_T, A64_COND_EQ);
        a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    }
}


/* ---- CR/system and memory lowerings (shared inline) ----
 *
 * Kept inline in the header (same pattern as src/interp/interp.h)
 * so L2b block prologues/epilogues can reuse the exact EA, CR, SPR,
 * and reservation semantics without a second implementation. */

/* ---- CR logicals, mcrf/mcrxr, mfcr/mtcrf, mfspr/mtspr ---- */

static inline int ei_cr_op(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t xo = in->xo;

    ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    ei_ld_crbit(b, EI_A, in->ra); /* abit -> EI_B */
    a64_emit_mov_w(b, EI_T, EI_B);
    ei_ld_crbit(b, EI_A, in->rb); /* bbit -> EI_B, one = EI_T2 */
    if (xo == 129U || xo == 417U) { /* complemented b */
        a64_emit_eor_reg_w(b, EI_B, EI_B, EI_T2, A64_SHIFT_LSL, 0U);
    }
    if (xo == 257U || xo == 129U) {
        a64_emit_and_reg_w(b, false, EI_B, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    } else if (xo == 449U || xo == 417U) {
        a64_emit_orr_reg_w(b, EI_B, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    } else if (xo == 193U || xo == 289U) {
        a64_emit_eor_reg_w(b, EI_B, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    } else if (xo == 225U) {
        a64_emit_and_reg_w(b, false, EI_B, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    } else {
        a64_emit_orr_reg_w(b, EI_B, EI_T, EI_B, A64_SHIFT_LSL, 0U);
    }
    if (xo == 225U || xo == 33U || xo == 289U) { /* nand/nor/eqv */
        a64_emit_eor_reg_w(b, EI_B, EI_B, EI_T2, A64_SHIFT_LSL, 0U);
    }
    /* Branchless insert: cr = out ? (cr|mask) : (cr&~mask). */
    a64_emit_mov_imm32(b, EI_T, 0x80000000U >> (in->rt & 31U));
    a64_emit_bic_reg_w(b, false, EI_T2, EI_A, EI_T, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, EI_T, EI_A, EI_T, A64_SHIFT_LSL, 0U);
    ei_cmp_imm(b, EI_B, 0U);
    a64_emit_csel_w(b, EI_A, EI_T, EI_T2, A64_COND_NE);
    ei_ctx_st(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    return PPC32_EMIT_NEXT;
}

static inline int ei_mcrf(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t s = (7U - ((in->rt >> 2U) & 7U)) * 4U;

    ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    a64_emit_shift_imm_w(b, EI_B, EI_A, A64_SHIFT_LSR,
        (7U - ((in->ra >> 2U) & 7U)) * 4U, false, NULL);
    a64_emit_mov_imm32(b, EI_T, 0xFU);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    ei_cr_merge(b, EI_A, EI_B, s);
    return PPC32_EMIT_NEXT;
}

static inline int ei_mcrxr(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t s = (7U - ((in->raw >> 23U) & 7U)) * 4U;

    ei_ctx_ld(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_shift_imm_w(b, EI_B, EI_B, A64_SHIFT_LSR, 28U, false, NULL);
    a64_emit_mov_imm32(b, EI_T, 0xFU);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    ei_cr_merge(b, EI_A, EI_B, s);
    ei_ctx_ld(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, xer));
    a64_emit_mov_imm32(b, EI_T, 0x0FFFFFFFU);
    a64_emit_and_reg_w(b, false, EI_B, EI_B, EI_T, A64_SHIFT_LSL, 0U);
    ei_ctx_st(b, EI_B, (uint32_t)offsetof(ppc32_ctx_t, xer));
    return PPC32_EMIT_NEXT;
}

static inline int ei_mtcrf(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t crm = (in->raw >> 12U) & 0xFFU;
    uint32_t i;

    ei_ctx_ld(b, EI_A, (uint32_t)offsetof(ppc32_ctx_t, cr));
    ei_ld(b, EI_B, in->rs);
    for (i = 0U; i < 8U; i++) {
        uint32_t s = (7U - i) * 4U;

        if (((crm >> (7U - i)) & 1U) == 0U) {
            continue;
        }
        a64_emit_shift_imm_w(b, EI_T, EI_B, A64_SHIFT_LSR, s, false, NULL);
        a64_emit_mov_imm32(b, EI_R, 0xFU);
        a64_emit_and_reg_w(b, false, EI_T, EI_T, EI_R, A64_SHIFT_LSL, 0U);
        ei_cr_merge(b, EI_A, EI_T, s);
    }
    return PPC32_EMIT_NEXT;
}

static inline int ei_spr(a64_buf_t *b, const ppc32_insn_t *in)
{
    uint32_t off;

    if (in->ui == PPC32_SPR_XER) {
        off = (uint32_t)offsetof(ppc32_ctx_t, xer);
    } else if (in->ui == PPC32_SPR_LR) {
        off = (uint32_t)offsetof(ppc32_ctx_t, lr);
    } else if (in->ui == PPC32_SPR_CTR) {
        off = (uint32_t)offsetof(ppc32_ctx_t, ctr);
    } else if (in->ui == 268U || in->ui == 269U) {
        if (in->op != PPC32_OP_MFSPR) {
            return PPC32_EMIT_FALLBACK;
        }
        a64_emit_movz_w(b, EI_A, 0U, 0U); /* TB/TBU read as 0 (interp) */
        ei_st(b, EI_A, in->rt);
        return PPC32_EMIT_NEXT;
    } else {
        return PPC32_EMIT_FALLBACK; /* privileged SPR: interp UNDEFs */
    }
    if (in->op == PPC32_OP_MFSPR) {
        ei_ctx_ld(b, EI_A, off);
        ei_st(b, EI_A, in->rt);
    } else {
        ei_ld(b, EI_A, in->rs);
        ei_ctx_st(b, EI_A, off);
    }
    return PPC32_EMIT_NEXT;
}

/* ---- loads/stores: D + X + update, swaps, multi/string, *brx ----
 * width: 0 = byte, 1 = half, 2 = word. swap: 0 = none, 1 = REV16, 2 = REV. */

static inline bool ei_is_load(uint32_t op)
{
    return op == PPC32_OP_LWZ || op == PPC32_OP_LWZU || op == PPC32_OP_LBZ ||
        op == PPC32_OP_LBZU || op == PPC32_OP_LHZ || op == PPC32_OP_LHZU ||
        op == PPC32_OP_LHA || op == PPC32_OP_LHAU || op == PPC32_OP_LWZX ||
        op == PPC32_OP_LWZUX || op == PPC32_OP_LBZX || op == PPC32_OP_LBZUX ||
        op == PPC32_OP_LHZX || op == PPC32_OP_LHZUX || op == PPC32_OP_LHAX ||
        op == PPC32_OP_LHAUX || op == PPC32_OP_LWBRX || op == PPC32_OP_LHBRX;
}

static inline bool ei_is_update(uint32_t op)
{
    return op == PPC32_OP_LWZU || op == PPC32_OP_LBZU || op == PPC32_OP_LHZU ||
        op == PPC32_OP_LHAU || op == PPC32_OP_STWU || op == PPC32_OP_STBU ||
        op == PPC32_OP_STHU || op == PPC32_OP_LWZUX || op == PPC32_OP_LBZUX ||
        op == PPC32_OP_LHZUX || op == PPC32_OP_LHAUX || op == PPC32_OP_STWUX ||
        op == PPC32_OP_STBUX || op == PPC32_OP_STHUX;
}

static inline int ei_mem(a64_buf_t *b, const ppc32_insn_t *in, bool is_x,
    uint32_t pc)
{
    unsigned width = 2U;
    unsigned swap = 2U;
    bool sign = false;
    bool load = ei_is_load(in->op);

    switch (in->op) {
    case PPC32_OP_LBZ:
    case PPC32_OP_LBZU:
    case PPC32_OP_STB:
    case PPC32_OP_STBU:
    case PPC32_OP_LBZX:
    case PPC32_OP_LBZUX:
    case PPC32_OP_STBX:
    case PPC32_OP_STBUX:
        width = 0U;
        swap = 0U;
        break;
    case PPC32_OP_LHZ:
    case PPC32_OP_LHZU:
    case PPC32_OP_STH:
    case PPC32_OP_STHU:
    case PPC32_OP_LHZX:
    case PPC32_OP_LHZUX:
    case PPC32_OP_STHX:
    case PPC32_OP_STHUX:
        width = 1U;
        swap = 1U;
        break;
    case PPC32_OP_LHBRX:
    case PPC32_OP_STHBRX:
        width = 1U;
        swap = 0U;
        break;
    case PPC32_OP_LWBRX:
    case PPC32_OP_STWBRX:
        swap = 0U;
        break;
    case PPC32_OP_LHA:
    case PPC32_OP_LHAU:
    case PPC32_OP_LHAX:
    case PPC32_OP_LHAUX:
        width = 1U;
        swap = 1U;
        sign = true;
        break;
    default:
        break;
    }
    if (in->ra == 0U && ei_is_update(in->op)) {
        return PPC32_EMIT_FALLBACK; /* interp UNDEFs */
    }
    if (is_x) {
        ei_ea_x(b, in->ra, in->rb);
    } else {
        ei_ea_d(b, in->ra, (uint32_t)in->d);
    }
    /* Interp (interp_exec_dform_mem) accesses BEFORE the base update, so
     * a store with rs == ra must capture the source first (RC2: stwu
     * r1,-32(r1) stored EA instead of the old value). Loads keep EA in
     * w22 across the update, so only the overlapping store needs this.
     * RC4 low-guard placement mirrors the interpreter per form: D-forms
     * guard before the update (interp accesses first), X-forms guard
     * after it (interp_exec_xform_mem updates first). */
    bool overlap = !load && ei_is_update(in->op) && in->rs == in->ra;
    if (overlap) {
        ei_ld(b, EI_B, in->rs);
    }
    if (!is_x) {
        ei_guard_low(b, pc);
    }
    if (ei_is_update(in->op)) {
        a64_emit_str_imm_w(b, A64_ADDR, A64_XCTX, ei_gpr_off(in->ra));
    }
    if (is_x) {
        ei_guard_low(b, pc);
    }
    if (load) {
        if (width == 2U) {
            a64_emit_guest_ldr_w(b, EI_B, A64_ADDR);
            if (swap == 2U) {
                a64_emit_rev_w(b, EI_B, EI_B);
            }
        } else if (width == 1U) {
            a64_emit_guest_ldrh_w(b, EI_B, A64_ADDR);
            if (swap == 1U) {
                a64_emit_rev16_w(b, EI_B, EI_B);
            }
            if (sign) {
                a64_emit_sbfm_w(b, EI_B, EI_B, 0U, 15U);
            }
        } else {
            a64_emit_guest_ldrb_w(b, EI_B, A64_ADDR);
        }
        ei_st(b, EI_B, in->rt);
        return PPC32_EMIT_NEXT;
    }
    if (!overlap) {
        ei_ld(b, EI_B, in->rs);
    }
    if (width == 2U) {
        if (swap == 2U) {
            a64_emit_rev_w(b, EI_B, EI_B);
        }
        a64_emit_guest_str_w(b, EI_B, A64_ADDR);
    } else if (width == 1U) {
        if (swap == 1U) {
            a64_emit_rev16_w(b, EI_B, EI_B);
        }
        a64_emit_guest_strh_w(b, EI_B, A64_ADDR);
    } else {
        a64_emit_guest_strb_w(b, EI_B, A64_ADDR);
    }
    return PPC32_EMIT_NEXT;
}

/* lmw/stmw: unrolled word loop; misaligned EA falls back (interp FAULTs). */
static inline int ei_multi(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc,
    ppc32_emit_ctx_t *e)
{
    uint32_t k;
    size_t patch_mis;
    size_t patch_skip;
    size_t fb_idx;

    ei_ea_d(b, in->ra, (uint32_t)in->d);
    ei_guard_low(b, pc);
    a64_emit_mov_imm32(b, EI_A, 3U);
    a64_emit_and_reg_w(b, true, A64_ZR, A64_ADDR, EI_A, A64_SHIFT_LSL, 0U);
    patch_mis = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    for (k = in->rt; k < 32U; k++) {
        if (k != in->rt) {
            a64_emit_add_imm_w(b, false, A64_ADDR, A64_ADDR, 4U, 0U);
        }
        if (in->op == PPC32_OP_LMW) {
            a64_emit_guest_ldr_w(b, EI_B, A64_ADDR);
            a64_emit_rev_w(b, EI_B, EI_B);
            ei_st(b, EI_B, k);
        } else {
            ei_ld(b, EI_B, k);
            a64_emit_rev_w(b, EI_B, EI_B);
            a64_emit_guest_str_w(b, EI_B, A64_ADDR);
        }
    }
    patch_skip = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    fb_idx = b->count;
    ppc32_emit_fallback(e, pc);
    a64_patch_b_cond(b, patch_mis, fb_idx);
    a64_patch_b_cond(b, patch_skip, b->count);
    return PPC32_EMIT_NEXT;
}

/* lswi/stswi: NB = rb (0 means 32). Bytes pack big-end first (E05). */
static inline int ei_string(a64_buf_t *b, const ppc32_insn_t *in, uint32_t pc)
{
    uint32_t n = (in->rb == 0U) ? 32U : in->rb;
    uint32_t i;

    if (in->ra == 0U) {
        a64_emit_movz_w(b, A64_ADDR, 0U, 0U);
    } else {
        ei_ld(b, A64_ADDR, in->ra);
    }
    ei_guard_low(b, pc);
    if (in->op == PPC32_OP_STSWI) {
        for (i = 0U; i < n; i++) {
            uint32_t reg = (in->rs + i / 4U) & 31U;
            uint32_t shift = (3U - (i % 4U)) * 8U;

            if (i != 0U) {
                a64_emit_add_imm_w(b, false, A64_ADDR, A64_ADDR, 1U, 0U);
            }
            ei_ld(b, EI_B, reg);
            a64_emit_shift_imm_w(b, EI_B, EI_B, A64_SHIFT_LSR, shift, false,
                NULL);
            a64_emit_guest_strb_w(b, EI_B, A64_ADDR);
        }
        return PPC32_EMIT_NEXT;
    }
    for (i = 0U; i < n; i++) { /* LSWI: one group store per register */
        uint32_t reg = (in->rt + i / 4U) & 31U;
        uint32_t shift = (3U - (i % 4U)) * 8U;
        uint32_t last = (i + 1U == n) ||
            (((in->rt + (i + 1U) / 4U) & 31U) != reg);

        if (i != 0U) {
            a64_emit_add_imm_w(b, false, A64_ADDR, A64_ADDR, 1U, 0U);
        }
        if (i == 0U || (((in->rt + (i - 1U) / 4U) & 31U) != reg)) {
            ei_ld(b, EI_B, reg);
        }
        a64_emit_guest_ldrb_w(b, EI_T, A64_ADDR);
        a64_emit_mov_imm32(b, EI_T2, 0xFFU << shift);
        a64_emit_bic_reg_w(b, false, EI_B, EI_B, EI_T2, A64_SHIFT_LSL, 0U);
        a64_emit_orr_reg_w(b, EI_B, EI_B, EI_T, A64_SHIFT_LSL, shift);
        if (last) {
            ei_st(b, EI_B, reg);
        }
    }
    return PPC32_EMIT_NEXT;
}

#endif /* PPC32RT_DBT_EMIT_INT_H */

