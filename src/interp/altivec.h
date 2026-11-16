/*
 * src/interp/altivec.h — PowerPC 7400/7450 (G4) AltiVec (VMX) reference
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * G04 Darwin G4 CPU profile: architectural VMX state lives in the
 * C-only tail of ppc32_ctx_t (vr[32][16] BE bytes, vscr, vrsave).
 * interp_step routes PPC32_OP_VMX / PPC32_OP_VMX_LDST here (and
 * PPC32_OP_SPE on non-SPE profiles, so shared primary-4 encodings
 * resolve by profile). DBT has no native VMX lowering yet and falls
 * back to interp_step via EXIT_UNDEF, which keeps --difftest exact.
 *
 * XO values follow PowerISA Book I (exact 11-bit match, Rc slot
 * included; never masked to 10 bits): e.g. VADDUBM 0, VSUBUBM 1024,
 * VAND 1028, VOR 1156, VXOR 1220, VNOR 1284, VSPLTB 524, VPERM 43,
 * VSEL 42, MFVSCR 1540, MTVSCR 1604, LVX 103 / STVX 231 (primary 31),
 * DST 342 / DSTST 374 / DSS 822 (decoded to DCBT no-ops), DCBA 758
 * (decoded to DCBT, never DCBZ), DCBF 86 / DCBST 54 (DCBT no-ops).
 * VXR-form compares (vcmpequb. etc.) arrive as base+1024 (bit 10 is
 * the VXR Rc slot); the dispatcher strips only bit 10 for the compare
 * group and honors it as Rc -> CR6.
 */

#ifndef PPC32RT_INTERP_ALTIVEC_H
#define PPC32RT_INTERP_ALTIVEC_H

#include <math.h>
#include <stdint.h>
#include <string.h>

#include "ppc32rt.h"
#include "interp/decode.h"

/* Big-endian lane access shared by altivec.c and altivec_arith.c.
 * vr[r][0] is the most significant byte. */

static inline uint16_t vr_be16(const ppc32_ctx_t *ctx, uint32_t r,
    uint32_t lane)
{
    const uint8_t *v = ctx->vr[r & 31U];

    return (uint16_t)(((uint16_t)v[lane * 2U] << 8) | v[lane * 2U + 1U]);
}

static inline void vr_set_be16(ppc32_ctx_t *ctx, uint32_t r, uint32_t lane,
    uint16_t w)
{
    uint8_t *v = ctx->vr[r & 31U];

    v[lane * 2U] = (uint8_t)(w >> 8);
    v[lane * 2U + 1U] = (uint8_t)w;
}

static inline uint32_t vr_be32(const ppc32_ctx_t *ctx, uint32_t r,
    uint32_t lane)
{
    const uint8_t *v = ctx->vr[r & 31U];

    return ((uint32_t)v[lane * 4U] << 24) |
        ((uint32_t)v[lane * 4U + 1U] << 16) |
        ((uint32_t)v[lane * 4U + 2U] << 8) | v[lane * 4U + 3U];
}

static inline void vr_set_be32(ppc32_ctx_t *ctx, uint32_t r, uint32_t lane,
    uint32_t w)
{
    uint8_t *v = ctx->vr[r & 31U];

    v[lane * 4U] = (uint8_t)(w >> 24);
    v[lane * 4U + 1U] = (uint8_t)(w >> 16);
    v[lane * 4U + 2U] = (uint8_t)(w >> 8);
    v[lane * 4U + 3U] = (uint8_t)w;
}

static inline float vr_f32(const ppc32_ctx_t *ctx, uint32_t r,
    uint32_t lane)
{
    uint32_t w = vr_be32(ctx, r, lane);
    float f;

    memcpy(&f, &w, 4);
    return f;
}

static inline void vr_set_f32(ppc32_ctx_t *ctx, uint32_t r, uint32_t lane,
    float f)
{
    uint32_t w;

    memcpy(&w, &f, 4);
    vr_set_be32(ctx, r, lane, w);
}

/* VSCR.NJ (bit 16, see the 0x00010001 mtvscr mask): denormal inputs
 * and results flush toward zero (sign preserved). Darwin runs with
 * NJ=1, so vaddfp/vsubfp/vmaddfp/vnmsubfp must not propagate
 * subnormals. */
static inline float vmx_nj_flush(const ppc32_ctx_t *ctx, float f)
{
    /* Bit-exact subnormal test (exponent field zero, mantissa
     * nonzero); avoids libm classification macros under strict C11. */
    uint32_t w;

    memcpy(&w, &f, 4);
    if (((ctx->vscr & 0x00010000U) != 0U) &&
        ((w & 0x7F800000U) == 0U) && ((w & 0x007FFFFFU) != 0U)) {
        return ((w & 0x80000000U) != 0U) ? -0.0f : 0.0f;
    }
    return f;
}

/* Sign-biased unsigned compares (avoid implementation-defined
 * (int8_t) casts on values above 127 under strict C11). */
static inline bool vmx_gt_s8(uint8_t a, uint8_t b)
{
    return (a ^ 0x80U) > (b ^ 0x80U);
}

static inline bool vmx_gt_s16(uint16_t a, uint16_t b)
{
    return (uint16_t)(a ^ 0x8000U) > (uint16_t)(b ^ 0x8000U);
}

static inline bool vmx_gt_s32(uint32_t a, uint32_t b)
{
    return (a ^ 0x80000000U) > (b ^ 0x80000000U);
}

/* CR6 for Rc=1 compares: bit 24 (LT slot, value 8) when every lane is
 * true, bit 26 (EQ slot, value 2) when every lane is false, bits 25
 * and 27 always zero. vcmpbfp falls out naturally: its result word is
 * 0 exactly when the element is in bounds, so all-in-bounds sets the
 * "all false" bit 26. */
static inline void vr_set_cr6(ppc32_ctx_t *ctx, bool all_true,
    bool all_false)
{
    uint32_t v = (all_true ? 8U : 0U) | (all_false ? 2U : 0U);

    ctx->cr = (ctx->cr & ~(0xFU << 4)) | (v << 4);
}

/* Execute one primary-4 VMX arithmetic/logical/permute/compare/FP op.
 * Unknown XOs set PPC32_EXIT_UNDEF. Rc=1 on compares sets CR6. */
void ppc32_altivec_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);

/* Execute one primary-31 VMX load/store (lvx/lvxl/lvebx/stvebx/lvsl/lvsr).
 * Unknown XOs set PPC32_EXIT_UNDEF. */
void ppc32_vmx_ldst_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);

/* Arithmetic/compare/pack/unpack helpers (altivec_arith.c, exact-XO
 * dispatched from ppc32_altivec_step). x is the full 11-bit XO. */
void ppc32_vmx_addsub(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x);
void ppc32_vmx_fp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, uint32_t x);
void ppc32_vmx_cmp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base, bool rc);
void ppc32_vmx_pack(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x);
void ppc32_vmx_unpack(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x);
void ppc32_vmx_sum(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t low6);

#endif /* PPC32RT_INTERP_ALTIVEC_H */
