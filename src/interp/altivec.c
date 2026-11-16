/*
 * src/interp/altivec.c — G4 AltiVec (VMX) reference interpreter (G04)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers the Darwin G4 libSystem / Accelerate / compiler subset:
 * lvx/lvxl/lvebx/lvehx/lvewx/lvsl/lvsr/stvx/stvxl/
 * stvebx/stvehx/stvewx, integer/logical/permute/splat/merge/pack/unpack/
 * sldoi/shift/rotate, vaddubm/hm/wm + vsububm/hm/wm, saturating
 * add/sub (VSCR.SAT), vaddfp/vsubfp/vmaddfp/vnmsubfp/vmaxfp/vminfp,
 * vmsumubm/vmsummbm/vmladduhm, vcmpeq/vcmpgt/vcmpge/vcmpbfp (Rc -> CR6),
 * vsl/vsr/vslo/vsro, mtvscr/mfvscr, dcbz zeroing, dcbf/dcbst/dcbt/
 * dcbtst/dst/dss/icbi/isync no-ops (decoded to SYNC/DCBT).
 *
 * vr[r][0] is the most significant byte (big-endian lane order).
 * Loads/stores use the BE ld/st helpers so Soft-TLB, COW promotion,
 * reservation invalidation, and fault reporting match the integer
 * path exactly. Vector EA for lvx/stvx is aligned down (EA & ~15U);
 * lvehx/stvehx clear EA bit 0 and lvewx/stvewx clear EA bits 0..1
 * before both the access and the lane index.
 *
 * Dispatch matches the full 11-bit XO exactly (never masked): unknown
 * XOs set PPC32_EXIT_UNDEF. VXR-form compares arrive as base+1024
 * (instruction bit 21 is the VXR Rc slot); Rc=1 updates CR6.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "interp/altivec.h"
#include "interp/interp.h"

void ppc32_vmx_ldst_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint32_t ea = (insn->ra == 0U ? 0U : ctx->gpr[insn->ra]) +
        ctx->gpr[insn->rb];
    uint32_t i;

    switch (insn->xo) {
    case 103u: /* lvx */
    case 359u: /* lvxl (lock hint ignored) */ {
        uint32_t base = ea & ~15U;
        uint8_t tmp[16];

        if (!interp_mem_ok(base, 16U)) {
            fault(ctx, base);
            return;
        }
        for (i = 0U; i < 16U; i++) {
            tmp[i] = ld8(ctx, base + i);
            if (ctx->exit_reason != PPC32_EXIT_NONE) {
                return;
            }
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        ctx->nip += 4U;
        return;
    }
    case 231u: /* stvx */
    case 487u: /* stvxl (lock hint ignored) */ {
        uint32_t base = ea & ~15U;

        if (!interp_mem_ok(base, 16U)) {
            fault(ctx, base);
            ctx->fault_is_store = 1U;
            return;
        }
        for (i = 0U; i < 16U; i++) {
            st8(ctx, base + i, ctx->vr[insn->rs & 31U][i]);
            if (ctx->exit_reason != PPC32_EXIT_NONE) {
                return;
            }
        }
        ctx->nip += 4U;
        return;
    }
    case 7u: /* lvebx */ {
        uint8_t b;

        if (!interp_mem_ok(ea, 1U)) {
            fault(ctx, ea);
            return;
        }
        b = ld8(ctx, ea);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->vr[insn->rt & 31U][ea & 15U] = b;
        ctx->nip += 4U;
        return;
    }
    case 39u: { /* lvehx: EA bit 0 cleared first */
        uint32_t ae = ea & ~1U;
        uint16_t h;

        if (!interp_mem_ok(ae, 2U)) {
            fault(ctx, ae);
            return;
        }
        h = ld16(ctx, ae);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->vr[insn->rt & 31U][ae & 15U] = (uint8_t)(h >> 8);
        ctx->vr[insn->rt & 31U][(ae & 15U) + 1U] = (uint8_t)h;
        ctx->nip += 4U;
        return;
    }
    case 71u: { /* lvewx: EA bits 0..1 cleared first */
        uint32_t ae = ea & ~3U;
        uint32_t w;

        if (!interp_mem_ok(ae, 4U)) {
            fault(ctx, ae);
            return;
        }
        w = ld32(ctx, ae);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->vr[insn->rt & 31U][ae & 15U] = (uint8_t)(w >> 24);
        ctx->vr[insn->rt & 31U][((ae & 15U) + 1U) & 15U] =
            (uint8_t)(w >> 16);
        ctx->vr[insn->rt & 31U][((ae & 15U) + 2U) & 15U] =
            (uint8_t)(w >> 8);
        ctx->vr[insn->rt & 31U][((ae & 15U) + 3U) & 15U] = (uint8_t)w;
        ctx->nip += 4U;
        return;
    }
    case 135u: { /* stvebx */
        if (!interp_mem_ok(ea, 1U)) {
            fault(ctx, ea);
            ctx->fault_is_store = 1U;
            return;
        }
        st8(ctx, ea, ctx->vr[insn->rs & 31U][ea & 15U]);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->nip += 4U;
        return;
    }
    case 167u: { /* stvehx: EA bit 0 cleared first */
        uint32_t ae = ea & ~1U;
        uint16_t h = (uint16_t)(((uint16_t)ctx->vr[insn->rs & 31U][ae & 15U]
            << 8) | ctx->vr[insn->rs & 31U][(ae & 15U) + 1U]);

        if (!interp_mem_ok(ae, 2U)) {
            fault(ctx, ae);
            ctx->fault_is_store = 1U;
            return;
        }
        st16(ctx, ae, h);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->nip += 4U;
        return;
    }
    case 199u: { /* stvewx: EA bits 0..1 cleared first */
        uint32_t ae = ea & ~3U;
        uint32_t off = ae & 15U;
        uint32_t w = ((uint32_t)ctx->vr[insn->rs & 31U][off] << 24) |
            ((uint32_t)ctx->vr[insn->rs & 31U][(off + 1U) & 15U] << 16) |
            ((uint32_t)ctx->vr[insn->rs & 31U][(off + 2U) & 15U] << 8) |
            ctx->vr[insn->rs & 31U][(off + 3U) & 15U];

        if (!interp_mem_ok(ae, 4U)) {
            fault(ctx, ae);
            ctx->fault_is_store = 1U;
            return;
        }
        st32(ctx, ae, w);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->nip += 4U;
        return;
    }
    case 6u: /* lvsl */
        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = (uint8_t)((ea & 15U) + i);
        }
        ctx->nip += 4U;
        return;
    case 38u: /* lvsr: bytes 16-sh .. 31-sh (values 0x10..0x1F legal) */
        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = (uint8_t)(16U - (ea & 15U) + i);
        }
        ctx->nip += 4U;
        return;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
}

static void vmx_logic(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t i;
    uint8_t *vd = ctx->vr[insn->rt & 31U];
    const uint8_t *va = ctx->vr[insn->ra & 31U];
    const uint8_t *vb = ctx->vr[insn->rb & 31U];

    for (i = 0U; i < 16U; i++) {
        switch (x) {
        case 1028u:
            vd[i] = va[i] & vb[i];
            break;
        case 1092u:
            vd[i] = va[i] & (uint8_t)~vb[i];
            break;
        case 1156u:
            vd[i] = va[i] | vb[i];
            break;
        case 1220u:
            vd[i] = va[i] ^ vb[i];
            break;
        case 1284u:
            vd[i] = (uint8_t)~(va[i] | vb[i]);
            break;
        default:
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
    }
    ctx->nip += 4U;
}

static void vmx_splat(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t u = insn->ra & 31U;
    uint32_t i;

    switch (x) {
    case 524u: {
        uint8_t b = ctx->vr[insn->rb & 31U][u & 15U];

        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = b;
        }
        break;
    }
    case 588u: {
        uint16_t h = vr_be16(ctx, insn->rb, u & 7U);

        for (i = 0U; i < 8U; i++) {
            vr_set_be16(ctx, insn->rt, i, h);
        }
        break;
    }
    case 652u: {
        uint32_t w = vr_be32(ctx, insn->rb, u & 3U);

        for (i = 0U; i < 4U; i++) {
            vr_set_be32(ctx, insn->rt, i, w);
        }
        break;
    }
    case 780u: {
        int32_t s = (u & 16U) != 0U ? (int32_t)u - 32 : (int32_t)u;

        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = (uint8_t)s;
        }
        break;
    }
    case 844u: {
        int32_t s = (u & 16U) != 0U ? (int32_t)u - 32 : (int32_t)u;

        for (i = 0U; i < 8U; i++) {
            vr_set_be16(ctx, insn->rt, i, (uint16_t)(int16_t)s);
        }
        break;
    }
    case 908u: {
        int32_t s = (u & 16U) != 0U ? (int32_t)u - 32 : (int32_t)u;

        for (i = 0U; i < 4U; i++) {
            vr_set_be32(ctx, insn->rt, i, (uint32_t)s);
        }
        break;
    }
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    ctx->nip += 4U;
}

static void vmx_merge(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t i;
    uint8_t tmp[16];

    switch (x) {
    case 12u:
    case 268u: {
        uint32_t base = (x == 12u) ? 0U : 8U;

        for (i = 0U; i < 8U; i++) {
            tmp[2U * i] = ctx->vr[insn->ra & 31U][base + i];
            tmp[2U * i + 1U] = ctx->vr[insn->rb & 31U][base + i];
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    case 76u:
    case 332u: {
        uint32_t base = (x == 76u) ? 0U : 4U;

        for (i = 0U; i < 4U; i++) {
            uint32_t a = vr_be16(ctx, insn->ra, base + i);
            uint32_t b = vr_be16(ctx, insn->rb, base + i);

            tmp[4U * i] = (uint8_t)(a >> 8);
            tmp[4U * i + 1U] = (uint8_t)a;
            tmp[4U * i + 2U] = (uint8_t)(b >> 8);
            tmp[4U * i + 3U] = (uint8_t)b;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    case 140u:
    case 396u: {
        uint32_t base = (x == 140u) ? 0U : 2U;

        for (i = 0U; i < 2U; i++) {
            uint32_t a = vr_be32(ctx, insn->ra, base + i);
            uint32_t b = vr_be32(ctx, insn->rb, base + i);

            tmp[8U * i] = (uint8_t)(a >> 24);
            tmp[8U * i + 1U] = (uint8_t)(a >> 16);
            tmp[8U * i + 2U] = (uint8_t)(a >> 8);
            tmp[8U * i + 3U] = (uint8_t)a;
            tmp[8U * i + 4U] = (uint8_t)(b >> 24);
            tmp[8U * i + 5U] = (uint8_t)(b >> 16);
            tmp[8U * i + 6U] = (uint8_t)(b >> 8);
            tmp[8U * i + 7U] = (uint8_t)b;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    ctx->nip += 4U;
}

/* Per-element shifts/rotates: the count comes from the matching lane
 * of vB (& 7 / & 15 / & 31); rotates guard n == 0 (shifting a
 * 32-bit word by 32 is UB). vsl/vsr shift the whole 128-bit quadword
 * by 0..7 bits; vslo/vsro shift by 0..15 whole bytes. */
static void vmx_shift(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t lane;

    switch (x) {
    case 260u:
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t n = ctx->vr[insn->rb & 31U][lane] & 7U;

            ctx->vr[insn->rt & 31U][lane] =
                (uint8_t)(ctx->vr[insn->ra & 31U][lane] << n);
        }
        break;
    case 324u:
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t n = vr_be16(ctx, insn->rb, lane) & 15U;

            vr_set_be16(ctx, insn->rt, lane,
                (uint16_t)(vr_be16(ctx, insn->ra, lane) << n));
        }
        break;
    case 388u:
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t n = vr_be32(ctx, insn->rb, lane) & 31U;

            vr_set_be32(ctx, insn->rt, lane,
                vr_be32(ctx, insn->ra, lane) << n);
        }
        break;
    case 516u:
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t n = ctx->vr[insn->rb & 31U][lane] & 7U;

            ctx->vr[insn->rt & 31U][lane] =
                (uint8_t)(ctx->vr[insn->ra & 31U][lane] >> n);
        }
        break;
    case 580u:
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t n = vr_be16(ctx, insn->rb, lane) & 15U;

            vr_set_be16(ctx, insn->rt, lane,
                (uint16_t)(vr_be16(ctx, insn->ra, lane) >> n));
        }
        break;
    case 644u:
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t n = vr_be32(ctx, insn->rb, lane) & 31U;

            vr_set_be32(ctx, insn->rt, lane,
                vr_be32(ctx, insn->ra, lane) >> n);
        }
        break;
    case 772u:
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t n = ctx->vr[insn->rb & 31U][lane] & 7U;
            uint32_t v = ctx->vr[insn->ra & 31U][lane];

            if ((v & 0x80U) != 0U) {
                v |= ~0xFFU;
            }
            ctx->vr[insn->rt & 31U][lane] =
                (uint8_t)((int32_t)v >> n);
        }
        break;
    case 836u:
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t n = vr_be16(ctx, insn->rb, lane) & 15U;
            uint32_t v = vr_be16(ctx, insn->ra, lane);
            int32_t s = (v & 0x8000U) != 0U ? (int32_t)v - 65536 :
                (int32_t)v;

            vr_set_be16(ctx, insn->rt, lane, (uint16_t)(s >> n));
        }
        break;
    case 900u:
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t n = vr_be32(ctx, insn->rb, lane) & 31U;

            vr_set_be32(ctx, insn->rt, lane,
                (uint32_t)((int32_t)vr_be32(ctx, insn->ra, lane) >>
                n));
        }
        break;
    case 4u:
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t n = ctx->vr[insn->rb & 31U][lane] & 7U;
            uint32_t v = ctx->vr[insn->ra & 31U][lane];

            ctx->vr[insn->rt & 31U][lane] = (n == 0U) ? (uint8_t)v :
                (uint8_t)((v << n) | (v >> (8U - n)));
        }
        break;
    case 68u:
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t n = vr_be16(ctx, insn->rb, lane) & 15U;
            uint32_t v = vr_be16(ctx, insn->ra, lane);

            vr_set_be16(ctx, insn->rt, lane, (n == 0U) ? (uint16_t)v :
                (uint16_t)((v << n) | (v >> (16U - n))));
        }
        break;
    case 132u:
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t n = vr_be32(ctx, insn->rb, lane) & 31U;
            uint32_t v = vr_be32(ctx, insn->ra, lane);

            vr_set_be32(ctx, insn->rt, lane, (n == 0U) ? v :
                (v << n) | (v >> (32U - n)));
        }
        break;
    case 452u: {
        /* vsl: 128-bit quadword shifted left by (vB[15] & 7) bits. */
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 7U;
        uint8_t tmp[16];
        uint32_t carry = 0U;

        for (lane = 0U; lane < 16U; lane++) {
            uint32_t idx = 15U - lane;
            uint32_t v = ((uint32_t)ctx->vr[insn->ra & 31U][idx] << n) |
                carry;

            tmp[idx] = (uint8_t)v;
            carry = (n == 0U) ? 0U :
                ((uint32_t)ctx->vr[insn->ra & 31U][idx] >>
                (8U - n)) & ((1U << n) - 1U);
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    case 708u: {
        /* vsr: 128-bit quadword shifted right by (vB[15] & 7) bits. */
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 7U;
        uint8_t tmp[16];
        uint32_t carry = 0U;

        for (lane = 0U; lane < 16U; lane++) {
            uint32_t v = ((uint32_t)ctx->vr[insn->ra & 31U][lane] >>
                n) | carry;

            tmp[lane] = (uint8_t)v;
            carry = (n == 0U) ? 0U :
                (((uint32_t)ctx->vr[insn->ra & 31U][lane] <<
                (8U - n)) & 0xFFU);
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    case 1036u: {
        /* vslo: shift left by (vB[15] & 15) whole bytes. */
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 15U;
        uint8_t tmp[16];

        for (lane = 0U; lane < 16U; lane++) {
            tmp[lane] = (lane + n < 16U) ?
                ctx->vr[insn->ra & 31U][lane + n] : 0U;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    case 1100u: {
        /* vsro: shift right by (vB[15] & 15) whole bytes. */
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 15U;
        uint8_t tmp[16];

        for (lane = 0U; lane < 16U; lane++) {
            tmp[lane] = (lane < n) ? 0U :
                ctx->vr[insn->ra & 31U][lane - n];
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    ctx->nip += 4U;
}

void ppc32_altivec_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint32_t x = insn->xo;
    uint32_t i;

    if ((x & 63u) == 42u) { /* vsel */
        uint8_t *vd = ctx->vr[insn->rt & 31U];
        const uint8_t *va = ctx->vr[insn->ra & 31U];
        const uint8_t *vb = ctx->vr[insn->rb & 31U];
        const uint8_t *vc = ctx->vr[insn->bi & 31U];

        for (i = 0U; i < 16U; i++) {
            vd[i] = (uint8_t)((va[i] & (uint8_t)~vc[i]) | (vb[i] & vc[i]));
        }
        ctx->nip += 4U;
        return;
    }
    if ((x & 63u) == 43u) { /* vperm */
        uint8_t tmp[16];
        const uint8_t *va = ctx->vr[insn->ra & 31U];
        const uint8_t *vb = ctx->vr[insn->rb & 31U];
        const uint8_t *vc = ctx->vr[insn->bi & 31U];

        for (i = 0U; i < 16U; i++) {
            uint32_t s = vc[i] & 31U;

            if (s < 16U) {
                tmp[i] = va[s];
            } else {
                tmp[i] = vb[s - 16U];
            }
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        ctx->nip += 4U;
        return;
    }
    if ((x & 63u) == 44u) { /* vsldoi */
        uint8_t tmp[16];
        uint32_t sh = insn->bi & 15U;

        for (i = 0U; i < 16U; i++) {
            uint32_t s = i + sh;

            if (s < 16U) {
                tmp[i] = ctx->vr[insn->ra & 31U][s];
            } else {
                tmp[i] = ctx->vr[insn->rb & 31U][s - 16U];
            }
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        ctx->nip += 4U;
        return;
    }
    if ((x & 63u) == 46u || (x & 63u) == 47u) {
        /* vmaddfp (vA * vC + vB) / vnmsubfp (-((vA * vC) - vB)). */
        ppc32_vmx_fp(ctx, insn, (x & 63u) == 46u ? 46u : 47u);
        return;
    }
    if ((x & 63u) == 32u || (x & 63u) == 40u || (x & 63u) == 41u) {
        ppc32_vmx_sum(ctx, insn, x & 63u);
        return;
    }
    {
        /* VXR-form compares: bit 10 of the 11-bit XO is Rc. */
        uint32_t base = x & 0x3FFu;

        if (base == 6u || base == 70u || base == 134u ||
            base == 198u || base == 518u || base == 582u ||
            base == 646u || base == 710u || base == 774u ||
            base == 838u || base == 902u || base == 454u ||
            base == 966u) {
            ppc32_vmx_cmp(ctx, insn, base, (x & 0x400u) != 0U);
            return;
        }
    }
    if (x == 10u || x == 74u || x == 1034u || x == 1098u) {
        ppc32_vmx_fp(ctx, insn, x);
        return;
    }
    if (x == 0u || x == 64u || x == 128u || x == 1024u ||
        x == 1088u || x == 1152u || x == 512u || x == 576u ||
        x == 640u || x == 704u || x == 768u || x == 832u ||
        x == 1536u || x == 1600u || x == 1664u || x == 1728u ||
        x == 1792u || x == 1856u) {
        ppc32_vmx_addsub(ctx, insn, x);
        return;
    }
    if (x == 1028u || x == 1092u || x == 1156u || x == 1220u ||
        x == 1284u) {
        vmx_logic(ctx, insn, x);
        return;
    }
    if (x == 524u || x == 588u || x == 652u || x == 780u ||
        x == 844u || x == 908u) {
        vmx_splat(ctx, insn, x);
        return;
    }
    if (x == 12u || x == 76u || x == 140u || x == 268u ||
        x == 332u || x == 396u) {
        vmx_merge(ctx, insn, x);
        return;
    }
    if (x == 14u || x == 78u || x == 142u || x == 206u ||
        x == 270u || x == 334u || x == 398u || x == 462u ||
        x == 782u) {
        ppc32_vmx_pack(ctx, insn, x);
        return;
    }
    if (x == 526u || x == 590u || x == 654u || x == 718u ||
        x == 846u || x == 974u) {
        ppc32_vmx_unpack(ctx, insn, x);
        return;
    }
    if (x == 4u || x == 68u || x == 132u || x == 260u ||
        x == 324u || x == 388u || x == 452u || x == 516u ||
        x == 580u || x == 644u || x == 708u || x == 772u ||
        x == 836u || x == 900u || x == 1036u || x == 1100u) {
        vmx_shift(ctx, insn, x);
        return;
    }
    if (x == 1540u) { /* mfvscr */
        memset(ctx->vr[insn->rt & 31U], 0, 12);
        vr_set_be32(ctx, insn->rt, 3, ctx->vscr);
        ctx->nip += 4U;
        return;
    }
    if (x == 1604u) { /* mtvscr: only NJ and SAT are architected */
        ctx->vscr = vr_be32(ctx, insn->rb, 3) & 0x00010001U;
        ctx->nip += 4U;
        return;
    }
    ctx->exit_reason = PPC32_EXIT_UNDEF;
}
