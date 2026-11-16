/*
 * src/interp/altivec.c — G4 AltiVec (VMX) reference interpreter (G04)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers the Darwin G4 libSystem / Accelerate / compiler subset from
 * the work order: lvx/lvxl/lvebx/lvehx/lvewx/lvsl/lvsr/stvx/stvxl/
 * stvebx/stvehx/stvewx, dst/dss no-ops (decoded to SYNC), core
 * integer/logical/permute/splat/merge/pack/unpack/sldoi/shift/rotate,
 * vaddubm/hm/wm + vsububm/hm/wm, vaddfp/vsubfp/vmaddfp/vnmsubfp,
 * vcmpeq and vcmpgt families (Rc -> CR6), mtvscr/mfvscr, dcbz/dcba zeroing,
 * dcbf/dcbst/dcbt/dcbtst address-checked no-ops, icbi/isync no-ops.
 *
 * vr[r][0] is the most significant byte (big-endian lane order).
 * Loads/stores use the BE ld/st helpers so Soft-TLB, COW promotion,
 * reservation invalidation, and fault reporting match the integer
 * path exactly. Vector EA for lvx/stvx is aligned down (EA & ~15U).
 */

#include <math.h>
#include <string.h>

#include "interp/altivec.h"
#include "interp/interp.h"

static uint16_t vr_be16(const ppc32_ctx_t *ctx, uint32_t r, uint32_t lane)
{
    const uint8_t *v = ctx->vr[r & 31U];

    return (uint16_t)(((uint16_t)v[lane * 2U] << 8) | v[lane * 2U + 1U]);
}

static void vr_set_be16(ppc32_ctx_t *ctx, uint32_t r, uint32_t lane,
    uint16_t w)
{
    uint8_t *v = ctx->vr[r & 31U];

    v[lane * 2U] = (uint8_t)(w >> 8);
    v[lane * 2U + 1U] = (uint8_t)w;
}

static uint32_t vr_be32(const ppc32_ctx_t *ctx, uint32_t r, uint32_t lane)
{
    const uint8_t *v = ctx->vr[r & 31U];

    return ((uint32_t)v[lane * 4U] << 24) | ((uint32_t)v[lane * 4U + 1U] << 16) |
        ((uint32_t)v[lane * 4U + 2U] << 8) | v[lane * 4U + 3U];
}

static void vr_set_be32(ppc32_ctx_t *ctx, uint32_t r, uint32_t lane,
    uint32_t w)
{
    uint8_t *v = ctx->vr[r & 31U];

    v[lane * 4U] = (uint8_t)(w >> 24);
    v[lane * 4U + 1U] = (uint8_t)(w >> 16);
    v[lane * 4U + 2U] = (uint8_t)(w >> 8);
    v[lane * 4U + 3U] = (uint8_t)w;
}

static float vr_f32(const ppc32_ctx_t *ctx, uint32_t r, uint32_t lane)
{
    uint32_t w = vr_be32(ctx, r, lane);
    float f;

    memcpy(&f, &w, 4);
    return f;
}

static void vr_set_f32(ppc32_ctx_t *ctx, uint32_t r, uint32_t lane, float f)
{
    uint32_t w;

    memcpy(&w, &f, 4);
    vr_set_be32(ctx, r, lane, w);
}

/* CR6 for Rc=1 compares: EQ bit set when every result byte is 0xFF
 * (all lanes true), else zero; SO copied live from XER.SO. */
static void vr_set_cr6(ppc32_ctx_t *ctx, bool all_true)
{
    uint32_t v = 0U;

    if (all_true) {
        v |= 2U;
    }
    v |= (ctx->xer >> 31U) & 1U;
    ctx->cr = (ctx->cr & ~(0xFU << 4)) | (v << 4);
}

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
            st8(ctx, base + i, ctx->vr[insn->rt & 31U][i]);
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
    case 39u: { /* lvehx */
        uint16_t h;

        if (!interp_mem_ok(ea, 2U)) {
            fault(ctx, ea);
            return;
        }
        h = ld16(ctx, ea);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->vr[insn->rt & 31U][ea & 15U] = (uint8_t)(h >> 8);
        ctx->vr[insn->rt & 31U][((ea & 15U) + 1U) & 15U] = (uint8_t)h;
        ctx->nip += 4U;
        return;
    }
    case 71u: { /* lvewx */
        uint32_t w;

        if (!interp_mem_ok(ea, 4U)) {
            fault(ctx, ea);
            return;
        }
        w = ld32(ctx, ea);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->vr[insn->rt & 31U][ea & 15U] = (uint8_t)(w >> 24);
        ctx->vr[insn->rt & 31U][((ea & 15U) + 1U) & 15U] =
            (uint8_t)(w >> 16);
        ctx->vr[insn->rt & 31U][((ea & 15U) + 2U) & 15U] =
            (uint8_t)(w >> 8);
        ctx->vr[insn->rt & 31U][((ea & 15U) + 3U) & 15U] = (uint8_t)w;
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
    case 167u: { /* stvehx */
        uint16_t h = (uint16_t)(((uint16_t)ctx->vr[insn->rs & 31U][ea & 15U] << 8) |
            ctx->vr[insn->rs & 31U][((ea & 15U) + 1U) & 15U]);

        if (!interp_mem_ok(ea, 2U)) {
            fault(ctx, ea);
            ctx->fault_is_store = 1U;
            return;
        }
        st16(ctx, ea, h);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->nip += 4U;
        return;
    }
    case 199u: { /* stvewx */
        uint32_t w = ((uint32_t)ctx->vr[insn->rs & 31U][ea & 15U] << 24) |
            ((uint32_t)ctx->vr[insn->rs & 31U][((ea & 15U) + 1U) & 15U] << 16) |
            ((uint32_t)ctx->vr[insn->rs & 31U][((ea & 15U) + 2U) & 15U] << 8) |
            ctx->vr[insn->rs & 31U][((ea & 15U) + 3U) & 15U];

        if (!interp_mem_ok(ea, 4U)) {
            fault(ctx, ea);
            ctx->fault_is_store = 1U;
            return;
        }
        st32(ctx, ea, w);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        ctx->nip += 4U;
        return;
    }
    case 6u: /* lvsl */
        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = (uint8_t)((ea + i) & 15U);
        }
        ctx->nip += 4U;
        return;
    case 38u: /* lvsr */
        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = (uint8_t)((ea + i) & 15U);
        }
        ctx->nip += 4U;
        return;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
}

static void vmx_logic(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t i;
    uint8_t *vd = ctx->vr[insn->rt & 31U];
    const uint8_t *va = ctx->vr[insn->ra & 31U];
    const uint8_t *vb = ctx->vr[insn->rb & 31U];

    for (i = 0U; i < 16U; i++) {
        switch (base) {
        case 1028u:
            vd[i] = va[i] & vb[i];
            break;
        case 1092u:
            vd[i] = va[i] & (uint8_t)~vb[i];
            break;
        case 1156u:
            vd[i] = va[i] | vb[i];
            break;
        case 1188u:
            vd[i] = va[i] | (uint8_t)~vb[i];
            break;
        case 1220u:
            vd[i] = va[i] ^ vb[i];
            break;
        default:
            vd[i] = (uint8_t)~(va[i] | vb[i]);
            break;
        }
    }
    ctx->nip += 4U;
}

static void vmx_add_sub(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t lane;

    if (base == 0u || base == 1024u) {
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t a = ctx->vr[insn->ra & 31U][lane];
            uint32_t b = ctx->vr[insn->rb & 31U][lane];

            if (base == 0u) {
                ctx->vr[insn->rt & 31U][lane] = (uint8_t)(a + b);
            } else {
                ctx->vr[insn->rt & 31U][lane] = (uint8_t)(a - b);
            }
        }
    } else if (base == 64u || base == 1088u) {
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t a = vr_be16(ctx, insn->ra, lane);
            uint32_t b = vr_be16(ctx, insn->rb, lane);

            if (base == 64u) {
                vr_set_be16(ctx, insn->rt, lane, (uint16_t)(a + b));
            } else {
                vr_set_be16(ctx, insn->rt, lane, (uint16_t)(a - b));
            }
        }
    } else {
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t a = vr_be32(ctx, insn->ra, lane);
            uint32_t b = vr_be32(ctx, insn->rb, lane);

            if (base == 128u) {
                vr_set_be32(ctx, insn->rt, lane, a + b);
            } else {
                vr_set_be32(ctx, insn->rt, lane, a - b);
            }
        }
    }
    ctx->nip += 4U;
}

static void vmx_fp_arith(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t lane;

    if (base == 10u || base == 74u) {
        for (lane = 0U; lane < 4U; lane++) {
            float a = vr_f32(ctx, insn->ra, lane);
            float b = vr_f32(ctx, insn->rb, lane);

            if (base == 10u) {
                vr_set_f32(ctx, insn->rt, lane, a + b);
            } else {
                vr_set_f32(ctx, insn->rt, lane, a - b);
            }
        }
        ctx->nip += 4U;
        return;
    }
    {
        uint32_t vc = insn->bi & 31U;

        for (lane = 0U; lane < 4U; lane++) {
            float a = vr_f32(ctx, insn->ra, lane);
            float b = vr_f32(ctx, insn->rb, lane);
            float c = vr_f32(ctx, vc, lane);

            if (base == 46u) {
                vr_set_f32(ctx, insn->rt, lane, a * b + c);
            } else {
                vr_set_f32(ctx, insn->rt, lane, -(a * b + c));
            }
        }
        ctx->nip += 4U;
    }
}

static void vmx_compare(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    bool all_true = true;
    uint32_t lane;

    if (base == 6u || base == 518u || base == 774u) {
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t a = ctx->vr[insn->ra & 31U][lane];
            uint32_t b = ctx->vr[insn->rb & 31U][lane];
            bool t;

            if (base == 6u) {
                t = (a == b);
            } else if (base == 518u) {
                t = (a > b);
            } else {
                t = ((int8_t)a > (int8_t)b);
            }
            ctx->vr[insn->rt & 31U][lane] = t ? 0xFFU : 0x00U;
            if (!t) {
                all_true = false;
            }
        }
    } else if (base == 70u || base == 582u || base == 838u) {
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t a = vr_be16(ctx, insn->ra, lane);
            uint32_t b = vr_be16(ctx, insn->rb, lane);
            bool t;

            if (base == 70u) {
                t = (a == b);
            } else if (base == 582u) {
                t = (a > b);
            } else {
                t = ((int16_t)a > (int16_t)b);
            }
            vr_set_be16(ctx, insn->rt, lane, t ? 0xFFFFU : 0U);
            if (!t) {
                all_true = false;
            }
        }
    } else {
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t a = vr_be32(ctx, insn->ra, lane);
            uint32_t b = vr_be32(ctx, insn->rb, lane);
            bool t;

            if (base == 134u) {
                t = (a == b);
            } else if (base == 646u) {
                t = (a > b);
            } else {
                t = ((int32_t)a > (int32_t)b);
            }
            vr_set_be32(ctx, insn->rt, lane, t ? 0xFFFFFFFFU : 0U);
            if (!t) {
                all_true = false;
            }
        }
    }
    if (insn->rc != 0U) {
        vr_set_cr6(ctx, all_true);
    }
    ctx->nip += 4U;
}

static void vmx_splat(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t u = insn->ra & 31U;
    uint32_t i;

    if (base == 524u) {
        uint8_t b = ctx->vr[insn->rb & 31U][u & 15U];

        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = b;
        }
    } else if (base == 588u) {
        uint16_t h = vr_be16(ctx, insn->rb, u & 7U);

        for (i = 0U; i < 8U; i++) {
            vr_set_be16(ctx, insn->rt, i, h);
        }
    } else if (base == 652u) {
        uint32_t w = vr_be32(ctx, insn->rb, u & 3U);

        for (i = 0U; i < 4U; i++) {
            vr_set_be32(ctx, insn->rt, i, w);
        }
    } else if (base == 780u) {
        int8_t s = (int8_t)((u & 16U) != 0U ? (u | 0xE0U) : u);

        for (i = 0U; i < 16U; i++) {
            ctx->vr[insn->rt & 31U][i] = (uint8_t)s;
        }
    } else if (base == 844u) {
        int16_t s = (int16_t)((u & 16U) != 0U ? (u | 0xFFE0U) : u);

        for (i = 0U; i < 8U; i++) {
            vr_set_be16(ctx, insn->rt, i, (uint16_t)s);
        }
    } else {
        int32_t s = (int32_t)((u & 16U) != 0U ? (u | 0xFFFFFFE0U) : u);

        for (i = 0U; i < 4U; i++) {
            vr_set_be32(ctx, insn->rt, i, (uint32_t)s);
        }
    }
    ctx->nip += 4U;
}

static void vmx_merge(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t i;

    if (base == 12u || base == 268u) {
        for (i = 0U; i < 8U; i++) {
            uint32_t hi = (base == 12u) ? i : 8U + i;

            ctx->vr[insn->rt & 31U][2U * i] =
                ctx->vr[insn->ra & 31U][hi];
            ctx->vr[insn->rt & 31U][2U * i + 1U] =
                ctx->vr[insn->rb & 31U][hi];
        }
    } else if (base == 76u || base == 332u) {
        for (i = 0U; i < 4U; i++) {
            uint32_t hi = (base == 76u) ? i : 4U + i;

            vr_set_be16(ctx, insn->rt, 2U * i,
                vr_be16(ctx, insn->ra, hi));
            vr_set_be16(ctx, insn->rt, 2U * i + 1U,
                vr_be16(ctx, insn->rb, hi));
        }
    } else {
        for (i = 0U; i < 2U; i++) {
            uint32_t hi = (base == 140u) ? i : 2U + i;

            vr_set_be32(ctx, insn->rt, 2U * i,
                vr_be32(ctx, insn->ra, hi));
            vr_set_be32(ctx, insn->rt, 2U * i + 1U,
                vr_be32(ctx, insn->rb, hi));
        }
    }
    ctx->nip += 4U;
}

static void vmx_pack(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t i;

    if (base == 14u || base == 270u) {
        for (i = 0U; i < 8U; i++) {
            uint32_t a = vr_be16(ctx, insn->ra, i);
            uint32_t b = vr_be16(ctx, insn->rb, i);

            ctx->vr[insn->rt & 31U][i] = (uint8_t)a;
            ctx->vr[insn->rt & 31U][8U + i] = (uint8_t)b;
        }
    } else if (base == 78u || base == 334u) {
        for (i = 0U; i < 4U; i++) {
            uint32_t a = vr_be32(ctx, insn->ra, i);
            uint32_t b = vr_be32(ctx, insn->rb, i);

            vr_set_be16(ctx, insn->rt, i, (uint16_t)a);
            vr_set_be16(ctx, insn->rt, 4U + i, (uint16_t)b);
        }
    } else if (base == 142u || base == 206u) {
        for (i = 0U; i < 8U; i++) {
            uint32_t a = vr_be16(ctx, insn->ra, i);
            uint32_t b = vr_be16(ctx, insn->rb, i);
            int32_t sa = (int16_t)a;
            int32_t sb = (int16_t)b;

            if (sa > 127) {
                sa = 127;
            } else if (sa < -128) {
                sa = -128;
            }
            if (sb > 127) {
                sb = 127;
            } else if (sb < -128) {
                sb = -128;
            }
            ctx->vr[insn->rt & 31U][i] = (uint8_t)sa;
            ctx->vr[insn->rt & 31U][8U + i] = (uint8_t)sb;
        }
    } else {
        for (i = 0U; i < 16U; i++) {
            uint32_t src = (i < 8U) ? insn->ra : insn->rb;
            uint32_t lane = (i < 8U) ? i : i - 8U;

            if ((base & 64U) != 0U) {
                vr_set_be16(ctx, insn->rt, i,
                    (uint16_t)ctx->vr[src & 31U][lane]);
            } else {
                vr_set_be32(ctx, insn->rt, i / 4U,
                    ((uint32_t)ctx->vr[src & 31U][lane * 2U] << 24) |
                    ((uint32_t)ctx->vr[src & 31U][lane * 2U + 1U] << 16));
                i += 3U;
            }
        }
    }
    ctx->nip += 4U;
}

static void vmx_unpack(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t i;

    if (base == 398u || base == 526u) {
        uint32_t half = (base == 398u) ? 0U : 8U;

        for (i = 0U; i < 8U; i++) {
            int8_t s =
                (int8_t)ctx->vr[insn->rb & 31U][half + i];

            vr_set_be16(ctx, insn->rt, i, (uint16_t)(int16_t)s);
        }
    } else {
        uint32_t half = (base == 462u) ? 0U : 4U;

        for (i = 0U; i < 4U; i++) {
            int16_t s = (int16_t)vr_be16(ctx, insn->rb, half + i);

            vr_set_be32(ctx, insn->rt, i, (uint32_t)(int32_t)s);
        }
    }
    ctx->nip += 4U;
}

static void vmx_shift(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base)
{
    uint32_t lane;

    if (base == 196u || base == 198u || base == 200u) {
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 7U;

        if (base == 196u) {
            for (lane = 0U; lane < 16U; lane++) {
                ctx->vr[insn->rt & 31U][lane] =
                    (uint8_t)(ctx->vr[insn->ra & 31U][lane] << n);
            }
        } else if (base == 198u) {
            for (lane = 0U; lane < 8U; lane++) {
                vr_set_be16(ctx, insn->rt, lane,
                    (uint16_t)(vr_be16(ctx, insn->ra, lane) << n));
            }
        } else {
            for (lane = 0U; lane < 4U; lane++) {
                vr_set_be32(ctx, insn->rt, lane,
                    vr_be32(ctx, insn->ra, lane) << n);
            }
        }
    } else if (base == 202u || base == 204u || base == 262u) {
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 7U;

        if (base == 202u) {
            for (lane = 0U; lane < 16U; lane++) {
                ctx->vr[insn->rt & 31U][lane] =
                    (uint8_t)(ctx->vr[insn->ra & 31U][lane] >> n);
            }
        } else if (base == 204u) {
            for (lane = 0U; lane < 8U; lane++) {
                vr_set_be16(ctx, insn->rt, lane,
                    (uint16_t)(vr_be16(ctx, insn->ra, lane) >> n));
            }
        } else {
            for (lane = 0U; lane < 4U; lane++) {
                vr_set_be32(ctx, insn->rt, lane,
                    vr_be32(ctx, insn->ra, lane) >> n);
            }
        }
    } else if (base == 264u || base == 266u || base == 272u) {
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 7U;

        if (base == 264u) {
            for (lane = 0U; lane < 16U; lane++) {
                ctx->vr[insn->rt & 31U][lane] = (uint8_t)
                    ((int8_t)ctx->vr[insn->ra & 31U][lane] >> n);
            }
        } else if (base == 266u) {
            for (lane = 0U; lane < 8U; lane++) {
                vr_set_be16(ctx, insn->rt, lane,
                    (uint16_t)((int16_t)vr_be16(ctx, insn->ra,
                    lane) >> n));
            }
        } else {
            for (lane = 0U; lane < 4U; lane++) {
                vr_set_be32(ctx, insn->rt, lane,
                    (uint32_t)((int32_t)vr_be32(ctx, insn->ra,
                    lane) >> n));
            }
        }
    } else {
        uint32_t n = ctx->vr[insn->rb & 31U][15] & 7U;

        if (base == 274u) {
            for (lane = 0U; lane < 16U; lane++) {
                uint32_t v = ctx->vr[insn->ra & 31U][lane];

                ctx->vr[insn->rt & 31U][lane] =
                    (uint8_t)((v << n) | (v >> (8U - n)));
            }
        } else if (base == 276u) {
            for (lane = 0U; lane < 8U; lane++) {
                uint32_t v = vr_be16(ctx, insn->ra, lane);

                n &= 15U;
                vr_set_be16(ctx, insn->rt, lane,
                    (uint16_t)((v << n) | (v >> (16U - n))));
            }
        } else {
            for (lane = 0U; lane < 4U; lane++) {
                uint32_t v = vr_be32(ctx, insn->ra, lane);

                n &= 31U;
                vr_set_be32(ctx, insn->rt, lane,
                    (v << n) | (v >> (32U - n)));
            }
        }
    }
    ctx->nip += 4U;
}

void ppc32_altivec_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint32_t x = insn->xo;
    uint32_t base = x & ~1u;
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
        vmx_fp_arith(ctx, insn, (x & 63u) == 46u ? 46u : 110u);
        return;
    }
    if (base == 10u || base == 74u) {
        vmx_fp_arith(ctx, insn, base);
        return;
    }
    if (base == 0u || base == 64u || base == 128u || base == 1024u ||
        base == 1088u || base == 1152u) {
        vmx_add_sub(ctx, insn, base);
        return;
    }
    if (base == 1028u || base == 1092u || base == 1156u ||
        base == 1188u || base == 1220u || base == 1284u) {
        vmx_logic(ctx, insn, base);
        return;
    }
    if (base == 6u || base == 70u || base == 134u || base == 518u ||
        base == 582u || base == 646u || base == 774u || base == 838u ||
        base == 902u) {
        vmx_compare(ctx, insn, base);
        return;
    }
    if (base == 524u || base == 588u || base == 652u || base == 780u ||
        base == 844u || base == 908u) {
        vmx_splat(ctx, insn, base);
        return;
    }
    if (base == 12u || base == 76u || base == 140u || base == 268u ||
        base == 332u || base == 396u) {
        vmx_merge(ctx, insn, base);
        return;
    }
    if (base == 14u || base == 78u || base == 142u || base == 206u ||
        base == 270u || base == 334u) {
        vmx_pack(ctx, insn, base);
        return;
    }
    if (base == 398u || base == 462u || base == 526u || base == 590u) {
        vmx_unpack(ctx, insn, base);
        return;
    }
    if (base == 196u || base == 198u || base == 200u || base == 202u ||
        base == 204u || base == 262u || base == 264u || base == 266u ||
        base == 272u || base == 274u || base == 276u || base == 278u) {
        vmx_shift(ctx, insn, base);
        return;
    }
    if (base == 1540u) { /* mfvscr */
        memset(ctx->vr[insn->rt & 31U], 0, 12);
        vr_set_be32(ctx, insn->rt, 3, ctx->vscr);
        ctx->nip += 4U;
        return;
    }
    if (base == 1604u) { /* mtvscr */
        ctx->vscr = vr_be32(ctx, insn->rb, 3);
        ctx->nip += 4U;
        return;
    }
    ctx->exit_reason = PPC32_EXIT_UNDEF;
}
