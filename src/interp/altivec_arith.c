/*
 * src/interp/altivec_arith.c — G4 AltiVec arithmetic/compare/pack (G04)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exact-XO companions to ppc32_altivec_step (src/interp/altivec.c):
 * modulo add/sub, saturating add/sub (VSCR.SAT on saturation), FP
 * arithmetic (single-rounding fmaf, VSCR.NJ denormal flushing),
 * vmaxfp/vminfp, all compare families (Rc -> CR6), exact pack/unpack
 * (16-byte tmp so vD==vA/vB never clobbers inputs), and the VA-form
 * multiply-sum group (vmladduhm/vmsumubm/vmsummbm).
 *
 * Saturating XOs (VX-form): unsigned adds 512/576/640, signed adds
 * 704/768/832, unsigned subs 1536/1600/1664, signed subs
 * 1728/1792/1856. VA-form sum XOs (low 6 bits): 32 vmladduhm,
 * 40 vmsumubm, 41 vmsummbm. vpkpx 782 packs words to 1-5-5-5 pixels;
 * vupkhpx 846 / vupklpx 974 unpack pixels to words.
 */

#include <math.h>
#include <stdbool.h>
#include <stdint.h>

#include "interp/altivec.h"
#include "interp/interp.h"

void ppc32_vmx_addsub(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t lane;

    switch (x) {
    case 0u:
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t a = ctx->vr[insn->ra & 31U][lane];
            uint32_t b = ctx->vr[insn->rb & 31U][lane];

            ctx->vr[insn->rt & 31U][lane] = (uint8_t)(a + b);
        }
        break;
    case 64u:
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t a = vr_be16(ctx, insn->ra, lane);
            uint32_t b = vr_be16(ctx, insn->rb, lane);

            vr_set_be16(ctx, insn->rt, lane, (uint16_t)(a + b));
        }
        break;
    case 128u:
        for (lane = 0U; lane < 4U; lane++) {
            vr_set_be32(ctx, insn->rt, lane,
                vr_be32(ctx, insn->ra, lane) + vr_be32(ctx, insn->rb, lane));
        }
        break;
    case 1024u:
        for (lane = 0U; lane < 16U; lane++) {
            uint32_t a = ctx->vr[insn->ra & 31U][lane];
            uint32_t b = ctx->vr[insn->rb & 31U][lane];

            ctx->vr[insn->rt & 31U][lane] = (uint8_t)(a - b);
        }
        break;
    case 1088u:
        for (lane = 0U; lane < 8U; lane++) {
            uint32_t a = vr_be16(ctx, insn->ra, lane);
            uint32_t b = vr_be16(ctx, insn->rb, lane);

            vr_set_be16(ctx, insn->rt, lane, (uint16_t)(a - b));
        }
        break;
    case 1152u:
        for (lane = 0U; lane < 4U; lane++) {
            vr_set_be32(ctx, insn->rt, lane,
                vr_be32(ctx, insn->ra, lane) - vr_be32(ctx, insn->rb, lane));
        }
        break;
    case 512u:
    case 576u:
    case 640u:
    case 704u:
    case 768u:
    case 832u: {
        bool is_byte = (x == 512u || x == 704u);
        bool is_half = (x == 576u || x == 768u);
        bool is_signed = (x >= 704u);

        for (lane = 0U; lane < (is_byte ? 16U : (is_half ? 8U : 4U));
            lane++) {
            if (is_byte) {
                uint32_t a = ctx->vr[insn->ra & 31U][lane];
                uint32_t b = ctx->vr[insn->rb & 31U][lane];
                int32_t sa = ((a & 0x80U) != 0U && is_signed) ?
                    (int32_t)a - 256 : (int32_t)a;
                int32_t sb = ((b & 0x80U) != 0U && is_signed) ?
                    (int32_t)b - 256 : (int32_t)b;
                int32_t s = sa + sb;
                if (is_signed) {
                    if (s > 127) {
                        s = 127;
                        ctx->vscr |= 1U;
                    } else if (s < -128) {
                        s = -128;
                        ctx->vscr |= 1U;
                    }
                } else if (s > 255) {
                    s = 255;
                    ctx->vscr |= 1U;
                } else if (s < 0) {
                    s = 0;
                    ctx->vscr |= 1U;
                }
                ctx->vr[insn->rt & 31U][lane] = (uint8_t)s;
            } else if (is_half) {
                uint32_t a = vr_be16(ctx, insn->ra, lane);
                uint32_t b = vr_be16(ctx, insn->rb, lane);
                int32_t sa = is_signed ?
                    (int32_t)(a & 0x8000U ? a - 65536U : a) : (int32_t)a;
                int32_t sb = is_signed ?
                    (int32_t)(b & 0x8000U ? b - 65536U : b) : (int32_t)b;
                int32_t s = sa + sb;

                if (is_signed) {
                    if (s > 32767) {
                        s = 32767;
                        ctx->vscr |= 1U;
                    } else if (s < -32768) {
                        s = -32768;
                        ctx->vscr |= 1U;
                    }
                } else if (s > 65535) {
                    s = 65535;
                    ctx->vscr |= 1U;
                } else if (s < 0) {
                    s = 0;
                    ctx->vscr |= 1U;
                }
                vr_set_be16(ctx, insn->rt, lane, (uint16_t)s);
            } else {
                uint32_t a = vr_be32(ctx, insn->ra, lane);
                uint32_t b = vr_be32(ctx, insn->rb, lane);

                if (is_signed) {
                    int64_t s = (int64_t)(int32_t)a + (int64_t)(int32_t)b;

                    if (s > 2147483647LL) {
                        s = 2147483647LL;
                        ctx->vscr |= 1U;
                    } else if (s < -2147483648LL) {
                        s = -2147483648LL;
                        ctx->vscr |= 1U;
                    }
                    vr_set_be32(ctx, insn->rt, lane, (uint32_t)(int32_t)s);
                } else {
                    uint64_t s = (uint64_t)a + (uint64_t)b;

                    if (s > 4294967295ULL) {
                        s = 4294967295ULL;
                        ctx->vscr |= 1U;
                    }
                    vr_set_be32(ctx, insn->rt, lane, (uint32_t)s);
                }
            }
        }
        break;
    }
    case 1536u:
    case 1600u:
    case 1664u:
    case 1728u:
    case 1792u:
    case 1856u: {
        bool is_byte = (x == 1536u || x == 1728u);
        bool is_half = (x == 1600u || x == 1792u);
        bool is_signed = (x >= 1728u);

        for (lane = 0U; lane < (is_byte ? 16U : (is_half ? 8U : 4U));
            lane++) {
            if (is_byte) {
                uint32_t a = ctx->vr[insn->ra & 31U][lane];
                uint32_t b = ctx->vr[insn->rb & 31U][lane];
                int32_t sa = is_signed ?
                    ((a & 0x80U) != 0U ? (int32_t)a - 256 : (int32_t)a) :
                    (int32_t)a;
                int32_t sb = is_signed ?
                    ((b & 0x80U) != 0U ? (int32_t)b - 256 : (int32_t)b) :
                    (int32_t)b;
                int32_t s = sa - sb;

                if (is_signed) {
                    if (s > 127) {
                        s = 127;
                        ctx->vscr |= 1U;
                    } else if (s < -128) {
                        s = -128;
                        ctx->vscr |= 1U;
                    }
                } else if (s > 255) {
                    s = 255;
                    ctx->vscr |= 1U;
                } else if (s < 0) {
                    s = 0;
                    ctx->vscr |= 1U;
                }
                ctx->vr[insn->rt & 31U][lane] = (uint8_t)s;
            } else if (is_half) {
                uint32_t a = vr_be16(ctx, insn->ra, lane);
                uint32_t b = vr_be16(ctx, insn->rb, lane);
                int32_t sa = is_signed ?
                    (int32_t)(a & 0x8000U ? a - 65536U : a) : (int32_t)a;
                int32_t sb = is_signed ?
                    (int32_t)(b & 0x8000U ? b - 65536U : b) : (int32_t)b;
                int32_t s = sa - sb;

                if (is_signed) {
                    if (s > 32767) {
                        s = 32767;
                        ctx->vscr |= 1U;
                    } else if (s < -32768) {
                        s = -32768;
                        ctx->vscr |= 1U;
                    }
                } else if (s > 65535) {
                    s = 65535;
                    ctx->vscr |= 1U;
                } else if (s < 0) {
                    s = 0;
                    ctx->vscr |= 1U;
                }
                vr_set_be16(ctx, insn->rt, lane, (uint16_t)s);
            } else {
                uint32_t a = vr_be32(ctx, insn->ra, lane);
                uint32_t b = vr_be32(ctx, insn->rb, lane);

                if (is_signed) {
                    int64_t s = (int64_t)(int32_t)a - (int64_t)(int32_t)b;

                    if (s > 2147483647LL) {
                        s = 2147483647LL;
                        ctx->vscr |= 1U;
                    } else if (s < -2147483648LL) {
                        s = -2147483648LL;
                        ctx->vscr |= 1U;
                    }
                    vr_set_be32(ctx, insn->rt, lane, (uint32_t)(int32_t)s);
                } else {
                    int64_t s = (int64_t)a - (int64_t)b;

                    if (s > 4294967295LL) {
                        s = 4294967295LL;
                        ctx->vscr |= 1U;
                    } else if (s < 0) {
                        s = 0;
                        ctx->vscr |= 1U;
                    }
                    vr_set_be32(ctx, insn->rt, lane, (uint32_t)s);
                }
            }
        }
        break;
    }
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    ctx->nip += 4U;
}

void ppc32_vmx_fp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn, uint32_t x)
{
    uint32_t lane;

    if (x == 10u || x == 74u) {
        for (lane = 0U; lane < 4U; lane++) {
            float a = vmx_nj_flush(ctx, vr_f32(ctx, insn->ra, lane));
            float b = vmx_nj_flush(ctx, vr_f32(ctx, insn->rb, lane));

            vr_set_f32(ctx, insn->rt, lane,
                vmx_nj_flush(ctx, x == 10u ? a + b : a - b));
        }
        ctx->nip += 4U;
        return;
    }
    if (x == 1034u || x == 1098u) {
        for (lane = 0U; lane < 4U; lane++) {
            float a = vmx_nj_flush(ctx, vr_f32(ctx, insn->ra, lane));
            float b = vmx_nj_flush(ctx, vr_f32(ctx, insn->rb, lane));

            vr_set_f32(ctx, insn->rt, lane, vmx_nj_flush(ctx,
                x == 1034u ? fmaxf(a, b) : fminf(a, b)));
        }
        ctx->nip += 4U;
        return;
    }
    {
        /* VA-form: vD = vA * vC + vB (single rounding via fmaf) and
         * vD = -((vA * vC) - vB). vC rides in bits 21..25 (bi). */
        uint32_t vc = insn->bi & 31U;

        for (lane = 0U; lane < 4U; lane++) {
            float a = vmx_nj_flush(ctx, vr_f32(ctx, insn->ra, lane));
            float b = vmx_nj_flush(ctx, vr_f32(ctx, insn->rb, lane));
            float c = vmx_nj_flush(ctx, vr_f32(ctx, vc, lane));

            if (x == 46u) {
                vr_set_f32(ctx, insn->rt, lane,
                    vmx_nj_flush(ctx, fmaf(a, c, b)));
            } else if (x == 47u) {
                vr_set_f32(ctx, insn->rt, lane,
                    vmx_nj_flush(ctx, -fmaf(a, c, -b)));
            } else {
                ctx->exit_reason = PPC32_EXIT_UNDEF;
                return;
            }
        }
        ctx->nip += 4U;
    }
}

void ppc32_vmx_cmp(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t base, bool rc)
{
    bool all_true = true;
    bool all_false = true;
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
                t = vmx_gt_s8(a, b);
            }
            ctx->vr[insn->rt & 31U][lane] = t ? 0xFFU : 0x00U;
            all_true = all_true && t;
            all_false = all_false && !t;
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
                t = vmx_gt_s16((uint16_t)a, (uint16_t)b);
            }
            vr_set_be16(ctx, insn->rt, lane, t ? 0xFFFFU : 0U);
            all_true = all_true && t;
            all_false = all_false && !t;
        }
    } else if (base == 134u || base == 646u || base == 902u) {
        for (lane = 0U; lane < 4U; lane++) {
            uint32_t a = vr_be32(ctx, insn->ra, lane);
            uint32_t b = vr_be32(ctx, insn->rb, lane);
            bool t;

            if (base == 134u) {
                t = (a == b);
            } else if (base == 646u) {
                t = (a > b);
            } else {
                t = vmx_gt_s32(a, b);
            }
            vr_set_be32(ctx, insn->rt, lane, t ? 0xFFFFFFFFU : 0U);
            all_true = all_true && t;
            all_false = all_false && !t;
        }
    } else {
        /* FP compares: vcmpeqfp 198, vcmpgefp 454, vcmpgtfp 710,
         * vcmpbfp 966. NaN is unordered (eq/gt/ge all false). vcmpbfp
         * writes all-ones when vB escapes [-vA, +vA] (or either side
         * is NaN), zeros when in bounds. */
        for (lane = 0U; lane < 4U; lane++) {
            float a = vr_f32(ctx, insn->ra, lane);
            float b = vr_f32(ctx, insn->rb, lane);
            bool t;

            if (base == 198u) {
                t = (a == b);
            } else if (base == 710u) {
                t = (a > b);
            } else if (base == 454u) {
                t = (a >= b);
            } else {
                bool oob = isnan(a) || isnan(b) || (b < -a) || (b > a);

                t = oob;
            }
            vr_set_be32(ctx, insn->rt, lane, t ? 0xFFFFFFFFU : 0U);
            all_true = all_true && t;
            all_false = all_false && !t;
        }
    }
    if (rc) {
        vr_set_cr6(ctx, all_true, all_false);
    }
    ctx->nip += 4U;
}

void ppc32_vmx_pack(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t i;
    uint8_t tmp[16];

    switch (x) {
    case 14u:
        for (i = 0U; i < 8U; i++) {
            uint32_t a = vr_be16(ctx, insn->ra, i);
            uint32_t b = vr_be16(ctx, insn->rb, i);

            tmp[i] = (uint8_t)a;
            tmp[8U + i] = (uint8_t)b;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 78u:
        for (i = 0U; i < 4U; i++) {
            uint32_t a = vr_be32(ctx, insn->ra, i);
            uint32_t b = vr_be32(ctx, insn->rb, i);

            tmp[i * 2U] = (uint8_t)(a >> 8);
            tmp[i * 2U + 1U] = (uint8_t)a;
            tmp[8U + i * 2U] = (uint8_t)(b >> 8);
            tmp[8U + i * 2U + 1U] = (uint8_t)b;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 142u:
        /* vpkuhus: unsigned halfwords, unsigned saturation (only the
         * top clamp can fire). */
        for (i = 0U; i < 8U; i++) {
            uint32_t a = vr_be16(ctx, insn->ra, i);
            uint32_t b = vr_be16(ctx, insn->rb, i);

            if (a > 255U) {
                a = 255U;
                ctx->vscr |= 1U;
            }
            if (b > 255U) {
                b = 255U;
                ctx->vscr |= 1U;
            }
            tmp[i] = (uint8_t)a;
            tmp[8U + i] = (uint8_t)b;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 206u:
        /* vpkuwus: unsigned words, unsigned saturation. */
        for (i = 0U; i < 4U; i++) {
            uint32_t a = vr_be32(ctx, insn->ra, i);
            uint32_t b = vr_be32(ctx, insn->rb, i);

            if (a > 65535U) {
                a = 65535U;
                ctx->vscr |= 1U;
            }
            if (b > 65535U) {
                b = 65535U;
                ctx->vscr |= 1U;
            }
            tmp[i * 2U] = (uint8_t)(a >> 8);
            tmp[i * 2U + 1U] = (uint8_t)a;
            tmp[8U + i * 2U] = (uint8_t)(b >> 8);
            tmp[8U + i * 2U + 1U] = (uint8_t)b;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 270u:
        for (i = 0U; i < 8U; i++) {
            uint32_t a = vr_be16(ctx, insn->ra, i);
            uint32_t b = vr_be16(ctx, insn->rb, i);
            int32_t sa = (a & 0x8000U) != 0U ? (int32_t)a - 65536 :
                (int32_t)a;
            int32_t sb = (b & 0x8000U) != 0U ? (int32_t)b - 65536 :
                (int32_t)b;

            if (sa > 255) {
                sa = 255;
                ctx->vscr |= 1U;
            } else if (sa < 0) {
                sa = 0;
                ctx->vscr |= 1U;
            }
            if (sb > 255) {
                sb = 255;
                ctx->vscr |= 1U;
            } else if (sb < 0) {
                sb = 0;
                ctx->vscr |= 1U;
            }
            tmp[i] = (uint8_t)sa;
            tmp[8U + i] = (uint8_t)sb;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 334u:
        for (i = 0U; i < 4U; i++) {
            uint32_t a = vr_be32(ctx, insn->ra, i);
            uint32_t b = vr_be32(ctx, insn->rb, i);
            int64_t sa = (int64_t)(int32_t)a;
            int64_t sb = (int64_t)(int32_t)b;

            if (sa > 65535) {
                sa = 65535;
                ctx->vscr |= 1U;
            } else if (sa < 0) {
                sa = 0;
                ctx->vscr |= 1U;
            }
            if (sb > 65535) {
                sb = 65535;
                ctx->vscr |= 1U;
            } else if (sb < 0) {
                sb = 0;
                ctx->vscr |= 1U;
            }
            tmp[i * 2U] = (uint8_t)((uint32_t)sa >> 8);
            tmp[i * 2U + 1U] = (uint8_t)sa;
            tmp[8U + i * 2U] = (uint8_t)((uint32_t)sb >> 8);
            tmp[8U + i * 2U + 1U] = (uint8_t)sb;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 398u:
    case 462u: {
        bool is_byte = (x == 398u);

        for (i = 0U; i < (is_byte ? 8U : 4U); i++) {
            int64_t s;

            if (is_byte) {
                uint32_t a = vr_be16(ctx, insn->ra, i);
                uint32_t b = vr_be16(ctx, insn->rb, i);
                int32_t sa = (a & 0x8000U) != 0U ? (int32_t)a - 65536 :
                    (int32_t)a;
                int32_t sb = (b & 0x8000U) != 0U ? (int32_t)b - 65536 :
                    (int32_t)b;

                if (sa > 127) {
                    sa = 127;
                    ctx->vscr |= 1U;
                } else if (sa < -128) {
                    sa = -128;
                    ctx->vscr |= 1U;
                }
                if (sb > 127) {
                    sb = 127;
                    ctx->vscr |= 1U;
                } else if (sb < -128) {
                    sb = -128;
                    ctx->vscr |= 1U;
                }
                tmp[i] = (uint8_t)sa;
                tmp[8U + i] = (uint8_t)sb;
            } else {
                uint32_t a = vr_be32(ctx, insn->ra, i);
                uint32_t b = vr_be32(ctx, insn->rb, i);

                s = (int64_t)(int32_t)a;
                if (s > 32767) {
                    s = 32767;
                    ctx->vscr |= 1U;
                } else if (s < -32768) {
                    s = -32768;
                    ctx->vscr |= 1U;
                }
                tmp[i * 2U] = (uint8_t)((uint32_t)s >> 8);
                tmp[i * 2U + 1U] = (uint8_t)s;
                s = (int64_t)(int32_t)b;
                if (s > 32767) {
                    s = 32767;
                    ctx->vscr |= 1U;
                } else if (s < -32768) {
                    s = -32768;
                    ctx->vscr |= 1U;
                }
                tmp[8U + i * 2U] = (uint8_t)((uint32_t)s >> 8);
                tmp[8U + i * 2U + 1U] = (uint8_t)s;
            }
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    }
    case 782u: {
        /* vpkpx: words -> 1-5-5-5 pixels (sign bit as alpha). */
        for (i = 0U; i < 4U; i++) {
            uint32_t a = vr_be32(ctx, insn->ra, i);
            uint32_t b = vr_be32(ctx, insn->rb, i);
            uint16_t pa = (uint16_t)(((a & 0x80000000U) != 0U ? 0x8000U :
                0U) | ((a >> 9) & 0x7C00U) | ((a >> 6) & 0x03E0U) |
                ((a >> 3) & 0x001FU));
            uint16_t pb = (uint16_t)(((b & 0x80000000U) != 0U ? 0x8000U :
                0U) | ((b >> 9) & 0x7C00U) | ((b >> 6) & 0x03E0U) |
                ((b >> 3) & 0x001FU));

            tmp[i * 2U] = (uint8_t)(pa >> 8);
            tmp[i * 2U + 1U] = (uint8_t)pa;
            tmp[8U + i * 2U] = (uint8_t)(pb >> 8);
            tmp[8U + i * 2U + 1U] = (uint8_t)pb;
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

void ppc32_vmx_unpack(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t x)
{
    uint32_t i;
    uint8_t tmp[16];

    switch (x) {
    case 526u:
        for (i = 0U; i < 8U; i++) {
            uint32_t s = ctx->vr[insn->rb & 31U][i];
            uint16_t h = (s & 0x80U) != 0U ? (uint16_t)(0xFF00U | s) :
                (uint16_t)s;

            tmp[i * 2U] = (uint8_t)(h >> 8);
            tmp[i * 2U + 1U] = (uint8_t)h;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 590u:
        for (i = 0U; i < 4U; i++) {
            uint32_t h = vr_be16(ctx, insn->rb, i);
            uint32_t w = (h & 0x8000U) != 0U ? 0xFFFF0000U | h : h;

            tmp[i * 4U] = (uint8_t)(w >> 24);
            tmp[i * 4U + 1U] = (uint8_t)(w >> 16);
            tmp[i * 4U + 2U] = (uint8_t)(w >> 8);
            tmp[i * 4U + 3U] = (uint8_t)w;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 654u:
        for (i = 0U; i < 8U; i++) {
            uint32_t s = ctx->vr[insn->rb & 31U][8U + i];
            uint16_t h = (s & 0x80U) != 0U ? (uint16_t)(0xFF00U | s) :
                (uint16_t)s;

            tmp[i * 2U] = (uint8_t)(h >> 8);
            tmp[i * 2U + 1U] = (uint8_t)h;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 718u:
        for (i = 0U; i < 4U; i++) {
            uint32_t h = vr_be16(ctx, insn->rb, 4U + i);
            uint32_t w = (h & 0x8000U) != 0U ? 0xFFFF0000U | h : h;

            tmp[i * 4U] = (uint8_t)(w >> 24);
            tmp[i * 4U + 1U] = (uint8_t)(w >> 16);
            tmp[i * 4U + 2U] = (uint8_t)(w >> 8);
            tmp[i * 4U + 3U] = (uint8_t)w;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        break;
    case 846u:
    case 974u: {
        /* vupkhpx/vupklpx: 1-5-5-5 pixels -> words (5-bit fields
         * expanded to 8 bits, alpha bit replicated to the top byte). */
        uint32_t half = (x == 846u) ? 0U : 4U;

        for (i = 0U; i < 4U; i++) {
            uint32_t px = vr_be16(ctx, insn->rb, half + i);
            uint32_t a = (px & 0x8000U) != 0U ? 0xFFU : 0U;
            uint32_t r = (px >> 10) & 0x1FU;
            uint32_t g = (px >> 5) & 0x1FU;
            uint32_t b = px & 0x1FU;
            uint32_t w = (a << 24) | ((r << 3 | r >> 2) << 16) |
                ((g << 3 | g >> 2) << 8) | (b << 3 | b >> 2);

            tmp[i * 4U] = (uint8_t)(w >> 24);
            tmp[i * 4U + 1U] = (uint8_t)(w >> 16);
            tmp[i * 4U + 2U] = (uint8_t)(w >> 8);
            tmp[i * 4U + 3U] = (uint8_t)w;
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

void ppc32_vmx_sum(ppc32_ctx_t *ctx, const ppc32_insn_t *insn,
    uint32_t low6)
{
    /* VA-form multiply-sum: the 4th operand (addend vector) rides in
     * bits 21..25 (insn->bi). */
    uint32_t vc = insn->bi & 31U;
    uint32_t j;
    uint32_t k;

    if (low6 == 32u) {
        /* vmladduhm: d_hw[i] = a_hw[i] * b_hw[i] + c_hw[i] (mod 2^16). */
        uint8_t tmp[16];

        for (j = 0U; j < 8U; j++) {
            uint32_t p = vr_be16(ctx, insn->ra, j) *
                vr_be16(ctx, insn->rb, j) + vr_be16(ctx, vc, j);

            tmp[j * 2U] = (uint8_t)(p >> 8);
            tmp[j * 2U + 1U] = (uint8_t)p;
        }
        memcpy(ctx->vr[insn->rt & 31U], tmp, 16);
        ctx->nip += 4U;
        return;
    }
    if (low6 == 40u || low6 == 41u) {
        /* vmsumubm/vmsummbm: d_w[j] = sum(a_b[4j+i] * b_b[4j+i]) + c_w[j];
         * unsigned bytes for 40, sign-biased bytes for 41. */
        for (j = 0U; j < 4U; j++) {
            uint32_t acc = vr_be32(ctx, vc, j);

            for (k = 0U; k < 4U; k++) {
                uint32_t a = ctx->vr[insn->ra & 31U][j * 4U + k];
                uint32_t b = ctx->vr[insn->rb & 31U][j * 4U + k];

                if (low6 == 41u) {
                    a ^= 0x80U;
                    b ^= 0x80U;
                }
                acc += a * b;
            }
            vr_set_be32(ctx, insn->rt, j, acc);
        }
        ctx->nip += 4U;
        return;
    }
    ctx->exit_reason = PPC32_EXIT_UNDEF;
}
