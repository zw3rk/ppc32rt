/*
 * src/interp/fp_spe.h — e500v2 SPE helpers and FPU/SPE XO opcode constants
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Included by src/interp/fp.h after the IEEE-754 classic FPU inline helpers.
 */
#ifndef PPC32_FP_SPE_H
#define PPC32_FP_SPE_H

/* SPE converts (qemu helpers/macros). single ct*: QNaN->0 else
 * invalid->max; double ct*: any-NaN->0. P32-R7-11: signed fractions
 * scale by 2^31, unsigned by 2^32. P32-R7-13: FRMC rounding applies
 * (non-z forms round per FRMC, z forms truncate) and sticky status
 * (FINV on NaN/range failure, FINXS on inexact) is recorded.
 * Scalar cf* yield 32-bit singles, efdcf* 64-bit doubles, efscfd
 * narrows a double to a single in lo, efdcfs widens a single to a
 * double. op: 0 ctsi, 1 ctui, 2 ctsiz, 3 ctuiz, 4 ctsf, 5 ctuf,
 * 6 cfsi, 7 cfui, 8 cfsf, 9 cfuf, 10 cfd/cfs. Callers write lo-only
 * for 32-bit-out (hi preserved via split storage). */
static inline uint64_t fp_spe_cvt(ppc32_ctx_t *ctx, uint64_t in, int op,
    int is_dbl_in)
{
    int old = fegetround();

    if (!is_dbl_in) {
        uint32_t v = (uint32_t)in;
        float f = fp_f32(v);
        uint64_t r;

        if (op <= 5) {
            int z = (op == 2 || op == 3);
            int is_signed = (op == 0 || op == 2 || op == 4);
            float s = f;
            float rr;

            if (fp_snan(v)) {
                spe_raise(ctx, SPE_FINV | SPE_FINVS);
                if (((v >> 22) & 1u) != 0u) {
                    fesetround(old);
                    return 0u; /* single QNaN input converts to 0 */
                }
            }
            if (op == 4) {
                s = f * 2147483648.0f;
            } else if (op == 5) {
                s = f * 4294967296.0f;
            }
            if (is_signed) {
                if (s >= 2147483648.0f || s < -2147483648.0f) {
                    spe_raise(ctx, SPE_FINV | SPE_FINVS);
                }
            } else if (s >= 4294967296.0f || s < 0.0f) {
                spe_raise(ctx, SPE_FINV | SPE_FINVS);
            }
            spe_setrn(ctx);
            rr = z ? truncf(s) : rintf(s);
            if (rr != s && !fp_snan(v)) {
                spe_raise(ctx, SPE_FINXS);
            }
            if (op == 0 || op == 2 || op == 4) {
                r = (uint64_t)(uint32_t)fp_f2i(s, z);
            } else {
                r = (uint64_t)(uint32_t)fp_f2u(s, z);
            }
            fesetround(old);
            return r;
        }
        if (op <= 9) {
            float t;

            spe_setrn(ctx);
            feclearexcept(FE_ALL_EXCEPT);
            if (op == 6) {
                t = (float)(int32_t)v;
            } else if (op == 7) {
                t = (float)v;
            } else if (op == 8) {
                t = (float)(int32_t)v / 2147483648.0f;
            } else {
                t = (float)v / 4294967296.0f;
            }
            spe_flags(ctx);
            r = fp_u32(t);
            fesetround(old);
            return r;
        }
        if (fp_snan(v) && ((v >> 22) & 1u) == 0u) {
            spe_raise(ctx, SPE_FINV | SPE_FINVS);
            v |= 0x400000u;
        }
        fesetround(old);
        return fp_xtod(v);
    }
    {
        double d = fp_f64(in);
        uint64_t r;

        if (op <= 5) {
            int z = (op == 2 || op == 3);
            int is_signed = (op == 0 || op == 2 || op == 4);
            double s = d;
            double rr;

            if (fp_isnan(in)) {
                spe_raise(ctx, SPE_FINV | SPE_FINVS);
                fesetround(old);
                return 0u;
            }
            if (op == 4) {
                s = d * 2147483648.0;
            } else if (op == 5) {
                s = d * 4294967296.0;
            }
            if (is_signed) {
                if (s >= 2147483648.0 || s < -2147483648.0) {
                    spe_raise(ctx, SPE_FINV | SPE_FINVS);
                }
            } else if (s >= 4294967296.0 || s < 0.0) {
                spe_raise(ctx, SPE_FINV | SPE_FINVS);
            }
            spe_setrn(ctx);
            rr = z ? trunc(s) : rint(s);
            if (rr != s) {
                spe_raise(ctx, SPE_FINXS);
            }
            if (is_signed) {
                r = (uint64_t)(uint32_t)fp_d2i(s, z);
            } else {
                r = (uint64_t)(uint32_t)fp_d2u(s, z);
            }
            fesetround(old);
            return r;
        }
        if (op <= 9) {
            double t;

            spe_setrn(ctx);
            feclearexcept(FE_ALL_EXCEPT);
            if (op == 6) {
                t = (double)(int32_t)(uint32_t)in;
            } else if (op == 7) {
                t = (double)(uint32_t)in;
            } else if (op == 8) {
                t = (double)(int32_t)(uint32_t)in / 2147483648.0;
            } else {
                t = (double)(uint32_t)in / 4294967296.0;
            }
            spe_flags(ctx);
            r = fp_u64(t);
            fesetround(old);
            return r;
        }
        {
            uint32_t w;

            if (fp_isnan(in)) {
                if ((in & 0x8000000000000ull) == 0u) {
                    spe_raise(ctx, SPE_FINV | SPE_FINVS);
                }
                w = (uint32_t)(((in >> 29) & 0x7fffffu) | 0x7f800000u |
                    ((in >> 63) << 31) | 0x400000u);
                fesetround(old);
            } else {
                float t;

                spe_setrn(ctx);
                feclearexcept(FE_ALL_EXCEPT);
                t = (float)d;
                spe_flags(ctx);
                w = fp_u32(t);
                fesetround(old);
            }
            return (uint64_t)w;
        }
    }
}

/* Saturating signed 32-bit lane add (P32-R7-10 `sat` forms; P32-R7-13
 * records lane overflow in SPEFSCR). */
static inline uint32_t fp_mac_sat_add(ppc32_ctx_t *ctx, uint32_t x,
    uint32_t y, int high)
{
    int64_t sum = (int64_t)(int32_t)x + (int64_t)(int32_t)y;

    if (sum > 2147483647ll) {
        spe_raise(ctx, high ? (SPE_SOVH | SPE_OVH) : (SPE_SOV | SPE_OV));
        return 0x7fffffffu;
    }
    if (sum < -2147483648ll) {
        spe_raise(ctx, high ? (SPE_SOVH | SPE_OVH) : (SPE_SOV | SPE_OV));
        return 0x80000000u;
    }
    return (uint32_t)(int32_t)sum;
}

/* One whole-word MAC lane (P32-R7-10): the lane's own 32x32 product is
 * formed (never the neighbor lane's); fractional products scale by
 * >>31 with the -1*-1 special case, integer products select the high
 * (MWH) or low (MWL) 32 bits. Saturation records lane overflow. */
static inline uint32_t fp_mac_lane(ppc32_ctx_t *ctx, uint64_t prod, int f,
    int sat, int high)
{
    uint32_t ov = high ? (SPE_SOVH | SPE_OVH) : (SPE_SOV | SPE_OV);

    if (f) {
        if (prod == 0x4000000000000000ull) {
            if (sat) {
                spe_raise(ctx, ov);
                return 0x7fffffffu;
            }
            return 0x80000000u;
        }
        {
            int64_t t = (int64_t)prod >> 31;

            if (sat) {
                if (t > 2147483647ll) {
                    spe_raise(ctx, ov);
                    return 0x7fffffffu;
                }
                if (t < -2147483648ll) {
                    spe_raise(ctx, ov);
                    return 0x80000000u;
                }
            }
            return (uint32_t)(int32_t)t;
        }
    }
    return high ? (uint32_t)(prod >> 32) : (uint32_t)prod;
}

/* SPE MAC (EREF-best-effort; qemu-ppc SIGILLs all MAC, unverifiable
 * via oracle. Whole-word ops work per 32-bit lane (high word halves
 * and low word halves independently); s=signed, f=fractional,
 * acc=accumulate into rD lanes (and ACC), acp=accumulate into ACC
 * with rD=ACC, sat=saturate, high=high-32 (else low-32),
 * half=guarded-halfword, odd=odd halves (else even). Guarded ops
 * sign/zero-extend the selected halfword products into one 64-bit
 * sum accumulated into ACC (rD=ACC). evmra (rD=rA, ACC=rA) matches
 * qemu. */
static inline uint64_t fp_spe_mac(ppc32_ctx_t *ctx, uint64_t a, uint64_t b,
    uint64_t d, int s, int f, int acc, int acp, int sat, int high, int half,
    int odd)
{
    if (half) {
        uint32_t a0 = (uint32_t)((a >> (odd ? 32u : 48u)) & 0xffffu);
        uint32_t a1 = (uint32_t)((a >> (odd ? 0u : 16u)) & 0xffffu);
        uint32_t b0 = (uint32_t)((b >> (odd ? 32u : 48u)) & 0xffffu);
        uint32_t b1 = (uint32_t)((b >> (odd ? 0u : 16u)) & 0xffffu);
        uint64_t sum;

        if (s) {
            int64_t p0 = (int64_t)(int32_t)(int16_t)a0 *
                (int64_t)(int32_t)(int16_t)b0;
            int64_t p1 = (int64_t)(int32_t)(int16_t)a1 *
                (int64_t)(int32_t)(int16_t)b1;

            sum = (uint64_t)(p0 + p1);
        } else {
            sum = (uint64_t)(a0 * b0) + (uint64_t)(a1 * b1);
        }
        if (acp) {
            ctx->acc += sum;
            return ctx->acc;
        }
        {
            uint32_t p0 = s ? (uint32_t)((int32_t)(int16_t)a0 *
                (int32_t)(int16_t)b0) : a0 * b0;
            uint32_t p1 = s ? (uint32_t)((int32_t)(int16_t)a1 *
                (int32_t)(int16_t)b1) : a1 * b1;

            return ((uint64_t)(p0 + (uint32_t)(d >> 32)) << 32) |
                (uint64_t)(p1 + (uint32_t)d);
        }
    }
    {
        uint32_t ah = (uint32_t)(a >> 32);
        uint32_t al = (uint32_t)a;
        uint32_t bh = (uint32_t)(b >> 32);
        uint32_t bl = (uint32_t)b;
        uint64_t ph = s ? (uint64_t)((int64_t)(int32_t)ah *
            (int64_t)(int32_t)bh) : (uint64_t)ah * (uint64_t)bh;
        uint64_t pl = s ? (uint64_t)((int64_t)(int32_t)al *
            (int64_t)(int32_t)bl) : (uint64_t)al * (uint64_t)bl;
        uint32_t selh = fp_mac_lane(ctx, ph, f, sat, high);
        uint32_t sell = fp_mac_lane(ctx, pl, f, sat, high);
        uint64_t res = ((uint64_t)selh << 32) | sell;

        if (acp) {
            if (sat) {
                uint64_t sh = (uint64_t)(uint32_t)(ctx->acc >> 32) + selh;
                uint64_t sl = (uint64_t)(uint32_t)ctx->acc + sell;

                if (sh > 0xffffffffull) {
                    spe_raise(ctx, SPE_SOVH | SPE_OVH);
                }
                if (sl > 0xffffffffull) {
                    spe_raise(ctx, SPE_SOV | SPE_OV);
                }
                ctx->acc = ((sh > 0xffffffffull ? 0xffffffffull : sh)
                    << 32) | (sl > 0xffffffffull ? 0xffffffffu :
                    (uint32_t)sl);
            } else {
                ctx->acc += res;
            }
            return ctx->acc;
        }
        if (acc) {
            uint32_t dh = (uint32_t)(d >> 32);
            uint32_t dl = (uint32_t)d;
            uint32_t rh = sat ? fp_mac_sat_add(ctx, dh, selh, 1) :
                dh + selh;
            uint32_t rl = sat ? fp_mac_sat_add(ctx, dl, sell, 0) :
                dl + sell;

            ctx->acc += res;
            return ((uint64_t)rh << 32) | rl;
        }
        return res;
    }
}

/* ---- primary-31 floating-point indexed (full 10-bit XO) -------------- */
#define PPC32_FPUX_LFSX 535u
#define PPC32_FPUX_LFSUX 567u
#define PPC32_FPUX_LFDX 599u
#define PPC32_FPUX_LFDUX 631u
#define PPC32_FPUX_STFSX 663u
#define PPC32_FPUX_STFSUX 695u
#define PPC32_FPUX_STFDX 727u
#define PPC32_FPUX_STFDUX 759u

/* ---- primary-59 single A-form (5-bit XO = xo & 31) ------------------- */
#define PPC32_FS_FDIVS 18u
#define PPC32_FS_FSUBS 20u
#define PPC32_FS_FADDS 21u
#define PPC32_FS_FSQRTS 22u
#define PPC32_FS_FMULS 25u
#define PPC32_FS_FMSUBS 28u
#define PPC32_FS_FMADDS 29u
#define PPC32_FS_FNMSUBS 30u
#define PPC32_FS_FNMADDS 31u

/* ---- primary-63 double A-form (5-bit XO = xo & 31, FRC = bi) --------- */
#define PPC32_FD_FDIV 18u
#define PPC32_FD_FSUB 20u
#define PPC32_FD_FADD 21u
#define PPC32_FD_FSQRT 22u
#define PPC32_FD_FSEL 23u
#define PPC32_FD_FMUL 25u
#define PPC32_FD_FMSUB 28u
#define PPC32_FD_FMADD 29u
#define PPC32_FD_FNMSUB 30u
#define PPC32_FD_FNMADD 31u

/* ---- primary-63 double X-form (full 10-bit XO) ----------------------- */
#define PPC32_FD_FCMPU 0u
#define PPC32_FD_FRSP 12u
#define PPC32_FD_FCTIW 14u
#define PPC32_FD_FCTIWZ 15u
#define PPC32_FD_FCMPO 32u
#define PPC32_FD_FNEG 40u
#define PPC32_FD_FMR 72u
#define PPC32_FD_FNABS 136u
#define PPC32_FD_FABS 264u
#define PPC32_FD_MFFS 583u
#define PPC32_FD_MTFSF 711u
#define PPC32_FD_MTFSFI 134u
#define PPC32_FD_MTFSB0 70u
#define PPC32_FD_MTFSB1 38u

/* ---- e500v2 SPE integer/logical/merge (full 11-bit XO) --------------- */
#define PPC32_SPE_EVADDW 512u
#define PPC32_SPE_EVAND 529u
#define PPC32_SPE_EVOR 535u
#define PPC32_SPE_EVXOR 534u
#define PPC32_SPE_EVSUBFW 516u
#define PPC32_SPE_EVMERGEHI 556u
#define PPC32_SPE_EVMERGELO 557u
#define PPC32_SPE_EVMERGEHILO 558u
#define PPC32_SPE_EVMERGELOHI 559u
#define PPC32_SPE_EVCMP_GTU 560u
#define PPC32_SPE_EVCMP_GTS 561u
#define PPC32_SPE_EVCMP_LTU 562u
#define PPC32_SPE_EVCMP_LTS 563u
#define PPC32_SPE_EVCMP_EQ 564u

/* ---- e500v2 SPE loads/stores (odd = D-form, even = indexed) ---------- */
#define PPC32_SPE_EVLDD 769u
#define PPC32_SPE_EVLDDX 768u
#define PPC32_SPE_EVLDW 771u
#define PPC32_SPE_EVLDWX 770u
#define PPC32_SPE_EVSTDD 801u
#define PPC32_SPE_EVSTDDX 800u
#define PPC32_SPE_EVSTDW 803u
#define PPC32_SPE_EVSTDWX 802u
#define PPC32_SPE_EVLWHE 785u
#define PPC32_SPE_EVLWHEX 784u
#define PPC32_SPE_EVLWHOU 789u
#define PPC32_SPE_EVLWHOUX 788u
#define PPC32_SPE_EVLWHOS 791u
#define PPC32_SPE_EVLWHOSX 790u
#define PPC32_SPE_EVSTWWE 825u
#define PPC32_SPE_EVSTWWEX 824u
#define PPC32_SPE_EVSTWWO 829u
#define PPC32_SPE_EVSTWWOX 828u

/* evsel base (low 3 bits carry crS): 632 + crS */
#define PPC32_SPE_EVSEL_BASE 632u

/* ---- e500v2 SPE scalar-single efs (full 11-bit XO) ------------------- */
#define PPC32_SPE_EFSADD 704u
#define PPC32_SPE_EFSSUB 705u
#define PPC32_SPE_EFSABS 708u
#define PPC32_SPE_EFSNABS 709u
#define PPC32_SPE_EFSNEG 710u
#define PPC32_SPE_EFSMUL 712u
#define PPC32_SPE_EFSDIV 713u
#define PPC32_SPE_EFSCMPGT 716u
#define PPC32_SPE_EFSCMPLT 717u
#define PPC32_SPE_EFSCMPEQ 718u
#define PPC32_SPE_EFSCFD 719u
#define PPC32_SPE_EFSCFUI 720u
#define PPC32_SPE_EFSCFSI 721u
#define PPC32_SPE_EFSCFUF 722u
#define PPC32_SPE_EFSCFSF 723u
#define PPC32_SPE_EFSCTUI 724u
#define PPC32_SPE_EFSCTSI 725u
#define PPC32_SPE_EFSCTUF 726u
#define PPC32_SPE_EFSCTSF 727u
#define PPC32_SPE_EFSCTUIZ 728u
#define PPC32_SPE_EFSCTSIZ 730u
#define PPC32_SPE_EFSTSTGT 732u
#define PPC32_SPE_EFSTSTLT 733u
#define PPC32_SPE_EFSTSTEQ 734u

/* ---- e500v2 SPE scalar-double efd (full 11-bit XO) ------------------- */
#define PPC32_SPE_EFDADD 736u
#define PPC32_SPE_EFDSUB 737u
#define PPC32_SPE_EFDABS 740u
#define PPC32_SPE_EFDNABS 741u
#define PPC32_SPE_EFDNEG 742u
#define PPC32_SPE_EFDMUL 744u
#define PPC32_SPE_EFDDIV 745u
#define PPC32_SPE_EFDCMPGT 748u
#define PPC32_SPE_EFDCMPLT 749u
#define PPC32_SPE_EFDCMPEQ 750u
#define PPC32_SPE_EFDCFS 751u
#define PPC32_SPE_EFDCFUI 752u
#define PPC32_SPE_EFDCFSI 753u
#define PPC32_SPE_EFDCFUF 754u
#define PPC32_SPE_EFDCFSF 755u
#define PPC32_SPE_EFDCTUI 756u
#define PPC32_SPE_EFDCTSI 757u
#define PPC32_SPE_EFDCTUF 758u
#define PPC32_SPE_EFDCTSF 759u
#define PPC32_SPE_EFDCTUIZ 760u
#define PPC32_SPE_EFDCTSIZ 762u
#define PPC32_SPE_EFDTSTGT 764u
#define PPC32_SPE_EFDTSTLT 765u
#define PPC32_SPE_EFDTSTEQ 766u

/* ---- e500v2 SPE vector-single evfs (full 11-bit XO) ------------------ */
#define PPC32_SPE_EVFSADD 640u
#define PPC32_SPE_EVFSSUB 641u
#define PPC32_SPE_EVFSABS 644u
#define PPC32_SPE_EVFSNABS 645u
#define PPC32_SPE_EVFSNEG 646u
#define PPC32_SPE_EVFSMUL 648u
#define PPC32_SPE_EVFSDIV 649u
#define PPC32_SPE_EVFSCMPGT 652u
#define PPC32_SPE_EVFSCMPLT 653u
#define PPC32_SPE_EVFSCMPEQ 654u
#define PPC32_SPE_EVFSCFUI 656u
#define PPC32_SPE_EVFSCFSI 657u
#define PPC32_SPE_EVFSCFUF 658u
#define PPC32_SPE_EVFSCFSF 659u
#define PPC32_SPE_EVFSCTUI 660u
#define PPC32_SPE_EVFSCTSI 661u
#define PPC32_SPE_EVFSCTUF 662u
#define PPC32_SPE_EVFSCTSF 663u
#define PPC32_SPE_EVFSCTUIZ 664u
#define PPC32_SPE_EVFSCTSIZ 666u
#define PPC32_SPE_EVFSTSTGT 668u
#define PPC32_SPE_EVFSTSTLT 669u
#define PPC32_SPE_EVFSTSTEQ 670u

/* ---- e500v2 SPE MAC (full 11-bit XO; EREF semantics, see above) ------ */
#define PPC32_SPE_EVMWHSMF 1103u
#define PPC32_SPE_EVMWHSMFA 1135u
#define PPC32_SPE_EVMWHSMIA 1133u
#define PPC32_SPE_EVMWHSMIAA 1357u
#define PPC32_SPE_EVMWHSSF 1095u
#define PPC32_SPE_EVMWHSSFA 1127u
#define PPC32_SPE_EVMWHUMIA 1132u
#define PPC32_SPE_EVMWHUMIAA 1356u
#define PPC32_SPE_EVMWHUSIAA 1348u
#define PPC32_SPE_EVMWLUMIA 1128u
#define PPC32_SPE_EVMHEGSMIAA 1321u
#define PPC32_SPE_EVMHEGUMIAA 1320u
#define PPC32_SPE_EVMHOGSMIAA 1325u
#define PPC32_SPE_EVMHOGUMIAA 1324u
#define PPC32_SPE_EVMRA 1220u

#endif /* PPC32_FP_SPE_H */
