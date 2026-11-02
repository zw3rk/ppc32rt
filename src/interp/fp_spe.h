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

/* SPE converts (qemu helpers/macros; nearest-always; silent). single
 * ct*: QNaN->0 else invalid->max; double ct*: any-NaN->0. Fractional
 * x2^32. Scalar cf* yield 32-bit singles, efdcf* 64-bit doubles,
 * efscfd narrows a double to a single in lo, efdcfs widens a single
 * to a double. op: 0 ctsi, 1 ctui, 2 ctsiz, 3 ctuiz, 4 ctsf, 5 ctuf,
 * 6 cfsi, 7 cfui, 8 cfsf, 9 cfuf, 10 cfd/cfs. Callers write lo-only
 * for 32-bit-out (hi preserved via split storage). */
static inline uint64_t fp_spe_cvt(uint64_t in, int op, int is_dbl_in)
{
    if (!is_dbl_in) {
        uint32_t v = (uint32_t)in;
        float f = fp_f32(v);

        if (op <= 5) {
            if (fp_snan(v) && ((v >> 22) & 1u) != 0u) {
                return 0u; /* single QNaN input converts to 0 */
            }
            if (op == 0) {
                return (uint64_t)(uint32_t)fp_f2i(f, 0);
            }
            if (op == 1) {
                return (uint64_t)(uint32_t)fp_f2u(f, 0);
            }
            if (op == 2) {
                return (uint64_t)(uint32_t)fp_f2i(f, 1);
            }
            if (op == 3) {
                return (uint64_t)(uint32_t)fp_f2u(f, 1);
            }
            if (op == 4) {
                return (uint64_t)(uint32_t)fp_f2i(f * 4294967296.0f, 0);
            }
            return (uint64_t)(uint32_t)fp_f2u(f * 4294967296.0f, 0);
        }
        if (op <= 9) {
            if (op == 6) {
                return fp_u32((float)(int32_t)v);
            }
            if (op == 7) {
                return fp_u32((float)v);
            }
            if (op == 8) {
                return fp_u32((float)(int32_t)v / 4294967296.0f);
            }
            return fp_u32((float)v / 4294967296.0f);
        }
        if (fp_snan(v) && ((v >> 22) & 1u) == 0u) {
            v |= 0x400000u;
        }
        return fp_xtod(v);
    }
    {
        double d = fp_f64(in);

        if (op <= 5) {
            if (fp_isnan(in)) return 0u;
            if (op == 0) {
                return (uint64_t)(uint32_t)fp_d2i(d, 0);
            }
            if (op == 1) {
                return (uint64_t)(uint32_t)fp_d2u(d, 0);
            }
            if (op == 2) {
                return (uint64_t)(uint32_t)fp_d2i(d, 1);
            }
            if (op == 3) {
                return (uint64_t)(uint32_t)fp_d2u(d, 1);
            }
            if (op == 4) {
                return (uint64_t)(uint32_t)fp_d2i(d * 4294967296.0, 0);
            }
            return (uint64_t)(uint32_t)fp_d2u(d * 4294967296.0, 0);
        }
        if (op <= 9) {
            if (op == 6) {
                return fp_u64((double)(int32_t)(uint32_t)in);
            }
            if (op == 7) {
                return fp_u64((double)(uint32_t)in);
            }
            if (op == 8) {
                return fp_u64((double)(int32_t)(uint32_t)in / 4294967296.0);
            }
            return fp_u64((double)(uint32_t)in / 4294967296.0);
        }
        {
            uint32_t w;

            if (fp_isnan(in)) {
                w = (uint32_t)(((in >> 29) & 0x7fffffu) | 0x7f800000u |
                    ((in >> 63) << 31) | 0x400000u);
            } else {
                w = fp_u32((float)d);
            }
            return (uint64_t)w;
        }
    }
}

/* SPE MAC (EREF-best-effort; qemu-ppc SIGILLs all MAC, unverifiable
 * via oracle. Whole-word: LOW words 32x32->64; even/odd: halfword
 * pairs. s=signed, f=fractional, a=accum-rD-lo, c=accum-via-ACC,
 * t=saturate, h=high-32 (else low-32). Fractional high = prod>>31;
 * -1*-1 wraps or saturates. Whole-word zeroes rD.hi; halfword is
 * full 64-bit. evmra (rD=rA, ACC=rA) matches qemu. */
static inline uint64_t fp_spe_mac(ppc32_ctx_t *ctx, uint64_t a, uint64_t b,
    uint64_t d, int s, int f, int acc, int acp, int sat, int high, int half,
    int odd)
{
    if (half) {
        uint32_t a0 = (uint32_t)((a >> (odd ? 32u : 48u)) & 0xffffu);
        uint32_t a1 = (uint32_t)((a >> (odd ? 0u : 16u)) & 0xffffu);
        uint32_t b0 = (uint32_t)((b >> (odd ? 32u : 48u)) & 0xffffu);
        uint32_t b1 = (uint32_t)((b >> (odd ? 0u : 16u)) & 0xffffu);
        uint32_t p0 = s ? (uint32_t)((int32_t)(int16_t)a0 *
            (int32_t)(int16_t)b0) : a0 * b0;
        uint32_t p1 = s ? (uint32_t)((int32_t)(int16_t)a1 *
            (int32_t)(int16_t)b1) : a1 * b1;
        uint64_t cat = ((uint64_t)p0 << 32) | p1;

        if (acp) {
            cat += ctx->acc;
            ctx->acc = cat;
            return cat;
        }
        return ((uint64_t)(p0 + (uint32_t)(d >> 32)) << 32) |
            (uint64_t)(p1 + (uint32_t)d);
    }
    {
        uint64_t prod = s ? (uint64_t)((int64_t)(int32_t)(uint32_t)a *
            (int64_t)(int32_t)(uint32_t)b) : (uint64_t)(uint32_t)a *
            (uint64_t)(uint32_t)b;
        uint32_t sel;

        if (f) {
            if (prod == 0x4000000000000000ull) {
                sel = sat ? 0x7fffffffu : 0x80000000u;
            } else {
                sel = (uint32_t)((prod >> 31) & 0xffffffffu);
            }
        } else {
            sel = high ? (uint32_t)(prod >> 32) : (uint32_t)prod;
        }
        if (acp) {
            uint64_t old = ctx->acc;

            ctx->acc += prod;
            if (sat && ctx->acc < old) {
                return 0xffffffffu;
            }
            return (uint64_t)(high ? (uint32_t)(ctx->acc >> 32) :
                (uint32_t)ctx->acc);
        }
        if (acc) {
            if (sat) {
                int64_t sum = (int64_t)(int32_t)sel +
                    (int64_t)(int32_t)(uint32_t)d;

                if (sum > 2147483647ll) {
                    return 0x7fffffffu;
                }
                if (sum < -2147483648ll) {
                    return 0x80000000u;
                }
                return (uint64_t)(uint32_t)(int32_t)sum;
            }
            sel += (uint32_t)d;
        }
        return (uint64_t)sel;
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
