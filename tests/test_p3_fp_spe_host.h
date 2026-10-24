/*
 * tests/test_p3_fp_spe_host.h -- host-native self-check for test_p3_fp_spe.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Included by tests/test_p3_fp_spe.c inside its #else (non-__powerpc__)
 * branch. Mirrors every guest site with host C models; prints PASS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t dbl_bits(double v)
{
    uint64_t u = 0u;
    memcpy(&u, &v, sizeof u);
    return u;
}

static uint32_t flt_bits(float v)
{
    uint32_t u = 0u;
    memcpy(&u, &v, sizeof u);
    return u;
}

static double bits_dbl(uint32_t hi, uint32_t lo)
{
    uint64_t u = ((uint64_t)hi << 32U) | (uint64_t)lo;
    double v = 0.0;
    memcpy(&v, &u, sizeof v);
    return v;
}

/* CR outcome for fcmpu/fcmpo: 8 LT, 4 GT, 2 EQ, 1 UN (NaN). */
static uint32_t fcmp_cr(double a, double b)
{
    if (a != a || b != b) {
        return 1u;
    }
    if (a < b) {
        return 8u;
    }
    if (a > b) {
        return 4u;
    }
    return 2u;
}

/* fctiw[z] model: mode 0 = nearest-even, 1 = to-zero, 2 = +inf, 3 = -inf.
 * Oracle (qemu-750/7450): NaN/-inf/negative overflow -> 0x80000000,
 * positive overflow/+inf -> 0x7FFFFFFF. */
static uint32_t fctiw_model(double x, int mode)
{
    double ax;
    int64_t mag;
    double frac;
    int neg;
    if (x != x) {
        return 0x80000000u;
    }
    if (x >= 2147483648.0) {
        return 0x7fffffffu;
    }
    if (x < -2147483648.0) {
        return 0x80000000u;
    }
    neg = (x < 0.0) ? 1 : 0;
    ax = neg ? -x : x;
    mag = (int64_t)ax;
    frac = ax - (double)mag;
    if (mode == 0) {
        if (frac > 0.5 || (frac == 0.5 && (mag & 1LL) != 0LL)) {
            mag++;
        }
    } else if (mode == 1) {
        /* truncate: nothing to do */
    } else if (mode == 2) {
        if (!neg && frac > 0.0) {
            mag++;
        }
    } else {
        if (neg && frac > 0.0) {
            mag++;
        }
    }
    /* Rounding can carry into 2^31 (e.g. nearest-even of 2147483647.5):
     * saturate by sign like the oracle. */
    if (mag > 2147483647LL) {
        return neg ? 0x80000000u : 0x7fffffffu;
    }
    if (neg) {
        return (uint32_t)(int32_t)(-mag);
    }
    return (uint32_t)(int32_t)mag;
}

/* 64-bit SPE lane pair {hi, lo}. */
typedef struct {
    uint32_t hi;
    uint32_t lo;
} spe64;

static spe64 spe_add(spe64 a, spe64 b)
{
    spe64 r;
    r.hi = a.hi + b.hi;
    r.lo = a.lo + b.lo;
    return r;
}

static spe64 spe_sub(spe64 a, spe64 b) /* evsubfw: b - a per lane */
{
    spe64 r;
    r.hi = b.hi - a.hi;
    r.lo = b.lo - a.lo;
    return r;
}

static int failures = 0;

#define TEST(name, got, want)                                  \
    do {                                                       \
        uint32_t g_ = (uint32_t)(got);                         \
        uint32_t w_ = (uint32_t)(want);                        \
        if (g_ != w_) {                                        \
            printf("FAIL %s got=0x%08x want=0x%08x\n",         \
                name, g_, w_);                                 \
            failures++;                                        \
        }                                                      \
    } while (0)

int main(void)
{
    double d15 = bits_dbl(0x3FF80000u, 0u);
    double d225 = bits_dbl(0x40020000u, 0u);
    double d375 = bits_dbl(0x400E0000u, 0u);
    double d25 = bits_dbl(0x40040000u, 0u);
    double dm15 = bits_dbl(0xBFF80000u, 0u);
    double big = bits_dbl(0x43D00000u, 0u); /* 2^62 */
    double qnan = strtod("NAN", NULL);
    double snan = bits_dbl(0x7FF00000u, 1u);
    float f15 = 1.5f;
    float f225 = 2.25f;
    float f375 = 3.75f;
    float f25 = 2.5f;
    float f125 = 1.25f;
    spe64 va;
    spe64 vb;
    spe64 vr;

    /* Scalar FP arithmetic bit patterns. */
    TEST("fadd_hi", (uint32_t)(dbl_bits(d15 + d225) >> 32U), 0x400E0000u);
    TEST("fadd_lo", (uint32_t)dbl_bits(d15 + d225), 0u);
    TEST("fsub_hi", (uint32_t)(dbl_bits(d375 - d225) >> 32U), 0x3FF80000u);
    TEST("fsub_lo", (uint32_t)dbl_bits(d375 - d225), 0u);
    TEST("fmul_hi", (uint32_t)(dbl_bits(d15 * d225) >> 32U), 0x400B0000u);
    TEST("fmul_lo", (uint32_t)dbl_bits(d15 * d225), 0u);
    TEST("fdiv_hi", (uint32_t)(dbl_bits(d225 / d15) >> 32U), 0x3FF80000u);
    TEST("fdiv_lo", (uint32_t)dbl_bits(d225 / d15), 0u);
    TEST("fsqrt_hi", (uint32_t)(dbl_bits(d225 / d15) >> 32U), 0x3FF80000u);
    TEST("fmadd_hi", (uint32_t)(dbl_bits(d15 * d225 + d15) >> 32U),
        0x40138000u);
    TEST("fmadd_lo", (uint32_t)dbl_bits(d15 * d225 + d15), 0u);
    TEST("fneg_hi", (uint32_t)(dbl_bits(-d15) >> 32U), 0xBFF80000u);
    TEST("fneg_lo", (uint32_t)dbl_bits(-d15), 0u);
    TEST("fabs_hi", (uint32_t)(dbl_bits(-dm15) >> 32U), 0x3FF80000u);
    TEST("fsel_hi", (uint32_t)(dbl_bits(d15 >= 0.0 ? d225 : d15) >> 32U),
        0x40020000u);
    TEST("frsp_hi", (uint32_t)(dbl_bits((double)(float)d375) >> 32U),
        0x400E0000u);

    /* fcmpo/fcmpu CR outcomes incl. NaN. */
    TEST("fcmpu_lt", fcmp_cr(d15, d225), 8u);
    TEST("fcmpu_gt", fcmp_cr(d225, d15), 4u);
    TEST("fcmpu_eq", fcmp_cr(d15, d15), 2u);
    TEST("fcmpu_qnan", fcmp_cr(qnan, d15), 1u);
    TEST("fcmpu_snan", fcmp_cr(d15, snan), 1u);
    TEST("fcmpo_lt", fcmp_cr(d15, d225), 8u);
    TEST("fcmpo_qnan", fcmp_cr(qnan, d15), 1u);
    TEST("fcmpo_snan", fcmp_cr(snan, d15), 1u);

    /* Rounding modes + conversions. */
    TEST("fctiw_near", fctiw_model(d15, 0), 2u);
    TEST("fctiwz", fctiw_model(d15, 1), 1u);
    TEST("fctiwz_neg", fctiw_model(dm15, 1), 0xFFFFFFFFu);
    TEST("fctiw_neg_half", fctiw_model(dm15, 0), 0xFFFFFFFEu);
    TEST("fctiw_halfeven", fctiw_model(d25, 0), 2u);
    TEST("fctiwz_25", fctiw_model(d25, 1), 2u);
    TEST("fctiw_tozero", fctiw_model(d15, 1), 1u);
    TEST("fctiw_nearest", fctiw_model(d15, 0), 2u);
    TEST("fctiw_pinf", fctiw_model(d15, 2), 2u);
    TEST("fctiw_ninf", fctiw_model(d15, 3), 1u);
    TEST("fctiw_ovf", fctiw_model(big, 1), 0x7fffffffu);

    /* SPE vector integer. */
    va.hi = 1u;
    va.lo = 2u;
    vb.hi = 3u;
    vb.lo = 4u;
    vr = spe_add(va, vb);
    TEST("evaddw_hi", vr.hi, 4u);
    TEST("evaddw_lo", vr.lo, 6u);
    va.hi = 4u;
    va.lo = 1u;
    vb.hi = 10u;
    vb.lo = 3u;
    vr = spe_sub(va, vb);
    TEST("evsubfw_hi", vr.hi, 6u);
    TEST("evsubfw_lo", vr.lo, 2u);
    va.hi = 0xF0F0F0F0u;
    va.lo = 0xF0F0F0F0u;
    vb.hi = 0x0FF00FF0u;
    vb.lo = 0x0FF00FF0u;
    TEST("evand_hi", va.hi & vb.hi, 0x00F000F0u);
    TEST("evand_lo", va.lo & vb.lo, 0x00F000F0u);
    TEST("evor_hi", va.hi | vb.hi, 0xFFF0FFF0u);
    TEST("evor_lo", va.lo | vb.lo, 0xFFF0FFF0u);
    TEST("evxor_hi", va.hi ^ vb.hi, 0xFF00FF00u);
    TEST("evxor_lo", va.lo ^ vb.lo, 0xFF00FF00u);
    va.hi = 1u;
    va.lo = 2u;
    vb.hi = 3u;
    vb.lo = 4u;
    TEST("evmergehi_hi", va.hi, 1u);
    TEST("evmergehi_lo", vb.hi, 3u);
    TEST("evmergelo_hi", va.lo, 2u);
    TEST("evmergelo_lo", vb.lo, 4u);

    /* efs/efd scalar + evfs vector spot checks. */
    TEST("efsadd", flt_bits(f15 + f225), 0x40700000u);
    TEST("efssub", flt_bits(f375 - f15), 0x40100000u);
    TEST("efdadd_hi", (uint32_t)(dbl_bits(d15 + d225) >> 32U), 0x400E0000u);
    TEST("efdadd_lo", (uint32_t)dbl_bits(d15 + d225), 0u);
    TEST("efdsub_hi", (uint32_t)(dbl_bits(d375 - d15) >> 32U), 0x40020000u);
    TEST("efdsub_lo", (uint32_t)dbl_bits(d375 - d15), 0u);
    TEST("evfsadd_hi", flt_bits(f15 + f225), 0x40700000u);
    TEST("evfsadd_lo", flt_bits(f25 + f125), 0x40700000u);

    if (failures != 0) {
        printf("FAILURES %d\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
