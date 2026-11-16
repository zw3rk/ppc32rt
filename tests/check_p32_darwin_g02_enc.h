/*
 * tests/check_p32_darwin_g02_enc.h — G02 guest word encoders (split from
 * tests/check_p32_darwin_g02.c under the file-size discipline).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hand-crafted big-endian PowerPC 7450 words plus BE window helpers.
 * Behavior unchanged; shared by every G02 subtest in the one test TU.
 */

#ifndef PPC32RT_CHECK_P32_DARWIN_G02_ENC_H
#define PPC32RT_CHECK_P32_DARWIN_G02_ENC_H

#include <stdint.h>

#define CODE_VA 0x100000U
#define DATA_VA 0x200000U
#define STACK_TOP 0x301000U
#define RO_VA 0x400000U
#define UNMAPPED_VA 0x500000U

static void w32(uint64_t base, uint32_t va, uint32_t w)
{
    uint8_t *p = (uint8_t *)(uintptr_t)(base + (uint64_t)va);
    p[0] = (uint8_t)(w >> 24);
    p[1] = (uint8_t)(w >> 16);
    p[2] = (uint8_t)(w >> 8);
    p[3] = (uint8_t)w;
}

static uint32_t r32(uint64_t base, uint32_t va)
{
    const uint8_t *p = (const uint8_t *)(uintptr_t)(base + (uint64_t)va);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t w_dform(uint32_t op, uint32_t rt, uint32_t ra, uint32_t d)
{
    return (op << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        (d & 0xffffU);
}

static uint32_t w_x31(uint32_t rt, uint32_t ra, uint32_t rb, uint32_t xo,
    uint32_t rc)
{
    return (31U << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | ((xo & 1023U) << 1) | (rc & 1U);
}

static uint32_t w_vx3(uint32_t vd, uint32_t va, uint32_t vb, uint32_t xo)
{
    return (4U << 26) | ((vd & 31U) << 21) | ((va & 31U) << 16) |
        ((vb & 31U) << 11) | (xo & 0x7ffU);
}

static uint32_t w_va(uint32_t vd, uint32_t va, uint32_t vb, uint32_t vc,
    uint32_t low6)
{
    return (4U << 26) | ((vd & 31U) << 21) | ((va & 31U) << 16) |
        ((vb & 31U) << 11) | ((vc & 31U) << 6) | (low6 & 63U);
}

static uint32_t w_mtspr(uint32_t rs, uint32_t spr)
{
    return (31U << 26) | ((rs & 31U) << 21) | ((spr & 31U) << 16) |
        (((spr >> 5) & 31U) << 11) | (467U << 1);
}

static uint32_t w_mfspr(uint32_t rt, uint32_t spr)
{
    return (31U << 26) | ((rt & 31U) << 21) | ((spr & 31U) << 16) |
        (((spr >> 5) & 31U) << 11) | (339U << 1);
}

static uint32_t w_b(uint32_t pc, uint32_t target, uint32_t lk)
{
    uint32_t disp = target - pc;
    return (18U << 26) | (disp & 0x03FFFFFCU) | (lk & 1U);
}

static uint32_t w_bc(uint32_t pc, uint32_t bo, uint32_t bi,
    uint32_t target)
{
    uint32_t disp = target - pc;
    return (16U << 26) | ((bo & 31U) << 21) | ((bi & 31U) << 16) |
        (((disp >> 2) & 0x3fffU) << 2);
}

static uint32_t w_blr(void)
{
    return (19U << 26) | (20U << 21) | (16U << 1);
}

static uint32_t w_cmpi(uint32_t ra, uint32_t simm)
{
    return (11U << 26) | ((ra & 31U) << 16) | (simm & 0xFFFFU);
}

static uint32_t w_bne(uint32_t pc, uint32_t target)
{
    return w_bc(pc, 4, 2, target);
}

static uint32_t w_blt(uint32_t pc, uint32_t target)
{
    return w_bc(pc, 12, 0, target);
}

static uint32_t w_mftb(uint32_t rt, uint32_t tbr)
{
    return (31U << 26) | ((rt & 31U) << 21) | ((tbr & 31U) << 16) |
        (((tbr >> 5) & 31U) << 11) | (371U << 1);
}

static uint32_t w_subf(uint32_t rt, uint32_t ra, uint32_t rb)
{
    return w_x31(rt, ra, rb, 40U, 0);
}

static uint32_t w_lwarx(uint32_t rt, uint32_t ra, uint32_t rb)
{
    return w_x31(rt, ra, rb, 20, 0);
}

static uint32_t w_stwcx(uint32_t rs, uint32_t ra, uint32_t rb)
{
    return w_x31(rs, ra, rb, 150, 1);
}

#endif /* PPC32RT_CHECK_P32_DARWIN_G02_ENC_H */
