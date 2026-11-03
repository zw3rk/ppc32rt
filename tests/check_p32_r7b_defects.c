/*
 * tests/check_p32_r7b_defects.c — Round-7 ISA regressions, part B
 * (P32-R7-14..P32-R7-25).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side behavioral tests driving interp_step directly, mirroring
 * the style of tests/check_p32_defects.c. Each test names the finding
 * it pins; all run under `make test`.
 */

#define _POSIX_C_SOURCE 200809L

#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "interp/decode.h"
#include "interp/interp.h"
#include "os/syscalls.h"
#include "ppc32rt.h"
#include "vm/vm32.h"

static int g_fails = 0;

long ppc32_run_guest_child(ppc32_ctx_t *child)
{
    (void)child;
    return 0L;
}

#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__,     \
                (msg));                                                   \
            g_fails++;                                                    \
        }                                                                 \
    } while (0)

static void ctx_init_test(ppc32_ctx_t *ctx, uint8_t *base)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->guest_base = (uint64_t)(uintptr_t)base;
    ctx->vm_ready = true;
    ctx->region_count = 1U;
    ctx->regions[0].start = 0x100000U;
    ctx->regions[0].end = 0x180000U;
    ctx->regions[0].prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    vm32_tlb_invalidate_all();
    vm32_shadow_window((uint64_t)(uintptr_t)base);
    /* Code window carries guest EXEC for the R7-3 fetch check. */
    vm32_record_map(0x100000U, 0x180000U,
        PROT_READ | PROT_WRITE | PROT_EXEC, VM32_PAGE_ANON);
}

static void write_be32(uint8_t *base, uint32_t ea, uint32_t word)
{
    base[ea + 0U] = (uint8_t)(word >> 24);
    base[ea + 1U] = (uint8_t)(word >> 16);
    base[ea + 2U] = (uint8_t)(word >> 8);
    base[ea + 3U] = (uint8_t)word;
}

static uint64_t d64(double d)
{
    uint64_t u;

    memcpy(&u, &d, 8);
    return u;
}

/* Instruction word builders (big-endian words written with write_be32). */
static uint32_t w_dform(uint32_t op, uint32_t rt, uint32_t ra, uint32_t d)
{
    return (op << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        (d & 0xffffU);
}

static uint32_t w_xform(uint32_t rt, uint32_t ra, uint32_t rb, uint32_t xo,
    uint32_t rc)
{
    return (31U << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | ((xo & 1023U) << 1) | (rc & 1U);
}

static uint32_t w_fxform(uint32_t rt, uint32_t ra, uint32_t rb, uint32_t xo,
    uint32_t rc)
{
    return (63U << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | ((xo & 1023U) << 1) | (rc & 1U);
}

static uint32_t w_aform(uint32_t po, uint32_t rt, uint32_t ra, uint32_t rb,
    uint32_t frc, uint32_t xo, uint32_t rc)
{
    return (po << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | ((frc & 31U) << 6) | ((xo & 31U) << 1) |
        (rc & 1U);
}

static uint32_t w_spe(uint32_t rt, uint32_t ra, uint32_t rb, uint32_t xo)
{
    return (4U << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | (xo & 0x7ffU);
}

static void spe_mode(ppc32_ctx_t *ctx)
{
    ctx->profile = PPC32_PROFILE_SPE;
    ctx->is_spe = 1U;
}

/* P32-R7-14: halfword-vector loads transfer four bytes, faulting only
 * when the operand itself is unavailable. */
static void test_r7_14_halfword_width(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint32_t tail = 0x17fffcu;

    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    /* evlwhe r16, r3, 0 with EA at the mapping tail. */
    write_be32(base, code, w_spe(16U, 3U, 0U, 785U));
    write_be32(base, tail, 0xaabbccddU);
    ctx.nip = code;
    ctx.gpr[3] = tail;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-14 tail load succeeds");
    CHECK(ctx.gpr_hi[16] == 0xaabb0000U && ctx.gpr[16] == 0xccdd0000U,
        "r7-14 halves from one word");
}

/* P32-R7-15: Classic rejects SPE, SPE rejects classic FPU. */
static void test_r7_15_profile(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* Classic profile: evaddw is UNDEF. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_spe(16U, 14U, 15U, 512U));
    ctx.nip = code;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-15 classic rejects SPE");
    CHECK(ctx.nip == code, "r7-15 UNDEF holds NIP");

    /* SPE profile: lfd is UNDEF, evaddw runs. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_dform(50U, 1U, 3U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = 0x110000U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-15 SPE rejects lfd");

    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 15U, 512U));
    ctx.nip = code;
    ctx.gpr[14] = 1U;
    ctx.gpr_hi[14] = 1U;
    ctx.gpr[15] = 2U;
    ctx.gpr_hi[15] = 2U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-15 SPE runs evaddw");
    CHECK(ctx.gpr[16] == 3U && ctx.gpr_hi[16] == 3U,
        "r7-15 evaddw result");
}

/* P32-R7-16: lswi clears unfilled bytes of the final register. */
static void test_r7_16_lswi_clear(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint32_t data = 0x110000U;

    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(4U, 3U, 1U, 597U, 0U));
    base[data] = 0xaaU;
    ctx.nip = code;
    ctx.gpr[3] = data;
    ctx.gpr[4] = 0x11223344U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-16 lswi steps");
    CHECK(ctx.gpr[4] == 0xaa000000U, "r7-16 final register cleared");
}

/* P32-R7-17: lswx/stswx use the XER count with wrap and clearing. */
static void test_r7_17_lswx(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint32_t data = 0x110000U;

    /* Five-byte lswx: full word plus cleared partial word. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(4U, 3U, 6U, 533U, 0U));
    base[data + 0U] = 0x11U;
    base[data + 1U] = 0x22U;
    base[data + 2U] = 0x33U;
    base[data + 3U] = 0x44U;
    base[data + 4U] = 0x55U;
    ctx.nip = code;
    ctx.gpr[3] = data;
    ctx.gpr[6] = 0U;
    ctx.gpr[4] = 0U;
    ctx.gpr[5] = 0U;
    ctx.xer = 5U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-17 lswx steps");
    CHECK(ctx.gpr[4] == 0x11223344U, "r7-17 lswx full word");
    CHECK(ctx.gpr[5] == 0x55000000U, "r7-17 lswx cleared partial");

    /* Zero count completes without touching (unmapped) memory. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(4U, 3U, 6U, 533U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = 0x200000U;
    ctx.gpr[6] = 0U;
    ctx.xer = 0U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-17 zero count no-ops");
    CHECK(ctx.nip == code + 4U, "r7-17 zero count advances");

    /* stswx round-trip of the same five bytes. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(4U, 3U, 6U, 661U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = data;
    ctx.gpr[6] = 0U;
    ctx.gpr[4] = 0x11223344U;
    ctx.gpr[5] = 0x55000000U;
    ctx.xer = 5U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-17 stswx steps");
    CHECK(base[data + 0U] == 0x11U && base[data + 4U] == 0x55U,
        "r7-17 stswx bytes");
}

/* P32-R7-18: FPSCR direct writes raise summaries; exact arithmetic
 * never reasserts a software-cleared FX. */
static void test_r7_18_fpscr_summaries(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* mtfsb1 7 from zero sets VXSNAN, VX, and FX. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, (63U << 26) | (7U << 21) | (38U << 1));
    ctx.nip = code;
    interp_step(&ctx);
    CHECK(ctx.fpscr == 0xa1000000U, "r7-18 mtfsb1 raises summaries");

    /* mtfsfi field 1 <- 1 sets VXSNAN with VX/FX. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, (63U << 26) | (1U << 23) | (1U << 12) |
        (134U << 1));
    ctx.nip = code;
    interp_step(&ctx);
    CHECK((ctx.fpscr & 0xa1000000U) == 0xa1000000U,
        "r7-18 mtfsfi raises summaries");

    /* Cleared FX survives exact arithmetic with old OX sticky. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 21U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(2.0);
    ctx.fpscr = 1U << 28;
    interp_step(&ctx);
    CHECK((ctx.fpscr & (1U << 31)) == 0U, "r7-18 FX stays cleared");

    /* mtfsb0 of the last set VX sub-bit clears VX as well. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, (63U << 26) | (7U << 21) | (70U << 1));
    ctx.nip = code;
    ctx.fpscr = 1U << 24;
    interp_step(&ctx);
    CHECK((ctx.fpscr & ((1U << 29) | (1U << 24))) == 0U,
        "r7-18 mtfsb0 clears VX");

    /* mtfsf zeroing field 6 (the VXSNAN nibble) clears a derived VX. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, (63U << 26) | (4U << 21) | (2U << 11) |
        (711U << 1));
    ctx.nip = code;
    ctx.fpscr = (1U << 29) | (1U << 24);
    ctx.fpr[2] = 0ULL;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-18 mtfsf steps");
    CHECK((ctx.fpscr & ((1U << 29) | (1U << 24))) == 0U,
        "r7-18 mtfsf clears VX");
}

/* P32-R7-19: FR tracks the latest rounding event. */
static void test_r7_19_fr(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* Exact fadd clears stale FR/FI. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 21U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(1.0);
    ctx.fpscr = (1U << 18) | (1U << 17);
    interp_step(&ctx);
    CHECK((ctx.fpscr & ((1U << 18) | (1U << 17))) == 0U,
        "r7-19 exact clears FR|FI");

    /* Rounded fctiw(1.5) sets FR. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_fxform(1U, 0U, 2U, 14U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.5);
    interp_step(&ctx);
    CHECK(ctx.fpr[1] == 0x0000000000000002ULL, "r7-19 fctiw rounds to 2");
    CHECK(((ctx.fpscr >> 18) & 1U) != 0U, "r7-19 FR set on rounding");

    /* fadd(1, 2^-60) rounds down: FI set, FR clear. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 21U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(pow(2.0, -60.0));
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 17) & 1U) != 0U, "r7-19 FI on round-down");
    CHECK(((ctx.fpscr >> 18) & 1U) == 0U, "r7-19 no FR on round-down");

    /* fctiw(2.5) rounds to even (2): FI set, FR clear. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_fxform(1U, 0U, 2U, 14U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(2.5);
    interp_step(&ctx);
    CHECK(ctx.fpr[1] == 0x0000000000000002ULL, "r7-19 fctiw(2.5) rounds");
    CHECK(((ctx.fpscr >> 17) & 1U) != 0U, "r7-19 fctiw FI set");
    CHECK(((ctx.fpscr >> 18) & 1U) == 0U, "r7-19 fctiw no FR rounding down");
}

/* P32-R7-20: fctiw[z] rounds before the representability check. */
static void test_r7_20_fctiw_round_first(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* fctiwz(2147483647.25) truncates to a valid word. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_fxform(1U, 0U, 2U, 15U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(2147483647.25);
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-20 fctiwz steps");
    CHECK(ctx.fpr[1] == 0x000000007fffffffULL, "r7-20 truncates valid");
    CHECK(((ctx.fpscr >> 8) & 1U) == 0U, "r7-20 no VXCVI");
    CHECK(((ctx.fpscr >> 25) & 1U) != 0U, "r7-20 inexact XX");

    /* fctiwz(-2147483648.25) truncates to INT32_MIN (sign-extended). */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = d64(-2147483648.25);
    interp_step(&ctx);
    CHECK(ctx.fpr[1] == 0xffffffff80000000ULL, "r7-20 negative truncates");
    CHECK(((ctx.fpscr >> 8) & 1U) == 0U, "r7-20 negative no VXCVI");
}

/* P32-R7-21: FMA raises VXIMZ before NaN propagation. */
static void test_r7_21_fma_vximz(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* fmadd(0, +inf, QNaN): the 0*inf exception applies anyway, and
     * the addend payload is returned. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 4U, 29U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(0.0);
    ctx.fpr[4] = d64(INFINITY);
    ctx.fpr[3] = 0x7ff80000deadbeefULL;
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 20) & 1U) != 0U, "r7-21 VXIMZ despite NaN");
    CHECK(ctx.fpr[1] == 0x7ff80000deadbeefULL, "r7-21 NaN payload kept");

    /* fmadd(0, +inf, SNaN): VXIMZ and VXSNAN, quieted payload. */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = d64(0.0);
    ctx.fpr[4] = d64(INFINITY);
    ctx.fpr[3] = 0x7ff0000000000001ULL;
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 20) & 1U) != 0U, "r7-21 VXIMZ with SNaN");
    CHECK(((ctx.fpscr >> 24) & 1U) != 0U, "r7-21 VXSNAN with SNaN");
    CHECK(ctx.fpr[1] == 0x7ff8000000000001ULL, "r7-21 SNaN quieted");

    /* Control: NaN addend without 0*inf raises no VXIMZ. */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = d64(2.0);
    ctx.fpr[4] = d64(3.0);
    ctx.fpr[3] = 0x7ff8000000000000ULL;
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 20) & 1U) == 0U, "r7-21 no VXIMZ without 0*inf");
}

/* P32-R7-22: single-precision subnormals classify as subnormal. */
static void test_r7_22_fprf32(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* fmuls(FLT_MIN, 0.5) = 2^-127: single-subnormal, double-normal.
     * (fmuls takes its multiplier from the FRC slot.) */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(59U, 1U, 2U, 0U, 3U, 25U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64((double)FLT_MIN);
    ctx.fpr[3] = d64(0.5);
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-22 fmuls steps");
    CHECK(((ctx.fpscr >> 12) & 0x1fU) == 0x14U, "r7-22 FPRF subnormal");
}

/* P32-R7-23: comparisons update FPCC (bits 15..12) only, preserving
 * FPSCR[C] (bit 16, 0x10000). */
static void test_r7_23_fcmp_c(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* Ordered-equal with C preset: C survives, FPCC=EQ. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_fxform(4U, 2U, 3U, 0U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(1.0);
    ctx.fpscr = 1U << 16;
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 16) & 1U) != 0U, "r7-23 C preserved");
    CHECK(((ctx.fpscr >> 12) & 0xfU) == 0x2U, "r7-23 FPCC=EQ");

    /* Less-than with C preset: LT lands in FPCC, C is untouched. */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(2.0);
    ctx.fpscr = 1U << 16;
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 16) & 1U) != 0U, "r7-23 LT keeps C");
    CHECK(((ctx.fpscr >> 12) & 0xfU) == 0x8U, "r7-23 FPCC=LT");

    /* Unordered with C clear: C stays clear, FPCC=UN. */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = 0x7ff8000000000000ULL;
    ctx.fpr[3] = d64(1.0);
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 16) & 1U) == 0U, "r7-23 unordered keeps C clear");
    CHECK(((ctx.fpscr >> 12) & 0xfU) == 0x1U, "r7-23 FPCC=UN");
}

/* P32-R7-24: mftb/mfspr serve a coherent advancing time-base. */
static void test_r7_24_mftb(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    uint32_t lo1;
    uint32_t lo2;

    ctx_init_test(&ctx, base);
    /* mftb r3, 268 / mftb r4, 268: TBR 268 = rb 8, ra-lo 12. */
    write_be32(base, code + 0U, w_xform(3U, 12U, 8U, 371U, 0U));
    write_be32(base, code + 4U, w_xform(4U, 12U, 8U, 371U, 0U));
    /* mfspr r5, TBU (269) exercises the classic path. */
    write_be32(base, code + 8U, w_xform(5U, 13U, 8U, 339U, 0U));
    ctx.nip = code;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-24 mftb decodes");
    lo1 = ctx.gpr[3];
    interp_step(&ctx);
    lo2 = ctx.gpr[4];
    CHECK(lo2 >= lo1, "r7-24 TB advances");
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-24 mfspr TBU works");
    (void)lo1;

    /* mftb with an invalid TBR (8, the LR encoding) is UNDEF. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(3U, 8U, 0U, 371U, 0U));
    ctx.nip = code;
    ctx.lr = 0x12345678U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-24 bad TBR UNDEF");
    CHECK(ctx.nip == code, "r7-24 bad TBR holds NIP");
    CHECK(ctx.gpr[3] == 0U, "r7-24 bad TBR no side effects");
}

/* P32-R7-25: integer update forms validate RA!=0 and RA!=RT. */
static void test_r7_25_update_forms(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint32_t data = 0x110000U;

    /* lwzu r3,4(r3): RA==RT is UNDEF. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_dform(33U, 3U, 3U, 4U));
    ctx.nip = code;
    ctx.gpr[3] = data;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-25 lwzu RA==RT UNDEF");
    CHECK(ctx.nip == code && ctx.gpr[3] == data, "r7-25 no side effects");

    /* lwzux r3,r3,r4: RA==RT is UNDEF. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(3U, 3U, 4U, 55U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = data;
    ctx.gpr[4] = 4U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-25 lwzux RA==RT UNDEF");

    /* stbux with RA==0 is UNDEF (was a silent no-writeback). */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_xform(5U, 0U, 4U, 247U, 0U));
    ctx.nip = code;
    ctx.gpr[4] = data;
    ctx.gpr[5] = 0xaaU;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-25 stbux RA==0 UNDEF");

    /* stwu with RA==0 is UNDEF. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_dform(37U, 5U, 0U, 4U));
    ctx.nip = code;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_UNDEF, "r7-25 stwu RA==0 UNDEF");

    /* Valid lwzu still updates and loads. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_dform(33U, 4U, 3U, 4U));
    write_be32(base, data + 4U, 0x11223344U);
    ctx.nip = code;
    ctx.gpr[3] = data;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-25 valid lwzu runs");
    CHECK(ctx.gpr[3] == data + 4U && ctx.gpr[4] == 0x11223344U,
        "r7-25 valid lwzu commits");
}

int main(void)
{
    uint8_t *base = (uint8_t *)mmap(NULL, 0x200000U, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    test_r7_14_halfword_width(base);
    test_r7_15_profile(base);
    test_r7_16_lswi_clear(base);
    test_r7_17_lswx(base);
    test_r7_18_fpscr_summaries(base);
    test_r7_19_fr(base);
    test_r7_20_fctiw_round_first(base);
    test_r7_21_fma_vximz(base);
    test_r7_22_fprf32(base);
    test_r7_23_fcmp_c(base);
    test_r7_24_mftb(base);
    test_r7_25_update_forms(base);
    (void)munmap(base, 0x200000U);

    if (g_fails != 0) {
        fprintf(stderr, "check_p32_r7b_defects: %d FAILURES\n", g_fails);
        return 1;
    }
    printf("check_p32_r7b_defects: ALL OK\n");
    return 0;
}
