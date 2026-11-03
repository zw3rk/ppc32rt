/*
 * tests/check_p32_r7_defects.c — Round-7 ISA interpreter regressions
 * (P32-R7-1..P32-R7-25).
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

/* P32-R7-1: faulting loads/stores/multiple/string/SPE ops commit no
 * registers, no base writeback, and hold NIP at the faulting word. */
static void test_r7_1_fault_before_commit(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint32_t bad = 0x200000U;

    /* lwzu to an unmapped page. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_dform(33U, 4U, 3U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = bad;
    ctx.gpr[4] = 0xdeadbeefU;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r7-1 lwzu faults");
    CHECK(ctx.gpr[4] == 0xdeadbeefU, "r7-1 lwzu keeps RT");
    CHECK(ctx.gpr[3] == bad, "r7-1 lwzu skips base writeback");
    CHECK(ctx.nip == code, "r7-1 lwzu holds NIP");
    CHECK(ctx.fault_addr == bad, "r7-1 lwzu fault address");

    /* stw to an unmapped page. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_dform(36U, 5U, 4U, 0U));
    ctx.nip = code;
    ctx.gpr[4] = bad;
    ctx.gpr[5] = 0x11223344U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r7-1 stw faults");
    CHECK(ctx.nip == code, "r7-1 stw holds NIP");

    /* lmw faulting on its first element. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_dform(46U, 4U, 3U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = bad;
    ctx.gpr[4] = 0xdeadbeefU;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r7-1 lmw faults");
    CHECK(ctx.gpr[4] == 0xdeadbeefU, "r7-1 lmw keeps first RT");
    CHECK(ctx.nip == code, "r7-1 lmw holds NIP");

    /* SPE double load to an unmapped page (SPE profile). */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 3U, 4U, 768U));
    ctx.nip = code;
    ctx.gpr[3] = bad;
    ctx.gpr[4] = 0U;
    ctx.gpr[16] = 0xaaaaaaaaU;
    ctx.gpr_hi[16] = 0xbbbbbbbbU;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r7-1 evldd faults");
    CHECK(ctx.gpr[16] == 0xaaaaaaaaU && ctx.gpr_hi[16] == 0xbbbbbbbbU,
        "r7-1 evldd keeps destination");
    CHECK(ctx.nip == code, "r7-1 evldd holds NIP");
}

/* P32-R7-2: an instruction-fetch fault stays FAULT, never UNDEF. */
static void test_r7_2_fetch_fault(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    ctx_init_test(&ctx, base);
    /* b 0x200000 (unmapped): displacement 0x100000, AA=0, LK=0. */
    write_be32(base, code, (18U << 26) | 0x100000U);
    ctx.nip = code;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-2 branch steps");
    CHECK(ctx.nip == 0x200000U, "r7-2 branch lands");
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r7-2 fetch stays FAULT");
    CHECK(ctx.nip == 0x200000U, "r7-2 fetch holds NIP");
}

/* P32-R7-3: fetch from a readable-but-NX page faults; EXEC pages run. */
static void test_r7_3_nx_fetch(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    ctx_init_test(&ctx, base);
    write_be32(base, code, 0x60000000U);
    vm32_record_map(0x100000U, 0x180000U, PROT_READ | PROT_WRITE,
        VM32_PAGE_ANON);
    ctx.nip = code;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r7-3 NX fetch faults");
    CHECK(ctx.nip == code, "r7-3 NX fetch holds NIP");
    vm32_record_map(0x100000U, 0x180000U,
        PROT_READ | PROT_WRITE | PROT_EXEC, VM32_PAGE_ANON);
    ctx.exit_reason = PPC32_EXIT_NONE;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-3 EXEC fetch runs");
    CHECK(ctx.nip == code + 4U, "r7-3 EXEC fetch advances");
}

/* P32-R7-4: stwcx. succeeds undisturbed, fails after an ordinary
 * same-value store (cross-ctx ABA), and never deadlocks the store
 * path. The LL serialization itself is structural (see llsc.c). */
static void test_r7_4_sc_serial(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint32_t data = 0x120000U;
    const uint32_t lwarx = w_xform(3U, 0U, 4U, 20U, 0U);
    const uint32_t stwcx = w_xform(5U, 0U, 4U, 150U, 1U);

    /* Undisturbed reservation succeeds. */
    ctx_init_test(&ctx, base);
    write_be32(base, code + 0U, lwarx);
    write_be32(base, code + 4U, stwcx);
    write_be32(base, code + 8U, 0x44000002U);
    write_be32(base, data, 0x11223344U);
    ctx.nip = code;
    ctx.gpr[4] = data;
    ctx.gpr[5] = 0xdeadbeefU;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE && ctx.res_valid == 1U,
        "r7-4 lwarx records");
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-4 stwcx. steps");
    CHECK((ctx.cr & 0x20000000U) != 0U, "r7-4 stwcx. succeeds alone");

    /* Same-value ordinary store invalidates a peer (cross-ctx ABA). */
    {
        ppc32_ctx_t pa;
        ppc32_ctx_t pb;

        ctx_init_test(&pa, base);
        write_be32(base, data, 0x11223344U);
        pa.nip = code;
        pa.gpr[4] = data;
        pa.gpr[5] = 0x99999999U;
        interp_step(&pa);
        CHECK(pa.res_valid == 1U, "r7-4 peer A lwarx");

        ctx_init_test(&pb, base);
        write_be32(base, data, 0x11223344U);
        pb.nip = code;
        pb.gpr[4] = data;
        pb.gpr[5] = 0x11223344U;
        interp_step(&pb);
        interp_step(&pb);
        CHECK((pb.cr & 0x20000000U) != 0U, "r7-4 peer B stwcx. succeeds");

        pa.exit_reason = PPC32_EXIT_NONE;
        pa.nip = code + 4U;
        interp_step(&pa);
        CHECK(pa.exit_reason == PPC32_EXIT_NONE, "r7-4 peer A steps");
        CHECK((pa.cr & 0x20000000U) == 0U,
            "r7-4 peer A stwcx. fails after same-value store");
    }
}

/* P32-R7-5: record-form classic ops update CR1, never CR6. */
static void test_r7_5_cr1(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    ctx_init_test(&ctx, base);
    /* fadd. f1, f2, f3 with FPSCR top nibble preset. */
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 21U, 1U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(2.0);
    ctx.fpscr = 0xf0000000U;
    ctx.cr = 0U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-5 fadd. steps");
    CHECK(ctx.fpr[1] == d64(3.0), "r7-5 fadd. result");
    CHECK(((ctx.cr >> 24) & 0xfU) == ((ctx.fpscr >> 28) & 0xfU),
        "r7-5 CR1 mirrors FPSCR");
    CHECK(((ctx.cr >> 4) & 0xfU) == 0U, "r7-5 CR6 untouched");
}

/* P32-R7-6: addition faults on opposite-sign infinities only. */
static void test_r7_6_add_infinities(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* +inf + +inf = +inf, no VXISI. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 21U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(INFINITY);
    ctx.fpr[3] = d64(INFINITY);
    interp_step(&ctx);
    CHECK(ctx.fpr[1] == d64(INFINITY), "r7-6 +inf++inf=+inf");
    CHECK(((ctx.fpscr >> 23) & 1U) == 0U, "r7-6 no VXISI");

    /* +inf + -inf = NaN with VXISI. */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = d64(INFINITY);
    ctx.fpr[3] = d64(-INFINITY);
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 23) & 1U) != 0U, "r7-6 opposite infinities VXISI");

    /* +inf - +inf is still invalid for subtraction. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 20U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(INFINITY);
    ctx.fpr[3] = d64(INFINITY);
    interp_step(&ctx);
    CHECK(((ctx.fpscr >> 23) & 1U) != 0U, "r7-6 sub same infinities VXISI");
}

/* P32-R7-7: enabled invalid/zero-divide record without committing. */
static void test_r7_7_enabled_suppress(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint64_t sentinel = 0x0123456789abcdefULL;

    /* VE=1: fsqrt(-1) raises VXSQRT|VX, keeps FRT. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_fxform(1U, 0U, 2U, 22U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(-1.0);
    ctx.fpr[1] = sentinel;
    ctx.fpscr = 1U << 7;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-7 VE fsqrt steps");
    CHECK(ctx.fpr[1] == sentinel, "r7-7 VE fsqrt keeps FRT");
    CHECK(((ctx.fpscr >> 9) & 1U) != 0U, "r7-7 VXSQRT raised");
    CHECK(ctx.nip == code + 4U, "r7-7 VE fsqrt advances");

    /* ZE=1: 1.0/0.0 raises ZX, keeps FRT. */
    ctx_init_test(&ctx, base);
    write_be32(base, code, w_aform(63U, 1U, 2U, 3U, 0U, 18U, 0U));
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(0.0);
    ctx.fpr[1] = sentinel;
    ctx.fpscr = 1U << 4;
    interp_step(&ctx);
    CHECK(ctx.fpr[1] == sentinel, "r7-7 ZE fdiv keeps FRT");
    CHECK(((ctx.fpscr >> 26) & 1U) != 0U, "r7-7 ZX raised");

    /* Disabled: 1.0/0.0 commits +inf. */
    ctx_init_test(&ctx, base);
    ctx.nip = code;
    ctx.fpr[2] = d64(1.0);
    ctx.fpr[3] = d64(0.0);
    interp_step(&ctx);
    CHECK(ctx.fpr[1] == d64(INFINITY), "r7-7 plain fdiv commits inf");
}

/* P32-R7-8: vector float compares fill one CR nibble, no bleed. */
static void test_r7_8_vec_cmp(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;
    const uint64_t one = 0x3f8000003f800000ULL;

    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    /* evfscmpeq cr1, r14, r15 with equal lanes. */
    write_be32(base, code, w_spe(4U, 14U, 15U, 654U));
    ctx.nip = code;
    ctx.gpr[14] = (uint32_t)one;
    ctx.gpr_hi[14] = (uint32_t)(one >> 32);
    ctx.gpr[15] = (uint32_t)one;
    ctx.gpr_hi[15] = (uint32_t)(one >> 32);
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-8 evfscmpeq steps");
    CHECK(ctx.cr == 0x0f000000U, "r7-8 one nibble 0x0f, no bleed");
}

/* P32-R7-9: vector sign ops affect both single lanes. */
static void test_r7_9_sign_both_lanes(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 0U, 644U));
    ctx.nip = code;
    ctx.gpr[14] = 0xbf800000U;
    ctx.gpr_hi[14] = 0xbf800000U;
    interp_step(&ctx);
    CHECK(ctx.gpr[16] == 0x3f800000U && ctx.gpr_hi[16] == 0x3f800000U,
        "r7-9 evfsabs clears both signs");

    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 0U, 645U));
    ctx.nip = code;
    ctx.gpr[14] = 0x3f800000U;
    ctx.gpr_hi[14] = 0x40000000U;
    interp_step(&ctx);
    CHECK(ctx.gpr[16] == 0xbf800000U && ctx.gpr_hi[16] == 0xc0000000U,
        "r7-9 evfsnabs sets both signs");
}

/* P32-R7-10: whole-word MAC works per lane with ACC semantics. */
static void test_r7_10_mac(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* evmwhsmia: per-lane high-32 products, rD=ACC=result. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 15U, 1133U));
    ctx.nip = code;
    ctx.gpr[14] = 0x00010000U;
    ctx.gpr_hi[14] = 0x00010000U;
    ctx.gpr[15] = 0x00010000U;
    ctx.gpr_hi[15] = 0x00010000U;
    ctx.gpr[16] = 0U;
    ctx.gpr_hi[16] = 0U;
    ctx.acc = 0U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-10 evmwhsmia steps");
    CHECK(ctx.gpr[16] == 0x00000001U && ctx.gpr_hi[16] == 0x00000001U,
        "r7-10 evmwhsmia per-lane rD");
    CHECK(ctx.acc == 0x0000000100000001ULL, "r7-10 evmwhsmia ACC");

    /* evmwlumia: per-lane low-32 products accumulate. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 15U, 1128U));
    ctx.nip = code;
    ctx.gpr[14] = 0x00000002U;
    ctx.gpr_hi[14] = 0x00000001U;
    ctx.gpr[15] = 0x00000002U;
    ctx.gpr_hi[15] = 0x00000001U;
    ctx.gpr[16] = 0U;
    ctx.gpr_hi[16] = 0U;
    ctx.acc = 0U;
    interp_step(&ctx);
    CHECK(ctx.gpr[16] == 0x00000004U && ctx.gpr_hi[16] == 0x00000001U,
        "r7-10 evmwlumia per-lane rD");
    CHECK(ctx.acc == 0x0000000100000004ULL, "r7-10 evmwlumia ACC");
}

/* P32-R7-11: fractional converts use signed 2^31 scaling with the
 * correct signedness dispatch. */
static void test_r7_11_frac_conv(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* efscfsf(0xc0000000) = -0.5, not +0.75. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 0U, 14U, 723U));
    ctx.nip = code;
    ctx.gpr[14] = 0xc0000000U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-11 efscfsf steps");
    CHECK(ctx.gpr[16] == 0xbf000000U, "r7-11 efscfsf(-0.5)");

    /* efsctsf(+0.25) = 0x20000000, not 0x40000000. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 0U, 14U, 727U));
    ctx.nip = code;
    ctx.gpr[14] = 0x3e800000U;
    interp_step(&ctx);
    CHECK(ctx.gpr[16] == 0x20000000U, "r7-11 efsctsf(0.25)");
}

/* P32-R7-12: boundary float-to-int saturates without UB casts. */
static void test_r7_12_sat_ub(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* 2147483647.0f rounds to 2^31: must saturate to INT32_MAX. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 0U, 14U, 725U));
    ctx.nip = code;
    ctx.gpr[14] = 0x4f000000U;
    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "r7-12 efsctsi steps");
    CHECK(ctx.gpr[16] == 0x7fffffffU, "r7-12 saturates to INT32_MAX");
}

/* P32-R7-13: SPR 512 access, FRMC rounding, and sticky status. */
static void test_r7_13_spefscr(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code = 0x100000U;

    /* mtspr/mfspr 512 round-trip with the read-only/reserved mask. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code + 0U, w_xform(3U, 0U, 16U, 467U, 0U));
    write_be32(base, code + 4U, w_xform(4U, 0U, 16U, 339U, 0U));
    ctx.nip = code;
    ctx.gpr[3] = 0xffffffffU;
    interp_step(&ctx);
    CHECK(ctx.spefscr == 0xff3eff7fU, "r7-13 mtspr masks SPEFSCR");
    interp_step(&ctx);
    CHECK(ctx.gpr[4] == 0xff3eff7fU, "r7-13 mfspr reads SPEFSCR");

    /* FRMC=01 (toward zero): 1.0/3.0 truncates one ulp below nearest. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 15U, 713U));
    ctx.nip = code;
    ctx.gpr[14] = 0x3f800000U;
    ctx.gpr[15] = 0x40400000U;
    ctx.spefscr = 1U;
    interp_step(&ctx);
    CHECK(ctx.gpr[16] == 0x3eaaaaaaU, "r7-13 FRMC toward-zero divides");
    CHECK((ctx.spefscr & 0x00200000U) != 0U, "r7-13 FINXS recorded");

    /* QNaN arithmetic records invalid status. */
    ctx_init_test(&ctx, base);
    spe_mode(&ctx);
    write_be32(base, code, w_spe(16U, 14U, 15U, 704U));
    ctx.nip = code;
    ctx.gpr[14] = 0x7fc00000U;
    ctx.gpr[15] = 0x3f800000U;
    interp_step(&ctx);
    CHECK((ctx.spefscr & 0x00100800U) == 0x00100800U,
        "r7-13 NaN sets FINV|FINVS");
}
int main(void)
{
    uint8_t *base = (uint8_t *)mmap(NULL, 0x200000U, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    test_r7_1_fault_before_commit(base);
    test_r7_2_fetch_fault(base);
    test_r7_3_nx_fetch(base);
    test_r7_4_sc_serial(base);
    test_r7_5_cr1(base);
    test_r7_6_add_infinities(base);
    test_r7_7_enabled_suppress(base);
    test_r7_8_vec_cmp(base);
    test_r7_9_sign_both_lanes(base);
    test_r7_10_mac(base);
    test_r7_11_frac_conv(base);
    test_r7_12_sat_ub(base);
    test_r7_13_spefscr(base);
    (void)munmap(base, 0x200000U);

    if (g_fails != 0) {
        fprintf(stderr, "check_p32_r7_defects: %d FAILURES\n", g_fails);
        return 1;
    }
    printf("check_p32_r7_defects: ALL OK\n");
    return 0;
}
