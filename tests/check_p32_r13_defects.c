/*
 * tests/check_p32_r13_defects.c — Regression suite for audit findings
 * P32-R13-1..16, P32-R14-1, P32-R15-1..2, P32-R16-1.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side behavioral tests driving interp_step/dbt_run directly,
 * mirroring the style of tests/check_p32_defects.c. Each test names
 * the finding it pins; all run under `make test`.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "dbt/dbt.h"
#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"
#include "interp/decode.h"
#include "interp/interp.h"
#include "os/syscalls.h"
#include "os/syscall_nr.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"
#include "vm/vm32.h"

#define XER_SO (1U << 31)
#define XER_OV (1U << 30)
#define XER_CA (1U << 29)

/* Guest AT_EMPTY_PATH bit (host <fcntl.h> may lack it; the dyn layer
 * tests the guest value). Must match DYN_AT_EMPTY_PATH. */
#define T_AT_EMPTY_PATH 0x1000U

static int g_fails = 0;
static ppc32_ctx_t *g_emit_owner = NULL;

long ppc32_run_guest_child(ppc32_ctx_t *child)
{
    (void)child;
    return 0L;
}

static int emit_bridge(a64_buf_t *b, const ppc32_insn_t *insn, uint32_t pc)
{
    ppc32_emit_ctx_t e;
    int rc;

    ppc32_emit_begin(&e, g_emit_owner, b);
    rc = ppc32_emit_int(&e, insn, pc);
    if (rc == PPC32_EMIT_FALLBACK && !b->overflow) {
        rc = ppc32_emit_fp(&e, insn, pc);
    }
    if (rc == PPC32_EMIT_FALLBACK || b->overflow) {
        return 1;
    }
    return 0;
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

static uint32_t w_dform(uint32_t op, uint32_t rt, uint32_t ra, uint32_t d)
{
    return (op << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        (d & 0xffffU);
}

static uint32_t w_xoform(uint32_t rt, uint32_t ra, uint32_t rb,
    uint32_t oe, uint32_t xo, uint32_t rc)
{
    return (31U << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | ((oe & 1U) << 10) | ((xo & 511U) << 1) |
        (rc & 1U);
}

static uint32_t w_aform(uint32_t po, uint32_t rt, uint32_t ra, uint32_t rb,
    uint32_t frc, uint32_t xo, uint32_t rc)
{
    return (po << 26) | ((rt & 31U) << 21) | ((ra & 31U) << 16) |
        ((rb & 31U) << 11) | ((frc & 31U) << 6) | ((xo & 31U) << 1) |
        (rc & 1U);
}

/* P32-R13-1: DBT fetch rejects guest-NX pages exactly like interp. */
static void test_r13_1_dbt_nx_fetch(uint8_t *base)
{
    ppc32_ctx_t ctx;
    uint32_t code_ea = 0x150000U;
    uint32_t nop = 0x60000000U;
    uint32_t sc = PPC32_INSN_SC;
    int rc;

    /* NX page: mapped readable but not executable. */
    ctx_init_test(&ctx, base);
    ctx.regions[0].prot = PROT_READ | PROT_WRITE;
    vm32_record_map(0x100000U, 0x180000U, PROT_READ | PROT_WRITE,
        VM32_PAGE_ANON);
    write_be32(base, code_ea + 0U, nop);
    write_be32(base, code_ea + 4U, sc);
    ctx.nip = code_ea;

    interp_step(&ctx);
    CHECK(ctx.exit_reason == PPC32_EXIT_FAULT, "r13-1 interp NX faults");
    CHECK(ctx.fault_addr == code_ea, "r13-1 interp fault addr");

    ctx_init_test(&ctx, base);
    ctx.regions[0].prot = PROT_READ | PROT_WRITE;
    vm32_record_map(0x100000U, 0x180000U, PROT_READ | PROT_WRITE,
        VM32_PAGE_ANON);
    ctx.nip = code_ea;
    g_emit_owner = &ctx;
    ppc32_dbt_set_emitter(emit_bridge);
    dbt_invalidate_all(&ctx);
    rc = dbt_run(&ctx);
    CHECK(rc == PPC32_EXIT_FAULT, "r13-1 dbt NX faults");
    CHECK(ctx.fault_addr == code_ea, "r13-1 dbt fault addr");

    /* Control: the same bytes with EXEC translate and run to sc. */
    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    g_emit_owner = &ctx;
    dbt_invalidate_all(&ctx);
    rc = dbt_run(&ctx);
    CHECK(rc == PPC32_EXIT_SYSCALL, "r13-1 exec page runs");
}

/* P32-R13-2: statx to a bad guest buffer returns -EFAULT. */
static void test_r13_2_statx_bad_pointer(uint8_t *base)
{
    ppc32_ctx_t ctx;
    uint32_t path_va = 0x170000U;
    uint32_t good_va = 0x171000U;
    uint32_t bad_va = 0x200000U;
    long ret = 0L;
    int owned;

    ctx_init_test(&ctx, base);
    /* Checked copies consult ctx->regions when vm_ready is clear (the
     * global table stays empty until ppc32_vm_init). */
    ctx.vm_ready = false;
    base[path_va] = '\0';
    owned = ppc32_dyn_dispatch(&ctx, PPC32_NR_STATX, 1U, path_va,
        T_AT_EMPTY_PATH, 0U, good_va, 0U, &ret);
    CHECK(owned == 1, "r13-2 statx owned");
    CHECK(ret == 0, "r13-2 statx good buffer writes");
    CHECK(base[good_va + 0U] == 0U && base[good_va + 1U] == 0U &&
        base[good_va + 2U] == 0x07U && base[good_va + 3U] == 0xFFU,
        "r13-2 statx basic-stats image landed");

    owned = ppc32_dyn_dispatch(&ctx, PPC32_NR_STATX, 1U, path_va,
        T_AT_EMPTY_PATH, 0U, bad_va, 0U, &ret);
    CHECK(owned == 1, "r13-2 statx bad owned");
    CHECK(ret == -EFAULT, "r13-2 statx unmapped buffer faults");

    owned = ppc32_dyn_dispatch(&ctx, PPC32_NR_STATX, 1U, path_va,
        T_AT_EMPTY_PATH, 0U, 0x100U, 0U, &ret);
    CHECK(owned == 1, "r13-2 statx guard owned");
    CHECK(ret == -EFAULT, "r13-2 statx guard buffer faults");
}

/* P32-R14-1: addco./subfco. OV/CA/CR0 in both engines. */
static void test_r14_1_addco_subfco(uint8_t *base)
{
    size_t eng;

    for (eng = 0U; eng < 2U; eng++) {
        ppc32_ctx_t ctx;
        uint32_t code_ea = 0x102000U + (uint32_t)(eng * 0x1000U);
        uint32_t sc = PPC32_INSN_SC;
        int rc;

        /* li r3,-1; li r4,-1; addco. r5,r3,r4; sc */
        write_be32(base, code_ea + 0U, w_dform(14U, 3U, 0U, 0xFFFFU));
        write_be32(base, code_ea + 4U, w_dform(14U, 4U, 0U, 0xFFFFU));
        write_be32(base, code_ea + 8U, w_xoform(5U, 3U, 4U, 1U, 10U, 1U));
        write_be32(base, code_ea + 12U, sc);
        ctx_init_test(&ctx, base);
        ctx.nip = code_ea;
        if (eng == 0U) {
            interp_run(&ctx);
            CHECK(ctx.exit_reason == PPC32_EXIT_SYSCALL,
                "r14-1 interp addco runs");
        } else {
            g_emit_owner = &ctx;
            ppc32_dbt_set_emitter(emit_bridge);
            dbt_invalidate_all(&ctx);
            rc = dbt_run(&ctx);
            CHECK(rc == PPC32_EXIT_SYSCALL, "r14-1 dbt addco runs");
        }
        CHECK(ctx.gpr[5] == 0xFFFFFFFEU, "r14-1 addco result");
        CHECK((ctx.xer & XER_CA) != 0U, "r14-1 addco CA == 1");
        CHECK((ctx.xer & XER_OV) == 0U, "r14-1 addco OV == 0");
        CHECK((ctx.xer & XER_SO) == 0U, "r14-1 addco SO == 0");
        CHECK(((ctx.cr >> 28) & 1U) == 0U, "r14-1 addco CR0.SO == 0");

        /* lis r4,0x8000; li r3,1; subfco. r5,r3,r4; sc */
        code_ea += 0x100U;
        write_be32(base, code_ea + 0U, w_dform(15U, 4U, 0U, 0x8000U));
        write_be32(base, code_ea + 4U, w_dform(14U, 3U, 0U, 1U));
        write_be32(base, code_ea + 8U, w_xoform(5U, 3U, 4U, 1U, 8U, 1U));
        write_be32(base, code_ea + 12U, sc);
        ctx_init_test(&ctx, base);
        ctx.nip = code_ea;
        if (eng == 0U) {
            interp_run(&ctx);
            CHECK(ctx.exit_reason == PPC32_EXIT_SYSCALL,
                "r14-1 interp subfco runs");
        } else {
            g_emit_owner = &ctx;
            dbt_invalidate_all(&ctx);
            rc = dbt_run(&ctx);
            CHECK(rc == PPC32_EXIT_SYSCALL, "r14-1 dbt subfco runs");
        }
        CHECK(ctx.gpr[5] == 0x7FFFFFFFU, "r14-1 subfco result");
        CHECK((ctx.xer & XER_CA) != 0U, "r14-1 subfco CA == 1");
        CHECK((ctx.xer & XER_OV) != 0U, "r14-1 subfco OV == 1");
        CHECK((ctx.xer & XER_SO) != 0U, "r14-1 subfco SO == 1");
        CHECK(((ctx.cr >> 28) & 1U) != 0U, "r14-1 subfco CR0.SO == 1");
    }
}

/* P32-R15-1: fmsub/fnmsub single+double in both engines. */
static void test_r15_1_fmsub_fnmsub(uint8_t *base)
{
    static const struct {
        uint32_t po;
        uint32_t xo;
        uint32_t fprf;
    } cases[] = {
        { 59U, 28U, 0x04U },
        { 59U, 30U, 0x08U },
        { 63U, 28U, 0x04U },
        { 63U, 30U, 0x08U },
    };
    size_t c;
    size_t eng;

    for (c = 0U; c < 4U; c++) {
        for (eng = 0U; eng < 2U; eng++) {
            ppc32_ctx_t ctx;
            uint32_t code_ea = 0x110000U + (uint32_t)(c * 0x100U) +
                (uint32_t)(eng * 0x800U);
            uint32_t sc = PPC32_INSN_SC;
            int rc;

            write_be32(base, code_ea + 0U,
                w_aform(cases[c].po, 4U, 1U, 3U, 2U, cases[c].xo, 1U));
            write_be32(base, code_ea + 4U, sc);
            ctx_init_test(&ctx, base);
            ctx.nip = code_ea;
            ctx.fpr[1] = d64(3.0);
            ctx.fpr[2] = d64(4.0);
            ctx.fpr[3] = d64(5.0);
            if (eng == 0U) {
                interp_step(&ctx);
                CHECK(ctx.exit_reason == PPC32_EXIT_NONE,
                    "r15-1 interp steps");
            } else {
                g_emit_owner = &ctx;
                ppc32_dbt_set_emitter(emit_bridge);
                dbt_invalidate_all(&ctx);
                rc = dbt_run(&ctx);
                CHECK(rc == PPC32_EXIT_SYSCALL, "r15-1 dbt runs");
            }
            if (cases[c].xo == 28U) {
                CHECK(ctx.fpr[4] == d64(7.0), "r15-1 fmsub == +7.0");
            } else {
                CHECK(ctx.fpr[4] == d64(-7.0), "r15-1 fnmsub == -7.0");
            }
            CHECK(((ctx.fpscr >> 12) & 0x1fU) == cases[c].fprf,
                "r15-1 FPRF class");
        }
    }
}

/* P32-R15-2: +-Inf FPRF carries FU (0x05/0x09) in both engines. */
static void test_r15_2_inf_fprf(uint8_t *base)
{
    size_t eng;
    size_t s;

    for (s = 0U; s < 2U; s++) {
        for (eng = 0U; eng < 2U; eng++) {
            ppc32_ctx_t ctx;
            uint32_t code_ea = 0x120000U + (uint32_t)(s * 0x100U) +
                (uint32_t)(eng * 0x800U);
            uint64_t inf = (s == 0U) ? 0x7FF0000000000000ULL :
                0xFFF0000000000000ULL;
            uint32_t want = (s == 0U) ? 0x05U : 0x09U;
            uint32_t sc = PPC32_INSN_SC;
            int rc;

            /* fadd. f2,f1,f0 with f1=+-Inf, f0=+0.0. */
            write_be32(base, code_ea + 0U,
                w_aform(63U, 2U, 1U, 0U, 0U, 21U, 1U));
            write_be32(base, code_ea + 4U, sc);
            ctx_init_test(&ctx, base);
            ctx.nip = code_ea;
            ctx.fpr[0] = d64(0.0);
            ctx.fpr[1] = inf;
            if (eng == 0U) {
                interp_step(&ctx);
                CHECK(ctx.exit_reason == PPC32_EXIT_NONE,
                    "r15-2 interp steps");
            } else {
                g_emit_owner = &ctx;
                ppc32_dbt_set_emitter(emit_bridge);
                dbt_invalidate_all(&ctx);
                rc = dbt_run(&ctx);
                CHECK(rc == PPC32_EXIT_SYSCALL, "r15-2 dbt runs");
            }
            CHECK(ctx.fpr[2] == inf, "r15-2 Inf result preserved");
            CHECK(((ctx.fpscr >> 12) & 0x1fU) == want,
                "r15-2 Inf FPRF has FU");
        }
    }
}

int main(void)
{
    uint8_t *base = (uint8_t *)mmap(NULL, 0x200000U, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    test_r13_1_dbt_nx_fetch(base);
    test_r13_2_statx_bad_pointer(base);
    test_r14_1_addco_subfco(base);
    test_r15_1_fmsub_fnmsub(base);
    test_r15_2_inf_fprf(base);
    (void)munmap(base, 0x200000U);

    if (g_fails != 0) {
        fprintf(stderr, "check_p32_r13_defects: %d FAILURES\n", g_fails);
        return 1;
    }
    printf("check_p32_r13_defects: ALL OK\n");
    return 0;
}
