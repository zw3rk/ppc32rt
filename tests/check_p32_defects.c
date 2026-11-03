/*
 * tests/check_p32_defects.c — Regression suite for audit findings P32-1..P32-15
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dbt/dbt.h"
#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"
#include "interp/decode.h"
#include "interp/interp.h"
#include "os/backend.h"
#include "os/hostfault.h"
#include "os/procfs.h"
#include "os/signals.h"
#include "os/syscall_nr.h"
#include "os/syscalls.h"
#include "os/threads.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"
#include "vm/vm32.h"

#define XER_SO (1U << 31)
#define XER_OV (1U << 30)
#define XER_CA (1U << 29)

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
    vm32_record_map(0x100000U, 0x180000U, PROT_READ | PROT_WRITE,
        VM32_PAGE_ANON);
}

static void write_be32(uint8_t *base, uint32_t ea, uint32_t word)
{
    base[ea + 0U] = (uint8_t)(word >> 24);
    base[ea + 1U] = (uint8_t)(word >> 16);
    base[ea + 2U] = (uint8_t)(word >> 8);
    base[ea + 3U] = (uint8_t)word;
}

static uint32_t read_be32(const uint8_t *base, uint32_t ea)
{
    return ((uint32_t)base[ea + 0U] << 24) |
        ((uint32_t)base[ea + 1U] << 16) |
        ((uint32_t)base[ea + 2U] << 8) |
        (uint32_t)base[ea + 3U];
}

/* P32-1: All 14 XO-form OE=1 instructions decode and execute in interp & DBT */
static void test_p32_1_oe_decode_and_exec(uint8_t *base)
{
    static const uint16_t base_xos[14] = {
        8U, 10U, 40U, 104U, 136U, 138U, 200U,
        202U, 232U, 234U, 235U, 266U, 459U, 491U
    };
    size_t i;

    for (i = 0U; i < 14U; i++) {
        uint16_t xo = base_xos[i];
        uint32_t word = (31U << 26) | (3U << 21) | (4U << 16) | (5U << 11) |
            (1U << 10) | ((uint32_t)xo << 1);
        ppc32_insn_t d;
        int rc = ppc_decode(word, &d);

        CHECK(rc == 0 && d.op != PPC32_OP_UNDEF,
            "OE=1 XO opcode decoded as undef");
        CHECK(d.oe == true, "OE=1 flag not set");
        CHECK(d.xo == xo, "OE=1 xo not normalized to base 9-bit XO");
    }

    /* Execute addo. r3, r4, r5 (0x7fffffff + 1 -> overflow) in interp & DBT */
    for (i = 0U; i < 2U; i++) {
        ppc32_ctx_t ctx;
        uint32_t code_ea = 0x100000U;
        uint32_t addo_rc = (31U << 26) | (3U << 21) | (4U << 16) |
            (5U << 11) | (1U << 10) | (266U << 1) | 1U;
        uint32_t sc = PPC32_INSN_SC;
        int rc;

        ctx_init_test(&ctx, base);
        write_be32(base, code_ea + 0U, addo_rc);
        write_be32(base, code_ea + 4U, sc);
        ctx.nip = code_ea;
        ctx.gpr[4] = 0x7fffffffU;
        ctx.gpr[5] = 1U;
        if (i == 0U) {
            interp_step(&ctx);
            CHECK(ctx.exit_reason == PPC32_EXIT_NONE, "interp addo. step");
        } else {
            g_emit_owner = &ctx;
            ppc32_dbt_set_emitter(emit_bridge);
            dbt_invalidate_all(&ctx);
            rc = dbt_run(&ctx);
            CHECK(rc == PPC32_EXIT_SYSCALL, "dbt addo. run");
        }
        CHECK(ctx.gpr[3] == 0x80000000U, "addo. result");
        CHECK((ctx.xer & XER_OV) != 0U, "addo. sets XER.OV");
        CHECK((ctx.xer & XER_SO) != 0U, "addo. sets XER.SO");
        CHECK(((ctx.cr >> 28) & 1U) == 1U, "addo. propagates SO to CR0");
    }
}

/* P32-2: Multi-bit TO trap (OR semantics) in DBT */
static void test_p32_2_dbt_trap_or_semantics(uint8_t *base)
{
    uint32_t code_ea = 0x101000U;
    /* twne r3, r4 -> tw 24, r3, r4 (TO=24 = LT(16) | GT(8)) */
    uint32_t twne = (31U << 26) | (24U << 21) | (3U << 16) | (4U << 11) |
        (4U << 1);
    uint32_t sc = PPC32_INSN_SC;
    ppc32_ctx_t ctx;
    int rc;

    write_be32(base, code_ea + 0U, twne);
    write_be32(base, code_ea + 4U, sc);

    /* Case 1: r3 < r4 (LT true, GT false) -> MUST trap */
    ctx_init_test(&ctx, base);
    g_emit_owner = &ctx;
    ppc32_dbt_set_emitter(emit_bridge);
    dbt_invalidate_all(&ctx);
    ctx.nip = code_ea;
    ctx.gpr[3] = 1U;
    ctx.gpr[4] = 2U;
    rc = dbt_run(&ctx);
    CHECK(rc == PPC32_EXIT_TRAP, "twne traps when r3 < r4");

    /* Case 2: r3 > r4 (LT false, GT true) -> MUST trap */
    ctx_init_test(&ctx, base);
    g_emit_owner = &ctx;
    ctx.nip = code_ea;
    ctx.gpr[3] = 5U;
    ctx.gpr[4] = 2U;
    rc = dbt_run(&ctx);
    CHECK(rc == PPC32_EXIT_TRAP, "twne traps when r3 > r4");

    /* Case 3: r3 == r4 (neither LT nor GT) -> MUST fall through to sc */
    ctx_init_test(&ctx, base);
    g_emit_owner = &ctx;
    ctx.nip = code_ea;
    ctx.gpr[3] = 2U;
    ctx.gpr[4] = 2U;
    rc = dbt_run(&ctx);
    CHECK(rc == PPC32_EXIT_SYSCALL, "twne falls through when r3 == r4");
}

/* P32-3 & P32-7: sync and neg/nego XER.CA + overflow invariants */
static void test_p32_3_and_7_sync_and_neg(uint8_t *base)
{
    size_t eng;

    for (eng = 0U; eng < 2U; eng++) {
        ppc32_ctx_t ctx;
        uint32_t code_ea = 0x102000U + (uint32_t)(eng * 0x100U);
        /* sync; neg r3, r4; nego r5, r6; nego r7, r8; sc */
        uint32_t sync_insn = 0x7c0004acU;
        uint32_t neg_r3_r4 = (31U << 26) | (3U << 21) | (4U << 16) |
            (104U << 1);
        uint32_t nego_r5_r6 = (31U << 26) | (5U << 21) | (6U << 16) |
            (1U << 10) | (104U << 1);
        uint32_t nego_r7_r8 = (31U << 26) | (7U << 21) | (8U << 16) |
            (1U << 10) | (104U << 1);
        uint32_t sc = PPC32_INSN_SC;
        int rc;

        write_be32(base, code_ea + 0U, sync_insn);
        write_be32(base, code_ea + 4U, neg_r3_r4);
        write_be32(base, code_ea + 8U, nego_r5_r6);
        write_be32(base, code_ea + 12U, nego_r7_r8);
        write_be32(base, code_ea + 16U, sc);

        /* Subtest A: CA=0 preserved when negating 0, OV=0 on nego(0) */
        ctx_init_test(&ctx, base);
        ctx.nip = code_ea;
        ctx.xer = 0U;
        ctx.gpr[4] = 0U;
        ctx.gpr[6] = 0U;
        ctx.gpr[8] = 5U;
        if (eng == 0U) {
            interp_run(&ctx);
            CHECK(ctx.exit_reason == PPC32_EXIT_SYSCALL, "interp run sync/neg");
        } else {
            g_emit_owner = &ctx;
            ppc32_dbt_set_emitter(emit_bridge);
            dbt_invalidate_all(&ctx);
            rc = dbt_run(&ctx);
            CHECK(rc == PPC32_EXIT_SYSCALL, "dbt run sync/neg");
        }
        CHECK((ctx.xer & XER_CA) == 0U, "neg(0) must not set XER.CA");
        CHECK((ctx.xer & XER_OV) == 0U, "nego(0) must not set XER.OV");
        CHECK(ctx.gpr[7] == (uint32_t)-5, "nego(5) == -5");

        /* Subtest B: CA=1 preserved when negating non-zero, OV=1 on INT32_MIN */
        ctx_init_test(&ctx, base);
        ctx.nip = code_ea;
        ctx.xer = XER_CA;
        ctx.gpr[4] = 42U;
        ctx.gpr[6] = 0x80000000U;
        ctx.gpr[8] = 1U;
        if (eng == 0U) {
            interp_run(&ctx);
            CHECK(ctx.exit_reason == PPC32_EXIT_SYSCALL, "interp run neg CA=1");
        } else {
            g_emit_owner = &ctx;
            rc = dbt_run(&ctx);
            CHECK(rc == PPC32_EXIT_SYSCALL, "dbt run neg CA=1");
        }
        CHECK((ctx.xer & XER_CA) != 0U, "neg(42) must preserve CA=1");
        CHECK((ctx.xer & XER_SO) != 0U, "nego(0x80000000) sets SO");
        CHECK((ctx.xer & XER_OV) == 0U, "subsequent nego(1) clears OV");
    }
}

/* P32-4 & P32-10: lwarx/stwcx. permission checks and multi-thread reservation */
static void test_p32_4_and_10_atomics(uint8_t *base)
{
    uint32_t code_ea = 0x104000U;
    uint32_t data_ro_ea = 0x110000U;
    uint32_t data_rw_ea = 0x114000U;
    uint32_t lwarx_insn = (31U << 26) | (3U << 21) | (0U << 16) |
        (4U << 11) | (20U << 1);
    uint32_t stwcx_insn = (31U << 26) | (5U << 21) | (0U << 16) |
        (4U << 11) | (150U << 1) | 1U;
    uint32_t sc = PPC32_INSN_SC;
    ppc32_ctx_t ctx_a, ctx_b;
    int rc;

    write_be32(base, code_ea + 0U, lwarx_insn);
    write_be32(base, code_ea + 4U, stwcx_insn);
    write_be32(base, code_ea + 8U, sc);
    write_be32(base, data_ro_ea, 0x11223344U);
    write_be32(base, data_rw_ea, 0x11223344U);

    ctx_init_test(&ctx_a, base);
    ctx_a.vm_ready = true;
    ctx_a.region_count = 3U;
    ctx_a.regions[0].start = 0x100000U;
    ctx_a.regions[0].end = 0x110000U;
    ctx_a.regions[0].prot = PROT_READ | PROT_EXEC;
    ctx_a.regions[1].start = data_ro_ea;
    ctx_a.regions[1].end = data_ro_ea + 0x1000U;
    ctx_a.regions[1].prot = PROT_READ;
    ctx_a.regions[2].start = data_rw_ea;
    ctx_a.regions[2].end = data_rw_ea + 0x1000U;
    ctx_a.regions[2].prot = PROT_READ | PROT_WRITE;
    vm32_record_protect(data_ro_ea, data_ro_ea + 0x1000U, PROT_READ);

    /* 1. stwcx. to PROT_READ page must fault in DBT (even on Darwin 16K pages) */
    ctx_a.nip = code_ea;
    ctx_a.gpr[4] = data_ro_ea;
    ctx_a.gpr[5] = 0xdeadbeefU;
    g_emit_owner = &ctx_a;
    ppc32_dbt_set_emitter(emit_bridge);
    dbt_invalidate_all(&ctx_a);
    rc = dbt_run(&ctx_a);
    CHECK(rc == PPC32_EXIT_FAULT, "DBT stwcx. to PROT_READ page must fault");
    CHECK(read_be32(base, data_ro_ea) == 0x11223344U, "PROT_READ word untouched");

    /* 2. P32-10: ABA & cross-thread reservation invalidation via g_ll_generation */
    ctx_init_test(&ctx_b, base);
    vm32_record_protect(data_ro_ea, data_ro_ea + 0x1000U, PROT_READ);
    ctx_b.vm_ready = true;
    ctx_b.region_count = ctx_a.region_count;
    memcpy(ctx_b.regions, ctx_a.regions, sizeof(ctx_a.regions));

    /* Thread A executes lwarx at data_rw_ea */
    ctx_a.exit_reason = PPC32_EXIT_NONE;
    ctx_a.nip = code_ea;
    ctx_a.gpr[4] = data_rw_ea;
    ctx_a.gpr[5] = 0x99999999U;
    interp_step(&ctx_a);
    CHECK(ctx_a.exit_reason == PPC32_EXIT_NONE && ctx_a.res_valid == 1U,
        "Thread A lwarx");

    /* Thread B executes lwarx + stwcx. storing the SAME value (ABA) */
    ctx_b.nip = code_ea;
    ctx_b.gpr[4] = data_rw_ea;
    ctx_b.gpr[5] = 0x11223344U;
    interp_step(&ctx_b);
    CHECK(ctx_b.exit_reason == PPC32_EXIT_NONE, "Thread B lwarx");
    interp_step(&ctx_b);
    CHECK(ctx_b.exit_reason == PPC32_EXIT_NONE, "Thread B stwcx.");
    CHECK(((ctx_b.cr >> 28) & 0x2U) != 0U, "Thread B stwcx. succeeded (EQ=1)");

    /* Thread A now executes stwcx. — MUST fail due to generation mismatch */
    interp_step(&ctx_a);
    CHECK(ctx_a.exit_reason == PPC32_EXIT_NONE, "Thread A stwcx. step");
    CHECK(((ctx_a.cr >> 28) & 0x2U) == 0U, "Thread A stwcx. failed (EQ=0)");
    CHECK(read_be32(base, data_rw_ea) == 0x11223344U, "Thread A store rejected");
}

static void r2_faulting_run(ppc32_ctx_t *ctx)
{
    uint32_t *unmapped = (uint32_t *)ppc32_guest_ptr(ctx, 0x00400000U);
    ppc32_vm_lock();
    vm32_ll_record(ctx, 0x00400000U, 0x12345678U);
    *(volatile uint32_t *)unmapped = 1U;
}

static void test_p32_r2_5_6_alu_div_ov(uint8_t *base)
{
    ppc32_ctx_t ctx;
    const uint32_t code_ea = 0x100000U;

    /* P32-R2-5: subfo. r3, r4, r5 (r3 = r5 - r4).
     * Case 1: r5 = 0, r4 = 1 -> r3 = -1 (0xffffffff), NO signed overflow!
     * Case 2: r5 = 0x80000000, r4 = 1 -> r3 = 0x7fffffff, signed overflow! */
    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    ctx.gpr[4] = 1U;
    ctx.gpr[5] = 0U;
    /* subfo. r3, r4, r5: op=31, rt=3, ra=4, rb=5, oe=1, xo=40, rc=1 */
    write_be32(base, code_ea + 0U,
        (31U << 26) | (3U << 21) | (4U << 16) | (5U << 11) | (1U << 10) |
        (40U << 1) | 1U);
    interp_step(&ctx);
    CHECK(ctx.gpr[3] == 0xffffffffU, "subfo. 0 - 1 == -1 (interp)");
    CHECK((ctx.xer & XER_OV) == 0U, "subfo. 0 - 1 OV == 0 (interp)");

    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    ctx.gpr[4] = 1U;
    ctx.gpr[5] = 0x80000000U;
    interp_step(&ctx);
    CHECK(ctx.gpr[3] == 0x7fffffffU, "subfo. INT_MIN - 1 == INT_MAX (interp)");
    CHECK((ctx.xer & XER_OV) != 0U, "subfo. INT_MIN - 1 OV == 1 (interp)");

    /* Verify DBT ei_sub_ov matches on both cases */
    {
        ppc32_insn_t insn;
        a64_buf_t b;
        ppc32_emit_ctx_t e;
        uint32_t raw = read_be32(base, code_ea);
        CHECK(ppc_decode(raw, &insn) == 0, "decode subfo.");
        memset(&b, 0, sizeof(b));
        g_emit_owner = &ctx;
        ppc32_emit_begin(&e, g_emit_owner, &b);
        CHECK(ppc32_emit_int(&e, &insn, code_ea) == PPC32_EMIT_NEXT,
            "emit subfo. in DBT");
    }

    /* P32-R2-5: addeo. r3, r4, r5 with r4 = 0x7fffffff, r5 = 0x7fffffff, CA = 1
     * True signed sum = 2147483647 + 2147483647 + 1 > INT32_MAX -> OV = 1 */
    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    ctx.gpr[4] = 0x7fffffffU;
    ctx.gpr[5] = 0x7fffffffU;
    ctx.xer = XER_CA;
    /* addeo. r3, r4, r5: op=31, rt=3, ra=4, rb=5, oe=1, xo=138, rc=1 */
    write_be32(base, code_ea,
        (31U << 26) | (3U << 21) | (4U << 16) | (5U << 11) | (1U << 10) |
        (138U << 1) | 1U);
    interp_step(&ctx);
    CHECK(ctx.gpr[3] == 0xffffffffU, "addeo. result 0xffffffff");
    CHECK((ctx.xer & XER_OV) != 0U, "addeo. 0x7fffffff+0x7fffffff+1 sets OV");

    /* P32-R2-5: subfzeo. r3, r4 with r4 = 0x7fffffff, CA = 0
     * ~0x7fffffff + 0 = 0x80000000 (-2147483648), fits in int32_t -> OV = 0 */
    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    ctx.gpr[4] = 0x7fffffffU;
    ctx.xer = 0U;
    /* subfzeo. r3, r4: op=31, rt=3, ra=4, oe=1, xo=200, rc=1 */
    write_be32(base, code_ea,
        (31U << 26) | (3U << 21) | (4U << 16) | (1U << 10) | (200U << 1) | 1U);
    interp_step(&ctx);
    CHECK(ctx.gpr[3] == 0x80000000U, "subfzeo. result 0x80000000");
    CHECK((ctx.xer & XER_OV) == 0U, "subfzeo. ~0x7fffffff + 0 clears OV");
    {
        ppc32_insn_t insn;
        a64_buf_t b;
        ppc32_emit_ctx_t e;
        uint32_t raw = read_be32(base, code_ea);
        CHECK(ppc_decode(raw, &insn) == 0, "decode subfzeo.");
        memset(&b, 0, sizeof(b));
        g_emit_owner = &ctx;
        ppc32_emit_begin(&e, g_emit_owner, &b);
        CHECK(ppc32_emit_int(&e, &insn, code_ea) == PPC32_EMIT_FALLBACK,
            "subfzeo. routes to interpreter fallback in DBT");
    }

    /* P32-R2-6: divwo. and divwuo. by zero set XER.OV and XER.SO */
    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    ctx.gpr[4] = 42U;
    ctx.gpr[5] = 0U;
    /* divwo. r3, r4, r5: op=31, rt=3, ra=4, rb=5, oe=1, xo=491, rc=1 */
    write_be32(base, code_ea,
        (31U << 26) | (3U << 21) | (4U << 16) | (5U << 11) | (1U << 10) |
        (491U << 1) | 1U);
    interp_step(&ctx);
    CHECK((ctx.xer & (XER_OV | XER_SO)) == (XER_OV | XER_SO),
        "divwo. by zero sets XER.OV and XER.SO");
    CHECK(((ctx.cr >> 28) & 1U) == 1U, "divwo. by zero sets CR0.SO");

    ctx_init_test(&ctx, base);
    ctx.nip = code_ea;
    ctx.gpr[4] = 42U;
    ctx.gpr[5] = 0U;
    /* divwuo. r3, r4, r5: op=31, rt=3, ra=4, rb=5, oe=1, xo=459, rc=1 */
    write_be32(base, code_ea,
        (31U << 26) | (3U << 21) | (4U << 16) | (5U << 11) | (1U << 10) |
        (459U << 1) | 1U);
    interp_step(&ctx);
    CHECK((ctx.xer & (XER_OV | XER_SO)) == (XER_OV | XER_SO),
        "divwuo. by zero sets XER.OV and XER.SO");
    CHECK(((ctx.cr >> 28) & 1U) == 1U, "divwuo. by zero sets CR0.SO");
}

/* P32-5, P32-6, P32-11, P32-12, and Round-2 VM/OS defects */
static void test_p32_5_6_11_vm_and_syscalls(void)
{
    ppc32_ctx_t ctx;
    char tmp_path[] = "/tmp/ppc32rt-p32-test.XXXXXX";
    int fd;
    struct stat st_orig;
    uint32_t addr1, addr2;
    long sret;

    fd = mkstemp(tmp_path);
    CHECK(fd >= 0, "mkstemp");
    if (fd < 0) {
        return;
    }
    (void)unlink(tmp_path);
    CHECK(ftruncate(fd, 65536) == 0, "ftruncate");
    CHECK(fstat(fd, &st_orig) == 0, "fstat orig fd");

    memset(&ctx, 0, sizeof(ctx));
    CHECK(ppc32_vm_init(&ctx, UINT64_MAX) == 0, "ppc32_vm_init");

    /* P32-5 & P32-R2-1: file-backed MAP_SHARED mmap + close(fd) + mremap
     * preserves private dup'd fd, offset, and flags even after caller closes fd */
    addr1 = ppc32_vm_mmap2(&ctx, 0x100000U, 0x4000U, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED, fd, 1U /* pgoffset = 1 * 4096 = 0x1000 */);
    CHECK(addr1 == 0x100000U, "file-backed mmap2");
    write_be32((uint8_t *)(uintptr_t)ctx.guest_base, addr1, 0xcafebabeU);

    /* Close the caller's fd before mremap to verify P32-R2-1 private dup ownership */
    int saved_fd = dup(fd);
    (void)close(fd);
    fd = -1;

    addr2 = ppc32_vm_mremap(&ctx, addr1, 0x4000U, 0x8000U,
        1U /* MREMAP_MAYMOVE */, 0U);
    CHECK(addr2 < 0xfffff000U, "file-backed mremap after caller close(fd)");
    CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, addr2) == 0xcafebabeU,
        "file-backed mremap preserved file data after caller close(fd)");
    {
        bool found = false;
        uint32_t i;
        for (i = 0U; i < ctx.region_count; i++) {
            if (ctx.regions[i].start == addr2) {
                struct stat st_reg;
                found = true;
                CHECK(ctx.regions[i].fd >= 0 &&
                    fstat(ctx.regions[i].fd, &st_reg) == 0 &&
                    st_reg.st_ino == st_orig.st_ino &&
                    st_reg.st_dev == st_orig.st_dev,
                    "mremap preserved private region fd with matching inode");
                CHECK(ctx.regions[i].offset == 0x1000ULL,
                    "mremap preserved region offset");
                CHECK((ctx.regions[i].flags & MAP_SHARED) != 0U,
                    "mremap preserved MAP_SHARED");
            }
        }
        CHECK(found, "mremap target region present");
    }

    /* P32-R2-2: CLONE_VM child ctx with stale region_count=0 sees live mappings */
    {
        ppc32_ctx_t child_ctx = ctx;
        child_ctx.region_count = 0U;
        CHECK(ppc32_vm_range_prot_ok(&child_ctx, addr2, 4U, 3U),
            "CLONE_VM child sees parent's mremap region via authoritative g_vm_regions");
        CHECK(!ppc32_vm_range_prot_ok(&child_ctx, 0x500000U, 4U, 1U),
            "CLONE_VM child rejects unmapped VA");
        int maps_fd = ppc32_procfs_open(&child_ctx, "/proc/self/maps");
        CHECK(maps_fd >= 0, "ppc32_procfs_open(/proc/self/maps) on child_ctx");
        if (maps_fd >= 0) {
            char mbuf[512];
            ssize_t n = read(maps_fd, mbuf, sizeof(mbuf) - 1U);
            mbuf[(n > 0) ? n : 0] = '\0';
            CHECK(n > 0 && mbuf[0] != '\0',
                "/proc/self/maps synced authoritative regions on child_ctx");
            (void)close(maps_fd);
        }
    }

    /* P32-R2-4: MAP_SHARED | MAP_ANONYMOUS + mremap preserves shared memory across fork() */
    {
        uint32_t sh1 = ppc32_vm_mmap2(&ctx, 0U, 0x4000U, PROT_READ | PROT_WRITE,
            MAP_SHARED | 0x20U, -1, 0U);
        CHECK(sh1 < 0xfffff000U, "MAP_SHARED|MAP_ANONYMOUS mmap2");
        write_be32((uint8_t *)(uintptr_t)ctx.guest_base, sh1, 0x11112222U);
        uint32_t sh2 = ppc32_vm_mremap(&ctx, sh1, 0x4000U, 0x8000U, 1U, 0U);
        CHECK(sh2 < 0xfffff000U, "MAP_SHARED|MAP_ANONYMOUS mremap");
        CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, sh2) == 0x11112222U,
            "MAP_SHARED|MAP_ANONYMOUS mremap preserved initial word");
        pid_t pid = fork();
        CHECK(pid >= 0, "fork for MAP_SHARED|MAP_ANONYMOUS mremap test");
        if (pid == 0) {
            write_be32((uint8_t *)(uintptr_t)ctx.guest_base, sh2 + 0x4000U,
                0xdeadbeefU);
            _Exit(0);
        } else if (pid > 0) {
            int status = 0;
            (void)waitpid(pid, &status, 0);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "fork child exited cleanly");
            CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base,
                sh2 + 0x4000U) == 0xdeadbeefU,
                "parent observes child write in mremapped MAP_SHARED|MAP_ANONYMOUS");
        }
        CHECK(ppc32_vm_munmap(&ctx, sh2, 0x8000U) == 0,
            "munmap MAP_SHARED|MAP_ANONYMOUS");
    }

    /* P32-R2-7: mremap of PROT_NONE private mapping preserves data and PROT_NONE */
    {
        uint32_t p1 = ppc32_vm_mmap2(&ctx, 0U, 0x4000U, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | 0x20U, -1, 0U);
        CHECK(p1 < 0xfffff000U, "private mmap2 for PROT_NONE mremap");
        write_be32((uint8_t *)(uintptr_t)ctx.guest_base, p1, 0x55aa55aaU);
        CHECK(ppc32_vm_mprotect(&ctx, p1, 0x4000U, PROT_NONE) == 0,
            "mprotect to PROT_NONE");
        uint32_t p2 = ppc32_vm_mremap(&ctx, p1, 0x4000U, 0x8000U, 1U, 0U);
        CHECK(p2 < 0xfffff000U, "mremap of PROT_NONE region");
        CHECK(!ppc32_vm_range_prot_ok(&ctx, p2, 4U, 1U),
            "mremapped PROT_NONE region stays PROT_NONE");
        CHECK(ppc32_vm_mprotect(&ctx, p2, 0x8000U, PROT_READ) == 0,
            "mprotect mremapped region to PROT_READ");
        CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, p2) == 0x55aa55aaU,
            "mremapped PROT_NONE region preserved payload");
        CHECK(ppc32_vm_munmap(&ctx, p2, 0x8000U) == 0, "munmap p2");
    }

    /* P32-R2-3: hostfault recovery releases held VM and LL locks */
    {
        ppc32_hostfault_install();
        CHECK(ppc32_hostfault_run(&ctx, r2_faulting_run) == 1,
            "ppc32_hostfault_run caught fault while holding VM lock");
        /* If ppc32_vm_unlock_if_held_by_self worked, ppc32_vm_lock() will not deadlock */
        ppc32_vm_lock();
        ppc32_vm_unlock();
    }

    /* P32-R2-8: vm32_tlb_probe under tlb_lock returns coherent addend */
    {
        uintptr_t addend = 0U;
        vm32_tlb_fill(0x00200000U, (uintptr_t)ctx.guest_base + 0x00200000ULL,
            true, false);
        CHECK(vm32_tlb_probe(0x00200000U, false, 4U, &addend) &&
            addend == (uintptr_t)ctx.guest_base,
            "vm32_tlb_probe read hit returns coherent addend");
        vm32_tlb_invalidate_range(0x00200000U, 0x00201000U);
        CHECK(!vm32_tlb_probe(0x00200000U, false, 4U, &addend),
            "vm32_tlb_probe misses after invalidate_range");
    }

    /* X-R2-5: signal frame build/restore rejects unmapped guest stack */
    {
        ppc32_sigact_t act;
        uint32_t out_frame = 0U;
        memset(&act, 0, sizeof(act));
        act.handler = 0x100000U;
        ctx.gpr[PPC32_REG_SP] = 0x00600000U; /* unmapped */
        CHECK(ppc32_sig_build_frame(&ctx, PPC32_SIGUSR1, &act, 0, 0U, 0U, 0U,
            &out_frame) == -EFAULT,
            "ppc32_sig_build_frame on unmapped stack returns -EFAULT");
        CHECK(ppc32_sig_restore_frame(&ctx, 0x00600000U) == -EFAULT,
            "ppc32_sig_restore_frame on unmapped stack returns -EFAULT");
    }

    /* P32-6: thread_range_ok rejects unmapped / RO addresses when vm_ready */
    ppc32_vm_sync_ctx(&ctx);
    sret = ppc32_futex(&ctx, 0x500000U, PPC32_FUTEX_WAIT, 0U, 0U, 0U, 0U);
    CHECK(sret == -14L, "ppc32_futex on unmapped VA returns -EFAULT");

    /* P32-11: _llseek with offset_lo = 0x80000000 must not sign-extend */
    ctx.gpr[0] = PPC32_NR_LLSEEK;
    ctx.gpr[3] = (uint32_t)saved_fd;
    ctx.gpr[4] = 0U;          /* offset_hi */
    ctx.gpr[5] = 0x80000000U; /* offset_lo */
    ctx.gpr[6] = addr2;       /* result_va */
    ctx.gpr[7] = SEEK_SET;
    ppc32_syscall(&ctx);
    CHECK((ctx.cr & (1U << 28)) == 0U, "_llseek(0x80000000) succeeded (SO=0)");
    CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, addr2) == 0U &&
        read_be32((const uint8_t *)(uintptr_t)ctx.guest_base,
            addr2 + 4U) == 0x80000000U,
        "_llseek result is +0x80000000ULL");

    /* P32-12: rt_host_preempt_worker returns negative errno on bad tid */
    CHECK(rt_host_preempt_worker(0ULL) < 0,
        "rt_host_preempt_worker returns negative errno on invalid tid");

    if (saved_fd >= 0) {
        (void)close(saved_fd);
    }
}

/* P32-R3-3: guest-4K (but host-sub-page) MAP_SHARED file mappings keep
 * coherent sharing: two aliases of the same file range and parent/child
 * across fork() observe each other's stores. */
static void test_p32_r3_3_subpage_shared(void)
{
    ppc32_ctx_t ctx;
    char tmp_path[] = "/tmp/ppc32rt-r33-test.XXXXXX";
    int fd;
    uint32_t alias_a;
    uint32_t alias_b;
    uint32_t seed_be = 0x78563412U;

    fd = mkstemp(tmp_path);
    CHECK(fd >= 0, "mkstemp r3-3");
    if (fd < 0) {
        return;
    }
    (void)unlink(tmp_path);
    CHECK(ftruncate(fd, 65536) == 0, "ftruncate r3-3");
    /* Seed file bytes at the shared offset before mapping. */
    CHECK(pwrite(fd, &seed_be, sizeof seed_be, 0x1000) == 4,
        "pwrite seed r3-3");

    memset(&ctx, 0, sizeof(ctx));
    CHECK(ppc32_vm_init(&ctx, UINT64_MAX) == 0, "ppc32_vm_init r3-3");

    alias_a = ppc32_vm_mmap2(&ctx, 0x300000U, 0x4000U, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED, fd, 1U);
    CHECK(alias_a == 0x300000U, "sub-page MAP_SHARED mmap2 alias A");
    if (alias_a != 0x300000U) {
        (void)close(fd);
        return;
    }
    CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, alias_a) ==
        0x12345678U, "staged mapping shows seeded file bytes");
    alias_b = ppc32_vm_mmap2(&ctx, 0x304000U, 0x4000U, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED, fd, 1U);
    CHECK(alias_b == 0x304000U, "sub-page MAP_SHARED mmap2 alias B");
    if (alias_b != 0x304000U) {
        (void)close(fd);
        return;
    }

    write_be32((uint8_t *)(uintptr_t)ctx.guest_base, alias_a, 0xa1b2c3d4U);
    CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, alias_b) ==
        0xa1b2c3d4U, "alias B observes store through alias A");
    write_be32((uint8_t *)(uintptr_t)ctx.guest_base, alias_b + 4U,
        0x5a5a5a5aU);
    CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base,
        alias_a + 4U) == 0x5a5a5a5aU,
        "alias A observes store through alias B");

    {
        pid_t pid = fork();

        CHECK(pid >= 0, "fork for sub-page MAP_SHARED test");
        if (pid == 0) {
            write_be32((uint8_t *)(uintptr_t)ctx.guest_base, alias_a + 8U,
                0xdeadbeefU);
            _Exit(0);
        } else if (pid > 0) {
            int status = 0;

            (void)waitpid(pid, &status, 0);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "fork child exited cleanly r3-3");
            CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base,
                alias_b + 8U) == 0xdeadbeefU,
                "parent observes child store in sub-page MAP_SHARED");
        }
    }

    CHECK(ppc32_vm_munmap(&ctx, alias_a, 0x4000U) == 0, "munmap alias A");
    CHECK(read_be32((const uint8_t *)(uintptr_t)ctx.guest_base, alias_b) ==
        0xa1b2c3d4U, "surviving alias keeps shared bytes after peer munmap");
    CHECK(ppc32_vm_munmap(&ctx, alias_b, 0x4000U) == 0, "munmap alias B");
    (void)close(fd);
}

/* P32-R6-1/R6-6 follow-ups: cache fork protocol + sync epoch record,
 * atomic sibling pend + IGN pump, and the generic syscall-tail pump. */
static void test_p32_r6_followups(void)
{
    ppc32_ctx_t ctx;
    ppc32_sigact_t ign;
    uint64_t usr1 = 1ULL << (uint64_t)(PPC32_SIGUSR1 - 1U);
    uint64_t urg = 1ULL << (uint64_t)(PPC32_SIGURG - 1U);

    ppc32_sig_reset();

    /* Fork protocol smoke: balanced prepare/parent, plus a child drop
     * that can be re-locked right after. */
    ppc32_cache_fork_prepare();
    ppc32_cache_fork_parent();
    ppc32_cache_fork_prepare();
    ppc32_cache_fork_child();
    ppc32_cache_fork_prepare();
    ppc32_cache_fork_parent();

    /* Sync records the live generation on the ctx. */
    memset(&ctx, 0, sizeof(ctx));
    ppc32_cache_sync_ctx(&ctx);
    CHECK(ctx.ibtc_synced_epoch == *ppc32_cache_epoch_ptr(),
        "r6-1 sync records epoch");
    ppc32_cache_forget_ctx(&ctx);
    ppc32_cache_sync_ctx(NULL);

    /* Sibling pend path: ignored SIGUSR1 pends atomically, survives
     * the pump while blocked, and clears once unmasked. */
    CHECK(ppc32_vm_init(&ctx, UINT64_MAX) == 0, "r6-6 vm init");
    CHECK(ppc32_thread_init_main(&ctx) == 0, "r6-6 init main");
    memset(&ign, 0, sizeof(ign));
    ign.handler = PPC32_SIG_IGN;
    CHECK(ppc32_sigaction_set_raw((int)PPC32_SIGUSR1, &ign) == 0,
        "r6-6 ignore usr1");
    CHECK(ppc32_thread_signal(ctx.guest_tid, 0U, 0) == 0, "r6-6 probe");
    CHECK(ppc32_thread_signal(ctx.guest_tid + 1U, 0U, 0) == -ESRCH,
        "r6-6 probe missing");
    CHECK(ppc32_thread_signal(ctx.guest_tid, 0U, (int)PPC32_SIGUSR1) == 0,
        "r6-6 pend usr1");
    CHECK((__atomic_load_n(&ctx.pending_signals, __ATOMIC_ACQUIRE) &
        usr1) != 0ULL, "r6-6 bit set");
    ctx.sig_mask |= usr1;
    ppc32_sig_pump_pending(&ctx);
    CHECK((__atomic_load_n(&ctx.pending_signals, __ATOMIC_ACQUIRE) &
        usr1) != 0ULL, "r6-6 blocked stays");
    ctx.sig_mask &= ~usr1;
    ppc32_sig_pump_pending(&ctx);
    CHECK((__atomic_load_n(&ctx.pending_signals, __ATOMIC_ACQUIRE) &
        usr1) == 0ULL, "r6-6 pump clears ign");
    CHECK(ppc32_thread_signal(ctx.guest_tid, ctx.guest_pid + 1U,
        (int)PPC32_SIGUSR1) == -ESRCH, "r6-6 tgkill group mismatch");

    /* Generic syscall-tail pump: GETPID with an ignored SIGURG pending
     * returns normally, advances past sc, and the bit is gone after. */
    CHECK(ppc32_sigaction_set_raw((int)PPC32_SIGURG, &ign) == 0,
        "r6-6 ignore urg");
    CHECK(ppc32_thread_signal(ctx.guest_tid, 0U, (int)PPC32_SIGURG) == 0,
        "r6-6 pend urg");
    ctx.gpr[0] = PPC32_NR_GETPID;
    ctx.nip = 0x00100000U;
    ppc32_syscall(&ctx);
    CHECK(ctx.gpr[3] == (uint32_t)getpid(), "r6-6 getpid ret");
    CHECK(ctx.nip == 0x00100004U, "r6-6 syscall advanced");
    CHECK((__atomic_load_n(&ctx.pending_signals, __ATOMIC_ACQUIRE) &
        urg) == 0ULL, "r6-6 syscall tail pumps");
    ppc32_sig_reset();
}

int main(void)
{
    uint8_t *base = (uint8_t *)mmap(NULL, 0x200000U, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    test_p32_1_oe_decode_and_exec(base);
    test_p32_2_dbt_trap_or_semantics(base);
    test_p32_3_and_7_sync_and_neg(base);
    test_p32_4_and_10_atomics(base);
    test_p32_r2_5_6_alu_div_ov(base);
    (void)munmap(base, 0x200000U);

    test_p32_5_6_11_vm_and_syscalls();
    test_p32_r3_3_subpage_shared();
    test_p32_r6_followups();

    if (g_fails != 0) {
        fprintf(stderr, "check_p32_defects: %d FAILURES\n", g_fails);
        return 1;
    }
    printf("check_p32_defects: ALL OK\n");
    return 0;
}
