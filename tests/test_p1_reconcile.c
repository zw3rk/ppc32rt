/*
 * tests/test_p1_reconcile.c — RC1 decoder<->interp contract test
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guards the Phase 1 lane-integration contract (coordinator RC1 rewire):
 * every opcode id consumed by src/interp/interp.c must be produced by
 * src/interp/decode.c with the agreed field layout, and interp_step must
 * behave through the REAL decoder (L1b accepted against a /tmp stub).
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc \
 *     tests/test_p1_reconcile.c src/interp/decode.c src/interp/interp.c \
 *     -o /tmp/test_p1_reconcile && /tmp/test_p1_reconcile
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ppc32rt.h"
#include "interp/decode.h"
#include "interp/interp.h"

static int fails = 0;

static void expect(const char *name, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("FAIL %-18s got 0x%08X want 0x%08X\n", name, got, want);
        fails++;
    } else {
        printf("ok   %-18s 0x%08X\n", name, got);
    }
}

/* Store one big-endian instruction word at guest offset 0. */
static void put_insn(ppc32_ctx_t *ctx, uint32_t word)
{
    uint8_t *mem = (uint8_t *)(uintptr_t)(uint64_t)ctx->guest_base;

    mem[0] = (uint8_t)(word >> 24);
    mem[1] = (uint8_t)(word >> 16);
    mem[2] = (uint8_t)(word >> 8);
    mem[3] = (uint8_t)word;
}

static ppc32_ctx_t *fresh_ctx(void)
{
    ppc32_ctx_t *ctx = (ppc32_ctx_t *)calloc(1, sizeof(*ctx));
    uint8_t *mem;

    if (ctx == NULL) {
        printf("FAIL oom\n");
        exit(1);
    }
    mem = (uint8_t *)calloc(1, 0x1000);
    if (mem == NULL) {
        printf("FAIL oom\n");
        exit(1);
    }
    ctx->guest_base = (uint64_t)(uintptr_t)mem;
    ctx->nip = 0;
    ctx->exit_reason = PPC32_EXIT_NONE;
    ctx->vm_ready = true;
    return ctx;
}

int main(void)
{
    ppc32_insn_t in;
    ppc32_ctx_t *ctx;

    /* ---- decode spot-checks through the real decoder ---- */
    expect("addic.-rc", (uint32_t)ppc_decode(0x34640005U, &in), 0U);
    expect("addic.-op", in.op, (uint32_t)PPC32_OP_ADDIC_DOT);
    expect("addic.-si", (uint32_t)in.si, 5U);

    expect("cror-rc", (uint32_t)ppc_decode(0x4CA63B82U, &in), 0U);
    expect("cror-op", in.op, (uint32_t)PPC32_OP_CR);
    expect("cror-xo", in.xo, 449U);

    expect("dcbz-rc", (uint32_t)ppc_decode(0x7C0327ECU, &in), 0U);
    expect("dcbz-op", in.op, (uint32_t)PPC32_OP_DCBZ);

    expect("tdi-undef", (uint32_t)(ppc_decode(0x08000000U, &in) != 0), 1U);
    expect("eieio-sync", (uint32_t)ppc_decode(0x7C0006ACU, &in), 0U);
    expect("eieio-op", in.op, (uint32_t)PPC32_OP_SYNC);
    expect("mflr-rc", (uint32_t)ppc_decode(0x7FE802A6U, &in), 0U);
    expect("mflr-op", in.op, (uint32_t)PPC32_OP_MFSPR);
    expect("mflr-spr", in.ui, 8U); /* LR: XFX split is RB<<5|RA */
    expect("beq-rc", (uint32_t)ppc_decode(0x41820008U, &in), 0U);
    expect("beq-op", in.op, (uint32_t)PPC32_OP_BC);
    expect("beq-bd", in.bd, 8U); /* displacement, not raw BD */
    expect("bcback-rc", (uint32_t)ppc_decode(0x4182FFFCU, &in), 0U);
    expect("bcback-bd", in.bd, 0xFFFFFFFCU); /* sign-extended */
    expect("bback-rc", (uint32_t)ppc_decode(0x4BFFFFFCU, &in), 0U);
    expect("bback-li", in.li, 0xFFFFFFFCU); /* sign-extended */

    /* sc leaves nip AT the sc; the syscall layer advances past it. */
    ctx = fresh_ctx();
    put_insn(ctx, 0x44000002U); /* sc */
    interp_step(ctx);
    expect("sc-exit", ctx->exit_reason, PPC32_EXIT_SYSCALL);
    expect("sc-nip", ctx->nip, 0U);

    /* ---- interp through the real decoder: addic. carry + CR0 ---- */
    ctx = fresh_ctx();
    ctx->gpr[4] = 0xFFFFFFFFU;
    put_insn(ctx, 0x34640005U); /* addic. r3, r4, 5 */
    interp_step(ctx);
    expect("addic.-r3", ctx->gpr[3], 4U);
    expect("addic.-ca", ctx->xer & 0x20000000U, 0x20000000U);
    expect("addic.-cr0", ctx->cr & 0xE0000000U, 0x40000000U); /* GT */
    expect("addic.-nip", ctx->nip, 4U);

    /* ---- interp: cror sets CR bit 5 from bits 6|7 ---- */
    ctx->nip = 0;
    ctx->exit_reason = PPC32_EXIT_NONE;
    ctx->cr = 0x02000000U; /* bit 6 set */
    put_insn(ctx, 0x4CA63B82U); /* cror 5, 6, 7 */
    interp_step(ctx);
    expect("cror-cr", ctx->cr, 0x06000000U);
    expect("cror-nip", ctx->nip, 4U);

    /* ---- interp: tw TO=31 always traps ---- */
    ctx->nip = 0;
    ctx->exit_reason = PPC32_EXIT_NONE;
    ctx->gpr[3] = 1;
    put_insn(ctx, 0x7FE32008U); /* tw 31, r3, r4 */
    interp_step(ctx);
    expect("tw-exit", ctx->exit_reason, PPC32_EXIT_TRAP);

    /* ---- interp: dcbz zeroes 32 bytes at EA ---- */
    ctx->nip = 0;
    ctx->exit_reason = PPC32_EXIT_NONE;
    ctx->gpr[3] = 0x100;
    ctx->gpr[4] = 0;
    memset((uint8_t *)(uintptr_t)(uint64_t)ctx->guest_base + 0x100, 0xA5, 32);
    put_insn(ctx, 0x7C0327ECU); /* dcbz r0, r3, r4 */
    interp_step(ctx);
    {
        uint8_t *blk = (uint8_t *)(uintptr_t)(uint64_t)ctx->guest_base + 0x100;
        uint32_t i;
        uint32_t acc = 0;

        for (i = 0; i < 32U; i++) {
            acc |= blk[i];
        }
        expect("dcbz-zero", acc, 0U);
    }
    expect("dcbz-nip", ctx->nip, 4U);

    printf(fails == 0 ? "test_p1_reconcile: ALL OK\n" :
        "test_p1_reconcile: %d FAILURES\n", fails);
    return fails != 0;
}
