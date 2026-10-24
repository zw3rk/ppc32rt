/*
 * src/dbt/dbt.c — AArch64 DBT dispatch loop and block translator
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * dbt_run translates guest basic blocks (<= PPC32_DBT_BLOCK_BUDGET
 * instructions, stopping at control transfers or guest page crossings)
 * and executes them through ppc32_jit_run_block until ctx->exit_reason
 * != NONE, mirroring the interp_run/main.c driver so the engines swap
 * one for one. UNDEF exits fall back to a single interp_step and then
 * resume; SYSCALL exits return with nip AT the sc word (the syscall
 * layer advances past it, exactly like the interpreter); TRAP/FAULT
 * return as recorded by the exit stub (those stubs store nip before
 * returning; see dbt.h).
 *
 * Until lane L2c lands its per-op emitter, a TEMPORARY all-fallback
 * emitter is installed: every instruction refuses emission, so each
 * block is a single exit_undef plus interp_step — exactly interpreter
 * semantics, hence --difftest-clean by construction. ppc32_dbt_set_emitter
 * swaps in the real emitter without touching this file.
 */

#include <string.h>

#include "dbt/dbt.h"
#include "interp/interp.h"

/* ABI facts the trampoline assembles against; break the build here if
 * the frozen ctx layout ever drifts (SPEC 2.1). */
_Static_assert(PPC32_EXIT_BRANCH == 1U, "trampoline pins BRANCH == 1");
_Static_assert(PPC32_EXIT_TRAP == 5U, "trampoline pins TRAP == 5");
_Static_assert(offsetof(ppc32_ctx_t, nip) == 0x100U,
    "trampoline stores nip @0x100");
_Static_assert(offsetof(ppc32_ctx_t, guest_base) == 0x228U,
    "trampoline loads xG @0x228");
_Static_assert(offsetof(ppc32_ctx_t, chain_hits) == 0x260U,
    "trampoline folds x24 @0x260");
_Static_assert(offsetof(ppc32_ctx_t, exit_reason) == 0x288U,
    "trampoline stores reason @0x288");
_Static_assert(offsetof(ppc32_ctx_t, exit_dest) == 0x294U,
    "trampoline stores dest @0x294");

/* TEMPORARY all-fallback emitter (delete when L2c lands): refuse every
 * instruction so translation always ends in an interp_step fallback. */
static int dbt_fallback_emit(a64_buf_t *b, const ppc32_insn_t *insn,
    uint32_t pc)
{
    (void)b;
    (void)insn;
    (void)pc;
    return -1;
}

static ppc32_emit_fn s_emitter = dbt_fallback_emit;

void ppc32_dbt_set_emitter(ppc32_emit_fn fn)
{
    if (fn != NULL) {
        s_emitter = fn;
    } else {
        s_emitter = dbt_fallback_emit;
    }
}

/* Block-ending instructions: the emitter has produced the block's exit
 * sequence for these, so translation stops after them. Conditional
 * traps (TWI/TW) fall through to the emitter's inline trap test and do
 * not end the block. */
static bool is_block_end(uint32_t op)
{
    return op == PPC32_OP_B || op == PPC32_OP_BC ||
        op == PPC32_OP_BCLR || op == PPC32_OP_BCCTR ||
        op == PPC32_OP_SC || op == PPC32_OP_UNDEF;
}

/* Translate one block starting at pc; on success the block is installed
 * in the cache and returned. On host-resource failure returns NULL with
 * exit_reason set (FAULT). Guest fetch mirrors interp fetch_raw. */
static ppc32_block_t *dbt_translate(ppc32_ctx_t *ctx, uint32_t pc)
{
    /* 16 KiB staging: 64 insns of even the most verbose L2c lowering
     * plus exit tails fit with wide margin. */
    uint32_t staging[4096];
    a64_buf_t b;
    uint32_t start_page = ppc32_page_down(pc);
    uint32_t cur = pc;
    unsigned n;

    a64_buf_init(&b, staging, 4096U);
    b.guest_start_pc = pc;
    bool end_is_control = false;
    for (n = 0U; n < PPC32_DBT_BLOCK_BUDGET; n++) {
        uint32_t raw;
        ppc32_insn_t insn;
        int rc;

        if (ppc32_page_down(cur) != start_page) {
            break;
        }
        memcpy(&raw, ppc32_guest_ptr(ctx, cur), sizeof(raw));
        raw = ppc32_be32(raw);
        memset(&insn, 0, sizeof(insn));
        if (ppc_decode(raw, &insn) != 0) {
            insn.raw = raw;
            insn.op = PPC32_OP_UNDEF;
        }
        rc = s_emitter(&b, &insn, cur);
        if (rc != 0) {
            if (n == 0U) {
                /* Nothing emitted: force interp_step progress via an
                 * UNDEF exit (an exit_branch here would retranslate
                 * the same pc forever). */
                a64_buf_init(&b, staging, 4096U);
                b.guest_start_pc = pc;
                a64_emit_exit_undef(&b, cur);
                b.guest_end_pc = cur;
                return ppc32_cache_install(ctx, pc, staging, b.count,
                    NULL, 0U, false, 0U);
            }
            /* Partial block: valid fallthrough-chaining tail. */
            a64_emit_exit_branch(&b, cur);
            end_is_control = true;
            break;
        }
        cur += 4U;
        if (b.overflow) {
            break;
        }
        if (is_block_end(insn.op)) {
            end_is_control = true;
            break;
        }
    }
    if (!b.overflow && b.count > 0U && !end_is_control) {
        /* Page-cross / budget fallthrough: terminate with an explicit
         * exit to cur (RC2: unterminated blocks ran off into zero
         * padding and died with host SIGILL). Enables chaining. */
        a64_emit_exit_branch(&b, cur);
    }
    if (b.overflow || b.count == 0U) {
        /* Overflow or empty (page-crossed at once): single-step via
         * interp instead of installing a corrupt block. */
        a64_buf_init(&b, staging, 4096U);
        b.guest_start_pc = pc;
        a64_emit_exit_undef(&b, pc);
        b.guest_end_pc = pc;
        return ppc32_cache_install(ctx, pc, staging, b.count, NULL, 0U,
            false, 0U);
    }
    b.guest_end_pc = cur;
    /* NOTE: the install below passes b.exit_slot_pcs/b.exit_slot_count
     * for direct-chain backfill even while the TEMPORARY all-fallback
     * emitter is active (count is 0 then: harmless). */
    {
        ppc32_block_t *e = ppc32_cache_install(ctx, pc, staging, b.count,
            b.exit_slot_pcs, b.exit_slot_count, b.is_call, cur);

        if (e == NULL) {
            ctx->fault_addr = pc;
            ctx->exit_reason = PPC32_EXIT_FAULT;
            return NULL;
        }
        return e;
    }
}

int dbt_run(ppc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return (int)PPC32_EXIT_FAULT;
    }
    for (;;) {
        ppc32_block_t *e;
        uint32_t reason;

        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return (int)ctx->exit_reason;
        }
        if (ctx->single_step) {
            /* GDB single-step (Phase 4): stay on the interpreter. */
            interp_step(ctx);
            return (int)ctx->exit_reason;
        }
        if (!ctx->vm_ready) {
            ctx->fault_addr = ctx->nip;
            ctx->exit_reason = PPC32_EXIT_FAULT;
            return (int)ctx->exit_reason;
        }
        e = ppc32_cache_lookup(ctx, ctx->nip);
        if (e == NULL) {
            e = dbt_translate(ctx, ctx->nip);
            if (e == NULL) {
                return (int)ctx->exit_reason;
            }
        }
        ctx->last_exec_entry = e->entry;
        reason = ppc32_jit_run_block(ctx, e->entry, (void *)e,
            ppc32_cache_epoch_ptr());
        ctx->blocks_executed++;
        switch (reason) {
        case PPC32_EXIT_BRANCH:
            /* Chained branches never return; a bail-out lands here. */
            ctx->nip = ctx->exit_dest;
            ctx->exit_reason = PPC32_EXIT_NONE;
            break;
        case PPC32_EXIT_SYSCALL:
            /* Trampoline left nip past sc; rewind AT it so the
             * syscall layer advances past exactly once. */
            ctx->nip = ctx->exit_dest - 4U;
            ctx->exit_reason = PPC32_EXIT_SYSCALL;
            return (int)ctx->exit_reason;
        case PPC32_EXIT_UNDEF:
            ctx->nip = ctx->exit_dest;
            ctx->exit_reason = PPC32_EXIT_NONE;
            interp_step(ctx);
            break;
        default:
            /* TRAP/FAULT: nip already stored by the exit stub. */
            return (int)ctx->exit_reason;
        }
    }
}

void dbt_invalidate_all(ppc32_ctx_t *ctx)
{
    ppc32_cache_invalidate_all(ctx);
}

void ppc32_dbt_invalidate_range(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end)
{
    ppc32_cache_invalidate_range(ctx, start, end);
}
