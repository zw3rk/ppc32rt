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

static ppc32_emit_fn s_user_emitter = dbt_fallback_emit;

/* H1 SMC: snapshot recorder (defined in cache.c; the smc_store
 * hook and bitmap base now live in dbt.h for the syscall layer). */
extern void ppc32_cache_record_guest(ppc32_ctx_t *ctx, ppc32_block_t *e,
    uint32_t start, uint32_t end);

/* H1 SMC: classify natively-emitted guest stores. Returns true with
 * *len_out = stored byte count and *back_out = how far w22 (the EA)
 * has advanced past the range start (multi-word/dcbz/string strides).
 * Every op listed here leaves the access EA in w22 on success; the
 * hook reads it back, so update-form ordering needs no special case.
 * Returns false for loads, barriers, and anything the emitter refuses
 * (fallback stores retire through the interpreter, covered by the
 * UNDEF-path flush plus dispatch snapshot verification). */
static bool dbt_store_shape(const ppc32_insn_t *insn, uint32_t *len_out,
    uint32_t *back_out)
{
    uint32_t len = 0U;
    uint32_t back = 0U;
    uint32_t n;

    if (insn == NULL || len_out == NULL || back_out == NULL) {
        return false;
    }
    switch (insn->op) {
    case PPC32_OP_STB:
    case PPC32_OP_STBU:
    case PPC32_OP_STBX:
    case PPC32_OP_STBUX:
        len = 1U;
        break;
    case PPC32_OP_STH:
    case PPC32_OP_STHU:
    case PPC32_OP_STHX:
    case PPC32_OP_STHUX:
    case PPC32_OP_STHBRX:
        len = 2U;
        break;
    case PPC32_OP_STW:
    case PPC32_OP_STWU:
    case PPC32_OP_STWX:
    case PPC32_OP_STWUX:
    case PPC32_OP_STWBRX:
    case PPC32_OP_STWCX:
        len = 4U;
        break;
    case PPC32_OP_STMW:
        /* stw loop from rt: n words, w22 ends (n-1)*4 past base. */
        if (insn->rt > 31U) {
            return false;
        }
        n = 32U - (uint32_t)insn->rt;
        len = n * 4U;
        back = (n - 1U) * 4U;
        break;
    case PPC32_OP_STSWI:
        /* nb lives in the rb field (0 means 32); w22 ends n-1 past. */
        n = (insn->rb == 0U) ? 32U : (uint32_t)insn->rb;
        if (n == 0U || n > 32U) {
            return false;
        }
        len = n;
        back = n - 1U;
        break;
    case PPC32_OP_DCBZ:
        /* Aligned base, 8 ascending words: w22 ends 28 past base. */
        len = 32U;
        back = 28U;
        break;
    case PPC32_OP_STFS:
    case PPC32_OP_STFSU:
        len = 4U;
        break;
    case PPC32_OP_STFD:
    case PPC32_OP_STFDU:
        len = 8U;
        break;
    case PPC32_OP_FPU_X: {
        /* Indexed float bit2 = store, bit1 = double (fp_indexed). */
        uint32_t k;

        if (insn->xo < 535U || insn->xo > 759U ||
            ((insn->xo - 535U) & 31U) != 0U) {
            return false;
        }
        k = (insn->xo - 535U) >> 5U;
        if ((k & 4U) == 0U) {
            return false;
        }
        len = ((k & 2U) != 0U) ? 8U : 4U;
        break;
    }
    case PPC32_OP_SPE:
        /* 64-bit indexed stores only (768/770 are the loads). */
        if (insn->xo != 800U && insn->xo != 802U) {
            return false;
        }
        len = 8U;
        break;
    default:
        return false;
    }
    *len_out = len;
    *back_out = back;
    return true;
}

/* Unconditional branch with later backfill (B, imm26). Mirrors the
 * B.cond placeholder/patch pair in rt32/ppc32_a64_emit2.c (which has
 * no unconditional form; B.cond with AL is architecturally reserved). */
static size_t dbt_emit_b_placeholder(a64_buf_t *b)
{
    size_t idx = b->count;

    a64_emit(b, 0x14000000U);
    return idx;
}

static void dbt_patch_b(a64_buf_t *b, size_t patch_idx, size_t target_idx)
{
    int32_t disp;

    if (patch_idx >= b->count) {
        return;
    }
    disp = (int32_t)target_idx - (int32_t)patch_idx;
    b->words[patch_idx] = 0x14000000U | ((uint32_t)disp & 0x03FFFFFFU);
}

/* H1 SMC slow path: call ppc32_smc_store(ctx, EA, len, cur) right after
 * a natively-emitted store. Contract (mirrors emit_int.h design
 * rules): GPRs live in ctx, no guest state survives in host regs
 * across instructions, w0-w7 are never touched by emitted code, and
 * NZCV is dead at every call site. The helper preserves x19-x28/x22/
 * x27 (AAPCS64 callee-saved); w1 holds the range start, w2 the length,
 * and x27 the current entry on entry. blr writes LR, so the sequence
 * spills/fills it on the host stack: no call-preserved register is
 * free, and the block's final ret must still reach the trampoline
 * resume address. SP stays 16-byte aligned throughout (the trampoline
 * aligned it; emitted code never touches it), and the spill touches
 * neither NZCV nor any live register. */
static void dbt_emit_smc_call(a64_buf_t *b)
{
    uintptr_t fn = (uintptr_t)ppc32_smc_store;
    uint32_t hi3 = (uint32_t)((fn >> 48U) & 0xFFFFU);
    uint32_t hi2 = (uint32_t)((fn >> 32U) & 0xFFFFU);
    uint32_t hi1 = (uint32_t)((fn >> 16U) & 0xFFFFU);
    uint32_t lo = (uint32_t)(fn & 0xFFFFU);

    a64_emit(b, 0xAA1303E0U); /* mov x0, x19 (ctx) */
    a64_emit(b, 0xAA1B03E3U); /* mov x3, x27 (cur entry) */
    a64_emit(b, 0xD2800000U | ((uint32_t)3U << 21) |
        (hi3 << 5) | 21U); /* movz x21, #hi3, lsl #48 */
    a64_emit(b, 0xF2800000U | ((uint32_t)2U << 21) |
        (hi2 << 5) | 21U); /* movk x21, #hi2, lsl #32 */
    a64_emit(b, 0xF2800000U | ((uint32_t)1U << 21) |
        (hi1 << 5) | 21U); /* movk x21, #hi1, lsl #16 */
    a64_emit(b, 0xF2800000U | (lo << 5) | 21U); /* movk x21, #lo */
    a64_emit(b, 0xF81F0FFEU); /* str x30, [sp, #-16]! */
    a64_emit(b, 0xD63F02A0U); /* blr x21 */
    a64_emit(b, 0xF84107FEU); /* ldr x30, [sp], #16 */
}

/* P1: emit the post-store hook after a natively-emitted store, guarded
 * by an inline code-page occupancy check. Data-page stores (the hot
 * path) skip the C call entirely; only a store touching a page marked
 * in the bitmap falls through to dbt_emit_smc_call. Both the start
 * page (ea >> 12) and the end page ((ea + size - 1) >> 12) are tested
 * so cross-page stores never miss an invalidation, and 32-bit wrap of
 * (ea + size) takes the slow path (which flushes everything).
 * Scratch is w3-w6 plus x2/x5/x6: w0-w7 are never live across emitted
 * instructions and NZCV is dead at every call site, while x19-x22/x27
 * (ctx, xG, EA, entry) survive untouched until the call setup. */
static void dbt_emit_smc_hook(a64_buf_t *b, uint32_t len, uint32_t back)
{
    uintptr_t base = (uintptr_t)ppc32_code_pages_base();
    uint32_t b3 = (uint32_t)((base >> 48U) & 0xFFFFU);
    uint32_t b2 = (uint32_t)((base >> 32U) & 0xFFFFU);
    uint32_t b1 = (uint32_t)((base >> 16U) & 0xFFFFU);
    uint32_t b0 = (uint32_t)(base & 0xFFFFU);
    size_t wrap;
    size_t start_hit;
    size_t end_hit;
    size_t done;

    if (back != 0U) {
        /* w1 = w22 - back (range start for strided stores). */
        a64_emit_sub_imm_w(b, false, 1U, 22U, (uint16_t)back, 0U);
    } else {
        a64_emit_mov_w(b, 1U, 22U);
    }
    a64_emit_mov_imm32(b, 2U, len);
    /* x2 = code-page bitmap base (absolute host address, fixed). */
    a64_emit(b, 0xD2800000U | ((uint32_t)3U << 21) |
        (b3 << 5) | 2U); /* movz x2, #b3, lsl #48 */
    a64_emit(b, 0xF2800000U | ((uint32_t)2U << 21) |
        (b2 << 5) | 2U); /* movk x2, #b2, lsl #32 */
    a64_emit(b, 0xF2800000U | ((uint32_t)1U << 21) |
        (b1 << 5) | 2U); /* movk x2, #b1, lsl #16 */
    a64_emit(b, 0xF2800000U | (b0 << 5) | 2U); /* movk x2, #b0 */
    /* w3 = start page (ea >> 12). */
    a64_emit_ubfm_w(b, 3U, 1U, 12U, 31U);
    /* w4 = ea + len; carry means 32-bit wrap past 4 GiB. */
    a64_emit_add_reg_w(b, true, 4U, 1U, 2U, A64_SHIFT_LSL, 0U);
    wrap = a64_emit_b_cond_placeholder(b, A64_COND_CS);
    /* w4 = end page ((ea + len - 1) >> 12); len is never 0 here. */
    a64_emit_sub_imm_w(b, false, 4U, 4U, 1U, 0U);
    a64_emit_ubfm_w(b, 4U, 4U, 12U, 31U);
    /* w5 = start-page bit: half (page >> 5) holds bit (page & 31). */
    a64_emit_ubfm_w(b, 5U, 3U, 5U, 31U);
    a64_emit_shift_imm_w(b, 5U, 5U, A64_SHIFT_LSL, 2U, false, NULL);
    a64_emit_add_uxtw_x(b, 5U, 2U, 5U);
    a64_emit_ldr_imm_w(b, 5U, 5U, 0U);
    a64_emit_ubfm_w(b, 6U, 3U, 0U, 4U);
    a64_emit_shift_reg_w(b, 5U, 5U, 6U, A64_SHIFT_LSR);
    a64_emit_ubfm_w(b, 5U, 5U, 0U, 0U);
    start_hit = a64_emit_cbz_w_placeholder(b, true, 5U);
    /* Same test for the end page (covers cross-page straddles). */
    a64_emit_ubfm_w(b, 5U, 4U, 5U, 31U);
    a64_emit_shift_imm_w(b, 5U, 5U, A64_SHIFT_LSL, 2U, false, NULL);
    a64_emit_add_uxtw_x(b, 5U, 2U, 5U);
    a64_emit_ldr_imm_w(b, 5U, 5U, 0U);
    a64_emit_ubfm_w(b, 6U, 4U, 0U, 4U);
    a64_emit_shift_reg_w(b, 5U, 5U, 6U, A64_SHIFT_LSR);
    a64_emit_ubfm_w(b, 5U, 5U, 0U, 0U);
    end_hit = a64_emit_cbz_w_placeholder(b, true, 5U);
    /* Neither page holds code: skip the slow-path call. */
    done = dbt_emit_b_placeholder(b);
    a64_patch_b_cond(b, wrap, b->count);
    a64_patch_cbz_w(b, start_hit, b->count);
    a64_patch_cbz_w(b, end_hit, b->count);
    dbt_emit_smc_call(b);
    dbt_patch_b(b, done, b->count);
}

/* H1 SMC wrapper: every translation goes through here. Native
 * stores get a post-store invalidation hook; everything else passes
 * through untouched (fallback/refusal codes propagate so dbt.c still
 * ends blocks exactly as before). */
static int dbt_emit_wrap(a64_buf_t *b, const ppc32_insn_t *insn,
    uint32_t pc)
{
    int rc = s_user_emitter(b, insn, pc);

    if (rc == 0 && insn != NULL) {
        uint32_t len = 0U;
        uint32_t back = 0U;

        if (dbt_store_shape(insn, &len, &back)) {
            dbt_emit_smc_hook(b, len, back);
        }
    }
    return rc;
}

static ppc32_emit_fn s_emitter = dbt_emit_wrap;

void ppc32_dbt_set_emitter(ppc32_emit_fn fn)
{
    if (fn != NULL) {
        s_user_emitter = fn;
    } else {
        s_user_emitter = dbt_fallback_emit;
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
                ppc32_block_t *e;

                a64_buf_init(&b, staging, 4096U);
                b.guest_start_pc = pc;
                a64_emit_exit_undef(&b, cur);
                b.guest_end_pc = cur;
                e = ppc32_cache_install(ctx, pc, staging, b.count,
                    NULL, 0U, false, 0U);
                /* H1 SMC: empty guest range (fallback block). */
                ppc32_cache_record_guest(ctx, e, pc, cur);
                return e;
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
        ppc32_block_t *e;

        a64_buf_init(&b, staging, 4096U);
        b.guest_start_pc = pc;
        a64_emit_exit_undef(&b, pc);
        b.guest_end_pc = pc;
        e = ppc32_cache_install(ctx, pc, staging, b.count, NULL, 0U,
            false, 0U);
        /* H1 SMC: empty guest range (fallback block). */
        ppc32_cache_record_guest(ctx, e, pc, pc);
        return e;
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
        /* H1 SMC: snapshot the translated guest bytes for dispatch
         * re-verification (covers interpreter stores and restores). */
        ppc32_cache_record_guest(ctx, e, pc, cur);
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
            /* GDB single-step (Phase 4): stay on the interpreter. A
             * stepped store bypasses the hooks, so retire the cache
             * the same way the UNDEF path does (decode the word
             * about to step, before it advances). */
            uint32_t upc = ctx->nip;
            uint32_t raw = 0U;
            ppc32_insn_t stepped;
            uint32_t len = 0U;
            uint32_t back = 0U;
            bool flush = false;

            if (ctx->vm_ready) {
                memcpy(&raw, ppc32_guest_ptr(ctx, upc), sizeof(raw));
                memset(&stepped, 0, sizeof(stepped));
                if (ppc_decode(ppc32_be32(raw), &stepped) == 0 &&
                    dbt_store_shape(&stepped, &len, &back)) {
                    flush = true;
                }
            }
            interp_step(ctx);
            if (flush) {
                ppc32_cache_invalidate_all(ctx);
            }
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
            /* P1: no unconditional flush here. Guest-memory copyouts
             * (read/pread64/readv/getdents64) report their exact
             * ranges via ppc32_smc_store, the JIT store hooks cover
             * natively-emitted stores, and dispatch re-verifies the
             * snapshot on the next lookup. */
            return (int)ctx->exit_reason;
        case PPC32_EXIT_UNDEF: {
            /* H1 SMC: the single step below has no store hook; when
             * the stepped word stores, retire the whole cache so a
             * chained re-entry retranslates fresh bytes. Decode
             * before stepping (a faulting step still flushes). */
            uint32_t upc = ctx->exit_dest;
            uint32_t raw = 0U;
            ppc32_insn_t stepped;
            uint32_t len = 0U;
            uint32_t back = 0U;
            bool flush = false;

            if (ctx->vm_ready) {
                memcpy(&raw, ppc32_guest_ptr(ctx, upc), sizeof(raw));
                memset(&stepped, 0, sizeof(stepped));
                if (ppc_decode(ppc32_be32(raw), &stepped) == 0 &&
                    dbt_store_shape(&stepped, &len, &back)) {
                    flush = true;
                }
            }
            ctx->nip = upc;
            ctx->exit_reason = PPC32_EXIT_NONE;
            interp_step(ctx);
            if (flush) {
                ppc32_cache_invalidate_all(ctx);
            }
            break;
        }
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
