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
 * Default emitter is dbt_fallback_emit (every instruction refuses native
 * emission and exits via PPC32_EXIT_UNDEF to interp_step) until main.c or a
 * test harness installs ppc32_emit_insn via ppc32_dbt_set_emitter.
 */

#include <string.h>

#include "dbt/dbt.h"
#include "interp/interp.h"
#include "os/signals.h"

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

/* Default all-fallback emitter used until ppc32_dbt_set_emitter installs
 * ppc32_emit_insn: refuse every instruction so translation falls back to
 * interp_step. */
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
 * a natively-emitted store. Wave P12: w0..w7/d16..d23 hold the
 * write-through GPR/FPR caches live across instructions, and the C
 * helper clobbers caller-saved x0..x7/d16..d23. The cold block spills
 * them around blr x16 (fast path never touches them, so it keeps the
 * caches 100% live). x19-x22/x27 survive; NZCV is dead; SP stays
 * 16-byte aligned; the spill touches neither NZCV nor x19/x27. */
static void dbt_emit_smc_call(a64_buf_t *b)
{
    uintptr_t fn = (uintptr_t)ppc32_smc_store;
    uint32_t hi3 = (uint32_t)((fn >> 48U) & 0xFFFFU);
    uint32_t hi2 = (uint32_t)((fn >> 32U) & 0xFFFFU);
    uint32_t hi1 = (uint32_t)((fn >> 16U) & 0xFFFFU);
    uint32_t lo = (uint32_t)(fn & 0xFFFFU);

    a64_emit(b, 0xD10243FFU); /* sub sp, sp, #144 */
    a64_emit(b, 0xA90007E0U); /* stp x0, x1, [sp, #0] */
    a64_emit(b, 0xA9010FE2U); /* stp x2, x3, [sp, #16] */
    a64_emit(b, 0xA90217E4U); /* stp x4, x5, [sp, #32] */
    a64_emit(b, 0xA9031FE6U); /* stp x6, x7, [sp, #48] */
    a64_emit(b, 0x6D0447F0U); /* stp d16, d17, [sp, #64] */
    a64_emit(b, 0x6D054FF2U); /* stp d18, d19, [sp, #80] */
    a64_emit(b, 0x6D0657F4U); /* stp d20, d21, [sp, #96] */
    a64_emit(b, 0x6D075FF6U); /* stp d22, d23, [sp, #112] */
    a64_emit(b, 0xF90043FEU); /* str x30, [sp, #128] */
    a64_emit(b, 0xAA1303E0U); /* mov x0, x19 (ctx) */
    a64_emit_mov_w(b, 1U, 9U); /* mov w1, w9 (range start) */
    a64_emit_mov_w(b, 2U, 10U); /* mov w2, w10 (len) */
    a64_emit(b, 0xAA1B03E3U); /* mov x3, x27 (cur entry) */
    a64_emit(b, 0xD2800000U | ((uint32_t)3U << 21) |
        (hi3 << 5) | 16U); /* movz x16, #hi3, lsl #48 */
    a64_emit(b, 0xF2800000U | ((uint32_t)2U << 21) |
        (hi2 << 5) | 16U); /* movk x16, #hi2, lsl #32 */
    a64_emit(b, 0xF2800000U | ((uint32_t)1U << 21) |
        (hi1 << 5) | 16U); /* movk x16, #hi1, lsl #16 */
    a64_emit(b, 0xF2800000U | (lo << 5) | 16U); /* movk x16, #lo */
    a64_emit(b, 0xD63F0200U); /* blr x16 */
    a64_emit(b, 0xF94043FEU); /* ldr x30, [sp, #128] */
    a64_emit(b, 0x6D4447F0U); /* ldp d16, d17, [sp, #64] */
    a64_emit(b, 0x6D454FF2U); /* ldp d18, d19, [sp, #80] */
    a64_emit(b, 0x6D4657F4U); /* ldp d20, d21, [sp, #96] */
    a64_emit(b, 0x6D475FF6U); /* ldp d22, d23, [sp, #112] */
    a64_emit(b, 0xA94007E0U); /* ldp x0, x1, [sp, #0] */
    a64_emit(b, 0xA9410FE2U); /* ldp x2, x3, [sp, #16] */
    a64_emit(b, 0xA94217E4U); /* ldp x4, x5, [sp, #32] */
    a64_emit(b, 0xA9431FE6U); /* ldp x6, x7, [sp, #48] */
    a64_emit(b, 0x910243FFU); /* add sp, sp, #144 */
}

/* P1: emit the post-store hook after a natively-emitted store, guarded
 * by an inline code-page occupancy check. Data-page stores (the hot
 * path) skip the C call entirely; only a store touching a page marked
 * in the bitmap falls through to dbt_emit_smc_call. Both the start
 * page (ea >> 12) and the end page ((ea + size - 1) >> 12) are tested
 * so cross-page stores never miss an invalidation, and 32-bit wrap of
 * (ea + size) takes the slow path (which flushes everything). Wave
 * P12: fast-path scratch is w9-w15/x13-x15 (dead EI/TMP regs), so
 * w0..w7/d16..d23 caches stay live; w9 holds the range start and w10
 * the length into the cold call; NZCV is dead; x19-x22/x27 survive. */
static void dbt_emit_smc_hook(a64_buf_t *b, uint32_t len, uint32_t back)
{
    uintptr_t base = (uintptr_t)ppc32_code_pages_base();
    uint32_t b3 = (uint32_t)((base >> 48U) & 0xFFFFU);
    uint32_t b2 = (uint32_t)((base >> 32U) & 0xFFFFU);
    uint32_t b1 = (uint32_t)((base >> 16U) & 0xFFFFU);
    uint32_t b0 = (uint32_t)(base & 0xFFFFU);
    size_t wrap;
    size_t start_hit;
    size_t end_hit = 0U;
    size_t done;

    if (back != 0U) {
        a64_emit_sub_imm_w(b, false, 9U, 22U, (uint16_t)back, 0U);
    } else {
        a64_emit_mov_w(b, 9U, 22U);
    }
    a64_emit_mov_imm32(b, 10U, len);
    a64_emit(b, 0xD2800000U | ((uint32_t)3U << 21) |
        (b3 << 5) | 13U); /* movz x13, #b3, lsl #48 */
    a64_emit(b, 0xF2800000U | ((uint32_t)2U << 21) |
        (b2 << 5) | 13U); /* movk x13, #b2, lsl #32 */
    a64_emit(b, 0xF2800000U | ((uint32_t)1U << 21) |
        (b1 << 5) | 13U); /* movk x13, #b1, lsl #16 */
    a64_emit(b, 0xF2800000U | (b0 << 5) | 13U); /* movk x13, #b0 */
    a64_emit_ubfm_w(b, 11U, 9U, 12U, 31U);
    a64_emit_add_reg_w(b, true, 12U, 9U, 10U, A64_SHIFT_LSL, 0U);
    wrap = a64_emit_b_cond_placeholder(b, A64_COND_CS);
    a64_emit_sub_imm_w(b, false, 12U, 12U, 1U, 0U);
    a64_emit_ubfm_w(b, 12U, 12U, 12U, 31U);
    a64_emit_ubfm_w(b, 14U, 11U, 5U, 31U);
    a64_emit_shift_imm_w(b, 14U, 14U, A64_SHIFT_LSL, 2U, false, NULL);
    a64_emit_add_uxtw_x(b, 14U, 13U, 14U);
    a64_emit_ldr_imm_w(b, 14U, 14U, 0U);
    a64_emit_ubfm_w(b, 15U, 11U, 0U, 4U);
    a64_emit_shift_reg_w(b, 14U, 14U, 15U, A64_SHIFT_LSR);
    a64_emit_ubfm_w(b, 14U, 14U, 0U, 0U);
    start_hit = a64_emit_cbz_w_placeholder(b, true, 14U);
    if (len == 1U) {
        /* A single byte cannot span pages: the start-page test above
         * already decides, so the end-page lookup is skipped. */
        done = dbt_emit_b_placeholder(b);
    } else {
        a64_emit_ubfm_w(b, 14U, 12U, 5U, 31U);
        a64_emit_shift_imm_w(b, 14U, 14U, A64_SHIFT_LSL, 2U, false, NULL);
        a64_emit_add_uxtw_x(b, 14U, 13U, 14U);
        a64_emit_ldr_imm_w(b, 14U, 14U, 0U);
        a64_emit_ubfm_w(b, 15U, 12U, 0U, 4U);
        a64_emit_shift_reg_w(b, 14U, 14U, 15U, A64_SHIFT_LSR);
        a64_emit_ubfm_w(b, 14U, 14U, 0U, 0U);
        end_hit = a64_emit_cbz_w_placeholder(b, true, 14U);
        done = dbt_emit_b_placeholder(b);
    }
    a64_patch_b_cond(b, wrap, b->count);
    a64_patch_cbz_w(b, start_hit, b->count);
    if (len != 1U) {
        a64_patch_cbz_w(b, end_hit, b->count);
    }
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

/* Wave P13 FP lookahead: true for ops the open FP batch can be
 * looked past without disturbing it. Integer ALU ops below never touch
 * host FPSR/FPCR or guest FPSCR (CR/XER writes are FP-invisible, and
 * every emitter is total for these shapes); 64-bit FP loads/stores,
 * single loads and pure moves transfer bits with no FP status update.
 * Single-precision stores and stfiwx convert through FCVT and can set
 * host FPSR flags, so they (with every other op: FPSCR observers,
 * converts, compares, branches, faults, helpers) close the batch.
 * Update-form FP memory with ra == 0 cannot emit, so it is not
 * transparent either. The XO numbers mirror emit_fp.c
 * (FP_XO_FMR/FNEG/FNABS/FABS, indexed k-bit layout); stfiwx decodes
 * to UNDEF and stops the scan by itself. */
static bool dbt_fp_passthrough(const ppc32_insn_t *t)
{
    switch (t->op) {
    case PPC32_OP_LFD:
    case PPC32_OP_STFD:
    case PPC32_OP_LFS:
        return true;
    case PPC32_OP_LFDU:
    case PPC32_OP_STFDU:
    case PPC32_OP_LFSU:
        return t->ra != 0U;
    case PPC32_OP_FPU_X:
        switch (t->xo) {
        case 535U: case 599U: case 663U:
            return true;
        case 567U: case 631U: case 695U:
            return t->ra != 0U;
        default:
            return false;
        }
    case PPC32_OP_FPU_DOUBLE:
        if (t->xo == 72U || t->xo == 40U || t->xo == 136U ||
            t->xo == 264U)
            return t->ra == 0U;
        return false;
    case PPC32_OP_ADDI:
    case PPC32_OP_ADDIS:
    case PPC32_OP_ADD:
    case PPC32_OP_SUBF:
    case PPC32_OP_ORI:
    case PPC32_OP_OR:
    case PPC32_OP_AND:
    case PPC32_OP_RLWINM:
        return true;
    case PPC32_OP_CMP:
    case PPC32_OP_CMPL:
    case PPC32_OP_CMPI:
    case PPC32_OP_CMPLI:
        /* ei_cmp falls back on L == 1 (rt bit 0). */
        return (t->rt & 1U) == 0U;
    default:
        return false;
    }
}

/* Wave P6 FP batching: true when `insn` is A-form FP arithmetic lowered
 * by fp_arith without FALLBACK (non-SELM XO with valid fields). Mirrors
 * the fp_arith validation in src/dbt/emit_fp.c so a peeked next word is
 * guaranteed emittable. */
static bool dbt_is_fp_arith(const ppc32_insn_t *insn)
{
    uint32_t xo5;

    if (insn == NULL || (insn->op != (uint32_t)PPC32_OP_FPU_SINGLE &&
        insn->op != (uint32_t)PPC32_OP_FPU_DOUBLE)) {
        return false;
    }
    xo5 = insn->xo & 0x1FU;
    switch (xo5) {
    case 18U: case 20U: case 21U: case 22U: case 25U:
    case 28U: case 29U: case 30U: case 31U:
        break;
    default:
        return false;
    }
    if (insn->rt >= 32U || insn->ra >= 32U || insn->rb >= 32U ||
        insn->bi >= 32U) {
        return false;
    }
    if ((xo5 == 21U || xo5 == 20U || xo5 == 18U) && insn->bi != 0U) {
        return false;
    }
    if (xo5 == 25U && insn->rb != 0U) {
        return false;
    }
    if (xo5 == 22U && (insn->ra != 0U || insn->bi != 0U)) {
        return false;
    }
    return true;
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
        /* Wave P6/P13 FP batching: when the current word opens (or
         * continues) a run of non-Rc A-form FP arithmetic, flag it so
         * fp_arith skips the per-op FPSCR/FPCR round-trip on
         * intermediates. A bounded forward scan looks past transparent
         * ops (non-observing FP moves/memory, non-trapping integer
         * ALU) for the next emittable arith word in this page; the
         * buffer has 128 words of headroom, so the run cannot
         * fallback or overflow. */
        b.fp_next_is_arith = false;
        if (insn.rc == 0U &&
            (insn.op == (uint32_t)PPC32_OP_FPU_SINGLE ||
             insn.op == (uint32_t)PPC32_OP_FPU_DOUBLE) &&
            dbt_is_fp_arith(&insn) && b.count + 128U < b.cap) {
            uint32_t fwd = cur + 4U;
            unsigned k;

            for (k = 0U; k < 16U; k++) {
                uint32_t scan_raw;
                ppc32_insn_t scan_insn;

                if (n + 1U + k >= PPC32_DBT_BLOCK_BUDGET ||
                    ppc32_page_down(fwd) != start_page) {
                    break;
                }
                memcpy(&scan_raw, ppc32_guest_ptr(ctx, fwd),
                    sizeof(scan_raw));
                scan_raw = ppc32_be32(scan_raw);
                memset(&scan_insn, 0, sizeof(scan_insn));
                if (ppc_decode(scan_raw, &scan_insn) != 0) {
                    break;
                }
                if ((scan_insn.op == (uint32_t)PPC32_OP_FPU_SINGLE ||
                    scan_insn.op == (uint32_t)PPC32_OP_FPU_DOUBLE) &&
                    dbt_is_fp_arith(&scan_insn)) {
                    b.fp_next_is_arith = true;
                    break;
                }
                if (!dbt_fp_passthrough(&scan_insn)) {
                    break;
                }
                fwd += 4U;
            }
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
        /* P32-R6-1: flush stale IBTC/RAS entries and record the synced
         * generation for the quiescent reclaimer before every lookup. */
        ppc32_cache_sync_ctx(ctx);
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
            /* P32-R6-6: the JIT bails here when pending_signals is
             * non-zero, so serve it now instead of crawling block to
             * block; the frame captures the bailed-to nip. */
            if (__atomic_load_n(&ctx->pending_signals,
                __ATOMIC_ACQUIRE) != 0ULL) {
                ppc32_sig_pump_pending(ctx);
            }
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
            uint32_t stwcx_ea = 0U;
            bool is_stwcx = false;
            bool flush = false;

            if (ctx->vm_ready) {
                memcpy(&raw, ppc32_guest_ptr(ctx, upc), sizeof(raw));
                memset(&stepped, 0, sizeof(stepped));
                if (ppc_decode(ppc32_be32(raw), &stepped) == 0) {
                    if (stepped.op == PPC32_OP_STWCX) {
                        stwcx_ea = ((stepped.ra == 0U ? 0U :
                            ctx->gpr[stepped.ra]) + ctx->gpr[stepped.rb]) & ~3U;
                        is_stwcx = true;
                    } else if (dbt_store_shape(&stepped, &len, &back)) {
                        flush = true;
                    }
                }
            }
            ctx->nip = upc;
            ctx->exit_reason = PPC32_EXIT_NONE;
            interp_step(ctx);
            if (is_stwcx) {
                ppc32_smc_store(ctx, stwcx_ea, 4U, NULL);
            } else if (flush) {
                ppc32_cache_invalidate_all(ctx);
            }
            break;
        }
        default:
            /* TRAP/FAULT: nip already stored by the exit stub. */
            if (reason == PPC32_EXIT_FAULT) {
                ctx->fault_is_store = 0U;
                if (ctx->vm_ready && ctx->fault_addr != ctx->nip &&
                    ctx->nip >= 0x1000U && ctx->nip <= 0xFFFFFFFCU) {
                    uint32_t raw = 0U;
                    ppc32_insn_t fi;
                    uint32_t len = 0U;
                    uint32_t back = 0U;

                    memcpy(&raw, ppc32_guest_ptr(ctx, ctx->nip), 4U);
                    memset(&fi, 0, sizeof(fi));
                    if (ppc_decode(ppc32_be32(raw), &fi) == 0 &&
                        (fi.op == PPC32_OP_STWCX ||
                         dbt_store_shape(&fi, &len, &back))) {
                        ctx->fault_is_store = 1U;
                    }
                }
            }
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
