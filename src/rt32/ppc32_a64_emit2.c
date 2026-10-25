/*
 * src/rt32/ppc32_a64_emit2.c — Direct 32-bit AArch64 instruction encoder (part 2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from ppc32_a64_emit.c (Phase 0, file-size discipline). Part 2:
 * crypto extensions, exclusives/barriers, branches and block exits
 * (RAS/IBTC/RAS-push, signal-window check), DSP helpers.
 * Never read or write x18.
 */

#include "ppc32_a64_emit.h"

/* ARMv8-A Crypto extensions (AES, PMULL, SHA1, SHA256) */
void a64_emit_aese(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E284800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_aesd(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E285800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_aesmc(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E286800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_aesimc(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E287800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_pmull_1q(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x0EE0E000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha1c(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E000000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha1p(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E001000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha1m(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E002000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha1su0(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E003000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha1h(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x5E280800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha1su1(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x5E281800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha256h(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E004000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha256h2(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E005000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha256su0(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x5E282800U | ((vn & 31U) << 5) | (vd & 31U));
}

void a64_emit_sha256su1(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E006000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

/* Exclusives & barriers */
void a64_emit_ldxr_b(a64_buf_t *b, unsigned rt_w, unsigned rn_x)
{
    a64_emit(b, 0x085F7C00U | ((rn_x & 31U) << 5) | (rt_w & 31U));
}

void a64_emit_stxr_b(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x)
{
    a64_emit(b, 0x08007C00U | ((rs_w & 31U) << 16) | ((rn_x & 31U) << 5) | (rt_w & 31U));
}

void a64_emit_ldxr_h(a64_buf_t *b, unsigned rt_w, unsigned rn_x)
{
    a64_emit(b, 0x485F7C00U | ((rn_x & 31U) << 5) | (rt_w & 31U));
}

void a64_emit_stxr_h(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x)
{
    a64_emit(b, 0x48007C00U | ((rs_w & 31U) << 16) | ((rn_x & 31U) << 5) | (rt_w & 31U));
}

void a64_emit_ldxr_w(a64_buf_t *b, unsigned rt_w, unsigned rn_x)
{
    a64_emit(b, 0x885F7C00U | ((rn_x & 31U) << 5) | (rt_w & 31U));
}

void a64_emit_stxr_w(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x)
{
    a64_emit(b, 0x88007C00U | ((rs_w & 31U) << 16) | ((rn_x & 31U) << 5) | (rt_w & 31U));
}

void a64_emit_ldxr_x(a64_buf_t *b, unsigned rt_x, unsigned rn_x)
{
    a64_emit(b, 0xC85F7C00U | ((rn_x & 31U) << 5) | (rt_x & 31U));
}

void a64_emit_stxr_x(a64_buf_t *b, unsigned rs_w, unsigned rt_x, unsigned rn_x)
{
    a64_emit(b, 0xC8007C00U | ((rs_w & 31U) << 16) | ((rn_x & 31U) << 5) | (rt_x & 31U));
}

void a64_emit_clrex(a64_buf_t *b)
{
    a64_emit(b, 0xD5033F5FU);
}

void a64_emit_dmb_ish(a64_buf_t *b)
{
    a64_emit(b, 0xD5033BBFU);
}

void a64_emit_dsb_ish(a64_buf_t *b)
{
    a64_emit(b, 0xD5033B9FU);
}

void a64_emit_isb(a64_buf_t *b)
{
    a64_emit(b, 0xD5033FDFU);
}

size_t a64_emit_b_cond_placeholder(a64_buf_t *b, unsigned cond)
{
    b->cond_branch_depth++;
    size_t idx = b->count;
    a64_emit(b, 0x54000000U | (cond & 15U));
    return idx;
}

void a64_patch_b_cond(a64_buf_t *b, size_t patch_idx, size_t target_idx)
{
    if (b->cond_branch_depth > 0U) {
        b->cond_branch_depth--;
    }
    if (patch_idx >= b->count) {
        return;
    }
    int32_t disp = (int32_t)target_idx - (int32_t)patch_idx;
    uint32_t cond = b->words[patch_idx] & 15U;
    b->words[patch_idx] = 0x54000000U | (((uint32_t)disp & 0x7FFFFU) << 5) | cond;
}

size_t a64_emit_cbz_w_placeholder(a64_buf_t *b, bool is_cbnz, unsigned rt)
{
    b->cond_branch_depth++;
    size_t idx = b->count;
    uint32_t base = is_cbnz ? 0x35000000U : 0x34000000U;
    a64_emit(b, base | (rt & 31U));
    return idx;
}

void a64_patch_cbz_w(a64_buf_t *b, size_t patch_idx, size_t target_idx)
{
    if (b->cond_branch_depth > 0U) {
        b->cond_branch_depth--;
    }
    if (patch_idx >= b->count) {
        return;
    }
    int32_t disp = (int32_t)target_idx - (int32_t)patch_idx;
    uint32_t op_rt = b->words[patch_idx] & 0xFF00001FU;
    b->words[patch_idx] = op_rt | (((uint32_t)disp & 0x7FFFFU) << 5);
}

void a64_emit_ret(a64_buf_t *b)
{
    a64_emit(b, 0xD65F03C0U);
}

static size_t emit_exit_sig_check(a64_buf_t *b, uint32_t bail_disp)
{
    /* The PPC32 prefix alone (0x238) exceeds LDP's signed ±504-byte reach,
     * so the carried single-LDP pair check becomes two LDRs. Relative
     * bail distances are unchanged (one extra insn shifts both ends).
     * [0] ldr x17, [x19, #pending] (ctx->pending_signals) */
    a64_emit(b, 0xF9400000U |
            ((((uint32_t)offsetof(ppc32_ctx_t, pending_signals)) / 8U) << 10) |
            (A64_XCTX << 5) | 17U);
    /* [1] ldr x23, [x19, #pending+8] (trace/sync flag word; zero at rest,
     *     so ORing it in is safe; blocks_executed starts after this pair) */
    a64_emit(b, 0xF9400000U |
            (((((uint32_t)offsetof(ppc32_ctx_t, pending_signals)) + 8U) / 8U) << 10) |
            (A64_XCTX << 5) | 23U);
    /* [2] orr x17, x17, x23 */
    a64_emit(b, 0xAA170231U);
    /* [3] cbnz x17, .Lbail */
    size_t patch_idx = b->count;
    a64_emit(b, 0xB5000011U | ((bail_disp & 0x7FFFFU) << 5));
    return patch_idx;
}

static void emit_ras_push_inline(a64_buf_t *b)
{
    /* [0] ldr x22, [x27, #96] (cur_entry->ret_entry, uimm = 96/8 = 12) */
    a64_emit(b, 0xF9403376U);
    /* [1] cbz x22, .Lskip_push (+7 words) */
    a64_emit(b, 0xB4000016U | (7U << 5));
    /* [2] ldr w21, [x19, #480] (w21 = ctx->ras_top, uimm = 480/4 = 120) */
    a64_emit(b, 0xB9400000U |
            ((((uint32_t)offsetof(ppc32_ctx_t, ras_top)) / 4U) << 10) |
            (A64_XCTX << 5) | 21U);
    /* [3] add w16, w21, #1 */
    a64_emit(b, 0x110006B0U);
    /* [4] and w16, w16, #0x3f */
    a64_emit(b, 0x12001610U);
    /* [5] str w16, [x19, #480] (ctx->ras_top = (ras_top + 1) & 63) */
    a64_emit(b, 0xB9000000U |
            ((((uint32_t)offsetof(ppc32_ctx_t, ras_top)) / 4U) << 10) |
            (A64_XCTX << 5) | 16U);
    /* [6] add x21, x19, x21, lsl #5 (x21 = ctx + ras_top * 32) */
    a64_emit(b, 0x8B151675U);
    /* [7] str x22, [x21, #504] (ras[top].entry = ret_entry, uimm = (ras_off+16)/8; computed via offsetof) */
    a64_emit(b, 0xF9000000U |
            (((((uint32_t)offsetof(ppc32_ctx_t, ras)) +
               ((uint32_t)offsetof(ppc32_ibtc_entry_t, entry))) / 8U) << 10) |
            (21U << 5) | 22U);
}

static void emit_chain_jump_tail(a64_buf_t *b)
{
    /* mov x27, x23 (cur_entry = next_entry) */
    a64_emit(b, 0xAA1703FBU);
    /* add x24, x24, #1 (chain_hits_delta++) */
    a64_emit(b, 0x91000718U);
    /* br x17 */
    a64_emit(b, 0xD61F0220U);
}

void a64_emit_exit_branch(a64_buf_t *b, uint32_t target_pc)
{
    if (target_pc == b->guest_start_pc && b->guest_start_pc != 0U && !b->is_call) {
        b->has_self_loop = true;
        emit_exit_sig_check(b, 7U);
        /* [4] ldar w21, [x28] (cur_epoch = g_cache_epoch) */
        a64_emit(b, 0x88DFFC00U | (28U << 5) | 21U);
        /* [5] ldr x22, [x27, #0] (cur_entry->key | (cur_entry->epoch << 32)) */
        a64_emit(b, 0xF9400376U);
        /* [6] eor x21, x21, x22, lsr #32 */
        a64_emit(b, 0xCA5682B5U);
        /* [7] cbnz x21, .Lbail (+3 words) */
        a64_emit(b, 0xB5000015U | (3U << 5));
        /* [8] add x24, x24, #1 (chain_hits_delta++) */
        a64_emit(b, 0x91000718U);
        /* [9] b loop_body_offset (direct PC-relative branch inside block!) */
        int32_t back_disp = (int32_t)b->loop_body_offset - (int32_t)b->count;
        a64_emit(b, 0x14000000U | ((uint32_t)back_disp & 0x03FFFFFFU));
        /* [10] .Lbail: return to trampoline */
        a64_emit_mov_pc32(b, A64_TMP0, target_pc);
        a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_BRANCH, 0U);
        a64_emit(b, 0xD65F03C0U); /* ret */
        return;
    }

    unsigned s = A64_MAX_EXIT_SLOTS;
    for (unsigned i = 0U; i < b->exit_slot_count; i++) {
        if (b->exit_slot_pcs[i] == target_pc) {
            s = i;
            break;
        }
    }
    if (s == A64_MAX_EXIT_SLOTS && b->exit_slot_count < A64_MAX_EXIT_SLOTS) {
        s = b->exit_slot_count++;
        b->exit_slot_pcs[s] = target_pc;
    }

    if (s < A64_MAX_EXIT_SLOTS) {
        uint32_t call_extra = b->is_call ? 8U : 0U;
        emit_exit_sig_check(b, 10U + call_extra);
        /* ldr x23, [x27, #(152 + s*8)] (cur_entry->slot_entry[s], uimm = 19 + s) */
        a64_emit(b, 0xF9400000U | (((19U + s) & 0xFFFU) << 10) | (27U << 5) | 23U);
        /* cbz x23, .Lbail */
        a64_emit(b, 0xB4000017U | ((8U + call_extra) << 5));
        /* ldar w21, [x28] (cur_epoch = g_cache_epoch) */
        a64_emit(b, 0x88DFFC00U | (28U << 5) | 21U);
        /* ldp x22, x17, [x23, #0] (x22 = key|epoch, x17 = host_code) */
        a64_emit(b, 0xA9400000U | (1U << 31) | (17U << 10) | (23U << 5) | 22U);
        /* eor x21, x21, x22, lsr #32 */
        a64_emit(b, 0xCA5682B5U);
        /* cbnz x21, .Lbail */
        a64_emit(b, 0xB5000015U | ((4U + call_extra) << 5));
        if (b->is_call) {
            emit_ras_push_inline(b);
        }
        emit_chain_jump_tail(b);
    }

    /* .Lbail */
    a64_emit_mov_pc32(b, A64_TMP0, target_pc);
    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_BRANCH, 0U);
    a64_emit(b, 0xD65F03C0U); /* ret */
}

/* a64_emit_exit_branch_imm (interwork) was dropped: PowerPC has no
 * interworking; direct branches use a64_emit_exit_branch. */

void a64_emit_exit_branch_reg(a64_buf_t *b, unsigned target_reg)
{
    if (b->lr_written_from_pc) {
        b->is_call = true;
    }
    if (target_reg != A64_TMP0) {
        a64_emit_mov_w(b, A64_TMP0, target_reg);
    }

    size_t patch_sig = emit_exit_sig_check(b, 0U);

    /* ldar w21, [x28] */
    a64_emit(b, 0x88DFFC00U | (28U << 5) | 21U);
    /* cbz w21, .Lbail */
    size_t patch_ep0 = b->count;
    a64_emit(b, 0x34000015U);

    /* mov w16, w15 (next cache key = guest NIP; identity, no T bit) */
    a64_emit_orr_reg_w(b, A64_TMP1, A64_ZR, A64_TMP0, A64_SHIFT_LSL, 0U);
    /* orr x16, x16, x21, lsl #32 (x16 = next_key | (cur_epoch << 32)) */
    a64_emit(b, 0xAA158210U);

    if (!b->is_call) {
        /* Inline RAS Pop */
        /* ldr w17, [x19, #480] (w17 = ctx->ras_top) */
        a64_emit(b, 0xB9400000U |
                ((((uint32_t)offsetof(ppc32_ctx_t, ras_top)) / 4U) << 10) |
                (A64_XCTX << 5) | 17U);
        /* sub w17, w17, #1 */
        a64_emit(b, 0x51000631U);
        /* and w17, w17, #0x3f */
        a64_emit(b, 0x12001631U);
        /* add x22, x19, x17, lsl #5 */
        a64_emit(b, 0x8B111676U);
        /* ldr x23, [x22, #504] (ras[r_idx].entry, uimm = (ras_off+16)/8; computed via offsetof) */
        a64_emit(b, 0xF9400000U |
                (((((uint32_t)offsetof(ppc32_ctx_t, ras)) +
                   ((uint32_t)offsetof(ppc32_ibtc_entry_t, entry))) / 8U) << 10) |
                (22U << 5) | 23U);
        /* cbz x23, .Ltry_ibtc */
        size_t patch_ras_null = b->count;
        a64_emit(b, 0xB4000017U);
        /* ldp x21, x22, [x23, #0] (x21 = entry->key|epoch, x22 = entry->host_code) */
        a64_emit(b, 0xA9400000U | (1U << 31) | (22U << 10) | (23U << 5) | 21U);
        /* eor x21, x21, x16 */
        a64_emit(b, 0xCA1002B5U);
        /* cbnz x21, .Ltry_ibtc */
        size_t patch_ras_miss = b->count;
        a64_emit(b, 0xB5000015U);
        /* str w17, [x19, #480] (commit pop: ctx->ras_top = r_idx) */
        a64_emit(b, 0xB9000000U |
                ((((uint32_t)offsetof(ppc32_ctx_t, ras_top)) / 4U) << 10) |
                (A64_XCTX << 5) | 17U);
        /* mov x27, x23 (cur_entry = next_entry) */
        a64_emit(b, 0xAA1703FBU);
        /* add x24, x24, #1 (chain_hits_delta++) */
        a64_emit(b, 0x91000718U);
        /* br x22 */
        a64_emit(b, 0xD61F02C0U);

        /* Patch patch_ras_null and patch_ras_miss to here (.Ltry_ibtc) */
        size_t try_ibtc_idx = b->count;
        b->words[patch_ras_null] |= (((uint32_t)(try_ibtc_idx - patch_ras_null) & 0x7FFFFU) << 5);
        b->words[patch_ras_miss] |= (((uint32_t)(try_ibtc_idx - patch_ras_miss) & 0x7FFFFU) << 5);
    }

    /* .Ltry_ibtc: */
    /* ubfx w17, w16, #2, #10 (ppc32_ibtc_hash: (nip >> 2) & (IBTC_SIZE-1)) */
    a64_emit(b, 0x53022E11U);
    /* add x22, x19, x17, lsl #5 */
    a64_emit(b, 0x8B111676U);
    /* ldr x23, [x22, #2552] (offsetof(ppc32_ctx_t, ibtc) + offsetof(ppc32_ibtc_entry_t, entry), uimm = (ibtc_off+16)/8; computed via offsetof) */
    a64_emit(b, 0xF9400000U |
            (((((uint32_t)offsetof(ppc32_ctx_t, ibtc)) +
               ((uint32_t)offsetof(ppc32_ibtc_entry_t, entry))) / 8U) << 10) |
            (22U << 5) | 23U);
    /* cbz x23, .Lbail */
    size_t patch_ibtc_null = b->count;
    a64_emit(b, 0xB4000017U);
    /* ldp x21, x17, [x23, #0] */
    a64_emit(b, 0xA9400000U | (1U << 31) | (17U << 10) | (23U << 5) | 21U);
    /* eor x21, x21, x16 */
    a64_emit(b, 0xCA1002B5U);
    /* cbnz x21, .Lbail */
    size_t patch_ibtc_miss = b->count;
    a64_emit(b, 0xB5000015U);

    if (b->is_call) {
        emit_ras_push_inline(b);
    }
    emit_chain_jump_tail(b);

    /* .Lbail: */
    size_t bail_idx = b->count;
    b->words[patch_sig] |= (((uint32_t)(bail_idx - patch_sig) & 0x7FFFFU) << 5);
    b->words[patch_ep0] |= (((uint32_t)(bail_idx - patch_ep0) & 0x7FFFFU) << 5);
    b->words[patch_ibtc_null] |= (((uint32_t)(bail_idx - patch_ibtc_null) & 0x7FFFFU) << 5);
    b->words[patch_ibtc_miss] |= (((uint32_t)(bail_idx - patch_ibtc_miss) & 0x7FFFFU) << 5);

    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_BRANCH, 0U);
    a64_emit(b, 0xD65F03C0U); /* ret */
}

void a64_emit_exit_syscall(a64_buf_t *b, uint32_t next_pc, uint32_t syscall_nr)
{
    a64_emit_mov_imm32(b, A64_TMP0, syscall_nr);
    a64_emit_str_imm_w(b, A64_TMP0, A64_XCTX, (uint32_t)offsetof(ppc32_ctx_t, exit_arg));
    a64_emit_mov_pc32(b, A64_TMP0, next_pc);
    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_SYSCALL, 0U);
    a64_emit_ret(b);
}

void a64_emit_exit_undef(a64_buf_t *b, uint32_t fault_pc)
{
    a64_emit_mov_pc32(b, A64_TMP0, fault_pc);
    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_UNDEF, 0U);
    a64_emit_ret(b);
}

void a64_emit_exit_trap(a64_buf_t *b, uint32_t trap_pc)
{
    a64_emit_mov_pc32(b, A64_TMP0, trap_pc);
    a64_emit_str_imm_w(b, A64_TMP0, A64_XCTX, (uint32_t)offsetof(ppc32_ctx_t, nip));
    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_TRAP, 0U);
    a64_emit_ret(b);
}

void a64_emit_exit_fault(a64_buf_t *b, uint32_t fault_pc, unsigned addr_w)
{
    a64_emit_mov_pc32(b, A64_TMP0, fault_pc);
    a64_emit_str_imm_w(b, A64_TMP0, A64_XCTX, (uint32_t)offsetof(ppc32_ctx_t, nip));
    a64_emit_str_imm_w(b, addr_w, A64_XCTX, (uint32_t)offsetof(ppc32_ctx_t, fault_addr));
    a64_emit_movz_w(b, A64_TMP1, PPC32_EXIT_FAULT, 0U);
    a64_emit_ret(b);
}

/* Parallel add/sub and saturating-arithmetic lowering were dropped:
 * PowerPC has no Q/GE flags; SPE/vector saturating packs arrive with
 * the Phase 3 DBT. */

void a64_emit_xt_add(a64_buf_t *b, bool is_signed, bool is_16, bool is_dual8,
                     unsigned rd, unsigned rn, unsigned rm, unsigned rot)
{
    a64_emit_orr_reg_w(b, A64_TMP0, A64_ZR, rm, A64_SHIFT_ROR, rot);
    if (is_dual8) {
        if (is_signed) {
            a64_emit_sbfm_w(b, A64_TMP1, A64_TMP0, 0U, 7U);
            a64_emit_sbfm_w(b, A64_TMP0, A64_TMP0, 16U, 23U);
        } else {
            a64_emit_ubfm_w(b, A64_TMP1, A64_TMP0, 0U, 7U);
            a64_emit_ubfm_w(b, A64_TMP0, A64_TMP0, 16U, 23U);
        }
        if (rn != 15U) {
            a64_emit_add_reg_w(b, false, A64_TMP1, A64_TMP1, rn, A64_SHIFT_LSL, 0U);
            a64_emit_add_reg_w(b, false, A64_TMP0, A64_TMP0, rn, A64_SHIFT_LSR, 16U);
        }
        a64_emit_bfm_w(b, A64_TMP1, A64_TMP0, 16U, 15U);
        a64_emit_mov_w(b, rd, A64_TMP1);
    } else {
        unsigned imms = is_16 ? 15U : 7U;
        if (is_signed) {
            a64_emit_sbfm_w(b, A64_TMP0, A64_TMP0, 0U, imms);
        } else {
            a64_emit_ubfm_w(b, A64_TMP0, A64_TMP0, 0U, imms);
        }
        if (rn != 15U) {
            a64_emit_add_reg_w(b, false, rd, rn, A64_TMP0, A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_mov_w(b, rd, A64_TMP0);
        }
    }
}

void a64_emit_pkh(a64_buf_t *b, bool is_tb, unsigned rd, unsigned rn, unsigned rm, unsigned shift_imm)
{
    if (!is_tb) {
        a64_emit_orr_reg_w(b, A64_TMP0, A64_ZR, rm, A64_SHIFT_LSL, shift_imm);
        a64_emit_bfm_w(b, A64_TMP0, rn, 0U, 15U);
        a64_emit_mov_w(b, rd, A64_TMP0);
    } else {
        unsigned amt = (shift_imm == 0U) ? 31U : shift_imm;
        a64_emit_orr_reg_w(b, A64_TMP1, A64_ZR, rm, A64_SHIFT_ASR, amt);
        a64_emit_mov_w(b, A64_TMP0, rn);
        a64_emit_bfm_w(b, A64_TMP0, A64_TMP1, 0U, 15U);
        a64_emit_mov_w(b, rd, A64_TMP0);
    }
}

/* Byte-select (sel) was dropped: no GE-flag counterpart on PowerPC. */

void a64_emit_usad8(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra)
{
    a64_emit_mrs_nzcv(b, A64_TMP3);
    if (ra != 15U) {
        a64_emit_mov_w(b, A64_TMP2, ra);
    } else {
        a64_emit_movz_w(b, A64_TMP2, 0U, 0U);
    }
    for (unsigned i = 0U; i < 4U; i++) {
        a64_emit_ubfm_w(b, A64_TMP0, rn, i * 8U, i * 8U + 7U);
        a64_emit_ubfm_w(b, A64_TMP1, rm, i * 8U, i * 8U + 7U);
        a64_emit_sub_reg_w(b, true, A64_TMP0, A64_TMP0, A64_TMP1, A64_SHIFT_LSL, 0U);
        a64_emit_csneg_w(b, A64_TMP0, A64_TMP0, A64_TMP0, A64_COND_PL);
        a64_emit_add_reg_w(b, false, A64_TMP2, A64_TMP2, A64_TMP0, A64_SHIFT_LSL, 0U);
    }
    a64_emit_msr_nzcv(b, A64_TMP3);
    a64_emit_mov_w(b, rd, A64_TMP2);
}

/* MLA multiply-accumulate variants were dropped: no Q-flag counterpart
 * on PowerPC; SPE MAC ops arrive with the Phase 3 DBT. */

void a64_emit_smlal_xy(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm,
                       bool n_top, bool m_top)
{
    a64_emit_mov_w(b, A64_TMP2, rd_lo);
    a64_emit_bfi_x(b, A64_TMP2, rd_hi, 32U, 32U);
    a64_emit_sbfm_w(b, A64_TMP0, rn, n_top ? 16U : 0U, n_top ? 31U : 15U);
    a64_emit_sbfm_w(b, A64_TMP1, rm, m_top ? 16U : 0U, m_top ? 31U : 15U);
    a64_emit_smaddl_x(b, A64_TMP2, A64_TMP0, A64_TMP1, A64_TMP2);
    a64_emit_mov_w(b, rd_lo, A64_TMP2);
    a64_emit_ubfx_x_to_w(b, rd_hi, A64_TMP2, 32U, 32U);
}

void a64_emit_smlald(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm,
                     bool is_sub, bool m_swap)
{
    unsigned m1_lsb = m_swap ? 16U : 0U;
    unsigned m2_lsb = m_swap ? 0U : 16U;
    a64_emit_mov_w(b, A64_TMP2, rd_lo);
    a64_emit_bfi_x(b, A64_TMP2, rd_hi, 32U, 32U);
    a64_emit_sbfm_w(b, A64_TMP0, rn, 0U, 15U);
    a64_emit_sbfm_w(b, A64_TMP1, rm, m1_lsb, m1_lsb + 15U);
    a64_emit_smaddl_x(b, A64_TMP2, A64_TMP0, A64_TMP1, A64_TMP2);
    a64_emit_sbfm_w(b, A64_TMP0, rn, 16U, 31U);
    a64_emit_sbfm_w(b, A64_TMP1, rm, m2_lsb, m2_lsb + 15U);
    if (is_sub) {
        a64_emit_smsubl_x(b, A64_TMP2, A64_TMP0, A64_TMP1, A64_TMP2);
    } else {
        a64_emit_smaddl_x(b, A64_TMP2, A64_TMP0, A64_TMP1, A64_TMP2);
    }
    a64_emit_mov_w(b, rd_lo, A64_TMP2);
    a64_emit_ubfx_x_to_w(b, rd_hi, A64_TMP2, 32U, 32U);
}

void a64_emit_smmla(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra,
                    bool is_sub, bool round)
{
    if (round) {
        a64_emit_movz_w(b, A64_TMP1, 0x8000U, 1U);
    } else {
        a64_emit_movz_w(b, A64_TMP1, 0U, 0U);
    }
    if (is_sub || ra != 15U) {
        a64_emit_bfi_x(b, A64_TMP1, ra, 32U, 32U);
    }
    if (is_sub) {
        a64_emit_smsubl_x(b, A64_TMP0, rn, rm, A64_TMP1);
    } else {
        a64_emit_smaddl_x(b, A64_TMP0, rn, rm, A64_TMP1);
    }
    a64_emit_ubfx_x_to_w(b, rd, A64_TMP0, 32U, 32U);
}

void a64_emit_umaal(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm)
{
    a64_emit_mov_w(b, A64_TMP1, rd_lo);
    a64_emit_umaddl_x(b, A64_TMP0, rn, rm, A64_TMP1);
    a64_emit_add_uxtw_x(b, A64_TMP0, A64_TMP0, rd_hi);
    a64_emit_mov_w(b, rd_lo, A64_TMP0);
    a64_emit_ubfx_x_to_w(b, rd_hi, A64_TMP0, 32U, 32U);
}

void a64_emit_mull(a64_buf_t *b, bool is_signed, bool accumulate, bool set_flags,
                   unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm)
{
    unsigned acc_x = A64_ZR;
    if (accumulate) {
        a64_emit_mov_w(b, A64_TMP1, rd_lo);
        a64_emit_bfi_x(b, A64_TMP1, rd_hi, 32U, 32U);
        acc_x = A64_TMP1;
    }
    if (is_signed) {
        a64_emit_smaddl_x(b, A64_TMP0, rn, rm, acc_x);
    } else {
        a64_emit_umaddl_x(b, A64_TMP0, rn, rm, acc_x);
    }
    a64_emit_mov_w(b, rd_lo, A64_TMP0);
    a64_emit_ubfx_x_to_w(b, rd_hi, A64_TMP0, 32U, 32U);
    if (set_flags) {
        a64_emit_mrs_nzcv(b, A64_TMP3);
        a64_emit(b, 0xEA000000U | (A64_TMP0 << 16) | (A64_TMP0 << 5) | A64_ZR);
        a64_emit_mrs_nzcv(b, A64_TMP2);
        a64_emit_ubfm_w(b, A64_TMP3, A64_TMP3, 28U, 29U);
        a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP3, A64_SHIFT_LSL, 28U);
        a64_emit_msr_nzcv(b, A64_TMP2);
    }
}

/* Condition-register accessors, SPR/TLS helpers, and lmw/stmw-class
 * multi-register lowering were dropped: A32-only, no PPC counterpart;
 * CR/XER/mfcr/mtcrf/mfspr lowering arrives with the Phase 2/3 DBT. */

