/*
 * src/dbt/trampoline_a64.S — host <-> translated-code switch for ppc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * uint32_t ppc32_jit_run_block(ppc32_ctx_t *ctx, const void *code,
 *                              void *cur_entry, const void *epoch_ptr);
 *
 * Register contract with emitted code (frozen in src/dbt/dbt.h and the
 * carried src/rt32/ppc32_a64_emit* exit sequences):
 *   x19 = xCtx (ppc32_ctx_t *), x20 = xG (ctx->guest_base),
 *   x27 = cur_entry (ppc32_block_t *), x28 = &g_cache_epoch,
 *   x24 = chain_hits delta accumulator (starts at 0).
 * Emitted fragments chain among themselves with `br` (slot/IBTC/RAS
 * paths) and return here with `ret`, w15 = exit destination pc,
 * w16 = PPC32_EXIT_* reason. The epilogue stores exit_reason/exit_dest,
 * stores nip = w15 for BRANCH/UNDEF/SYSCALL exits (TRAP and FAULT exits
 * store nip themselves before returning), folds x24 into
 * ctx->chain_hits, and returns the reason in w0.
 *
 * ABI-locked ctx offsets used here (dbt.c pins them with _Static_assert;
 * update both sides together): nip@0x100, guest_base@0x228,
 * chain_hits@0x260, exit_reason@0x288, exit_dest@0x294.
 *
 * Host callee-saved state (x19-x28, fp, lr) is preserved across the call.
 * The platform register is never read or written. Emitted code owns
 * w0-w17/w21-w23 and v0-v7 only.
 */

    .text
    .align 4
#ifdef __APPLE__
    .globl _ppc32_jit_run_block
_ppc32_jit_run_block:
#else
    .globl ppc32_jit_run_block
    .type ppc32_jit_run_block, %function
ppc32_jit_run_block:
#endif
    /* Frame for x19-x28 plus fp/lr: 6 pairs = 96 bytes, SP 16-aligned. */
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]

    mov     x19, x0                 /* x19 = xCtx */
    ldr     x20, [x19, #552]        /* x20 = xG (guest_base @0x228) */
    mov     x27, x2                 /* x27 = cur_entry */
    mov     x28, x3                 /* x28 = &g_cache_epoch */
    mov     x24, #0                 /* chain_hits delta = 0 */
    mov     x23, x1                 /* stash code ptr (emitted code
                                       may use w0-w17 freely) */
    blr     x23                     /* enter translated block */

    /* Epilogue: w15 = exit dest pc, w16 = reason, x24 = chain delta. */
    str     w16, [x19, #648]        /* ctx->exit_reason @0x288 */
    str     w15, [x19, #660]        /* ctx->exit_dest @0x294 */
    cmp     w16, #5                 /* TRAP stores nip itself */
    b.eq    .Lchain_fold
    cmp     w16, #4                 /* FAULT stores nip itself */
    b.eq    .Lchain_fold
    str     w15, [x19, #256]        /* ctx->nip @0x100 */
.Lchain_fold:
    ldr     x8, [x19, #608]         /* ctx->chain_hits @0x260 */
    add     x8, x8, x24
    str     x8, [x19, #608]
    mov     w0, w16                 /* return reason */

    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #64]
    ldp     x27, x28, [sp, #80]
    ldp     x29, x30, [sp], #96
    ret

#ifndef __APPLE__
    .size ppc32_jit_run_block, . - ppc32_jit_run_block
#endif
