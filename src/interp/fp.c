/*
 * src/interp/fp.c — classic-FPU data-movement reference (RC2 subset).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * See fp.h. Lane L3a owns FP arithmetic/SPE and extends this file.
 */

#include "interp/fp.h"

#include "interp/interp.h"

void ppc32_fp_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn)
{
    uint32_t ea;

    switch (insn->op) {
    case PPC32_OP_LFS:
    case PPC32_OP_LFSU:
    case PPC32_OP_LFD:
    case PPC32_OP_LFDU:
    case PPC32_OP_STFS:
    case PPC32_OP_STFSU:
    case PPC32_OP_STFD:
    case PPC32_OP_STFDU:
        break;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    if (insn->rt >= 32U) {
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    if (insn->ra == 0U) {
        if (insn->op == PPC32_OP_LFSU || insn->op == PPC32_OP_LFDU ||
            insn->op == PPC32_OP_STFSU || insn->op == PPC32_OP_STFDU) {
            ctx->exit_reason = PPC32_EXIT_UNDEF; /* update with r0 */
            return;
        }
        ea = (uint32_t)insn->d;
    } else {
        if (insn->ra >= 32U) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
        ea = ctx->gpr[insn->ra] + (uint32_t)insn->d;
    }
    switch (insn->op) {
    case PPC32_OP_LFS:
    case PPC32_OP_LFSU:
        ctx->fpr[insn->rt] = (uint64_t)ld32(ctx, ea);
        break;
    case PPC32_OP_LFD:
    case PPC32_OP_LFDU:
        ctx->fpr[insn->rt] =
            ((uint64_t)ld32(ctx, ea) << 32U) | (uint64_t)ld32(ctx, ea + 4U);
        break;
    case PPC32_OP_STFS:
    case PPC32_OP_STFSU:
        st32(ctx, ea, (uint32_t)ctx->fpr[insn->rt]);
        break;
    default:
        st32(ctx, ea, (uint32_t)(ctx->fpr[insn->rt] >> 32U));
        st32(ctx, ea + 4U, (uint32_t)ctx->fpr[insn->rt]);
        break;
    }
    if (insn->op == PPC32_OP_LFSU || insn->op == PPC32_OP_LFDU ||
        insn->op == PPC32_OP_STFSU || insn->op == PPC32_OP_STFDU) {
        ctx->gpr[insn->ra] = ea;
    }
    ctx->nip += 4U;
}
