/*
 * src/interp/interp.c — Base integer reference interpreter (Phase 1 L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements SPEC section 2.2 Book I integer ISA (classic 32-bit
 * semantics; FPU/SPE arrive in Phase 3): arithmetic/logical with XER.CA
 * and XER.OV/SO plus CR0 update on Rc=1, rotate/mask (incl. MB>ME wrap
 * per E02), shifts (sraw/srawi CA per the dropped-bit rule, E02), CR
 * logical ops, mfcr/mtcrf/mfspr/mtspr, branches (BO/BI/LK), sc, string/
 * multiple/byte-reverse loads and stores, load/store with update, and
 * lwarx/stwcx. with the SPEC section 2.1 reservation slot (E06).
 *
 * Field extraction not covered by ppc32_insn_t is decoded here from
 * insn->raw with the standard Book I layouts: SH/MB/ME (M-form),
 * TO (trap D/X-forms), NB (lswi/stswi), SPR (mfspr/mtspr), CRM
 * (mtcrf), crD/crS/BA/BB (CR ops, mcrf), BF/L (cmp/cmpl).
 *
 * XER bit positions (E02): SO=0x80000000, OV=0x40000000, CA=0x20000000.
 * CR field i occupies bits (28-4i)..(31-4i); CR0.SO=0x10000000 (E01).
 * Guest memory is big-endian: every multi-byte guest access byte-swaps
 * (ppc32_be16/32 helpers). Unaligned byte/half/word accesses are legal
 * and go through memcpy; lmw/stmw/lwarx/stwcx. require word-aligned EA
 * and report PPC32_EXIT_FAULT otherwise (fault_addr = EA).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ppc32rt.h"
#include "interp/interp.h"
#include "interp/fp.h"

/* Internal helpers (guest memory, branches, traps) live in
 * interp.h as static inline so both engines share one copy. */

/* ------------------------------------------------------------------ */
/* interp_step                                                        */
/* ------------------------------------------------------------------ */

void interp_step(ppc32_ctx_t *ctx)
{
    ppc32_insn_t insn;
    uint32_t raw;
    uint32_t a;
    uint32_t b;
    uint32_t r;
    uint64_t wide;
    bool ov;

    if (!ctx->vm_ready) {
        fault(ctx, ctx->nip);
        return;
    }
    raw = fetch_raw(ctx);
    (void)ppc_decode(raw, &insn);

    switch (insn.op) {
    /* ---- D-form arithmetic/immediate -------------------------- */
    case PPC32_OP_ADDI:
        ctx->gpr[insn.rt] = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            (uint32_t)insn.si;
        ctx->nip += 4U;
        break;
    case PPC32_OP_ADDIS:
        ctx->gpr[insn.rt] = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            ((uint32_t)insn.si << 16U);
        ctx->nip += 4U;
        break;
    case PPC32_OP_ADDIC:
    case PPC32_OP_ADDIC_DOT:
        a = ctx->gpr[insn.ra];
        wide = (uint64_t)a + (uint64_t)(uint32_t)insn.si;
        ctx->gpr[insn.rt] = (uint32_t)wide;
        xer_set_ca(ctx, (wide >> 32U) != 0U);
        if (insn.op == PPC32_OP_ADDIC_DOT) {
            set_cr0(ctx, (uint32_t)wide);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_SUBFIC:
        a = ctx->gpr[insn.ra];
        b = (uint32_t)insn.si;
        ctx->gpr[insn.rt] = b - a;
        xer_set_ca(ctx, b >= a);
        ctx->nip += 4U;
        break;
    case PPC32_OP_MULLI:
        ctx->gpr[insn.rt] = ctx->gpr[insn.ra] * (uint32_t)insn.si;
        ctx->nip += 4U;
        break;
    case PPC32_OP_ANDI:
    case PPC32_OP_ANDIS:
        b = (insn.op == PPC32_OP_ANDI) ? insn.ui : (insn.ui << 16U);
        ctx->gpr[insn.ra] = ctx->gpr[insn.rs] & b;
        set_cr0(ctx, ctx->gpr[insn.ra]);
        ctx->nip += 4U;
        break;
    case PPC32_OP_ORI:
    case PPC32_OP_ORIS:
        b = (insn.op == PPC32_OP_ORI) ? insn.ui : (insn.ui << 16U);
        ctx->gpr[insn.ra] = ctx->gpr[insn.rs] | b;
        ctx->nip += 4U;
        break;
    case PPC32_OP_XORI:
    case PPC32_OP_XORIS:
        b = (insn.op == PPC32_OP_XORI) ? insn.ui : (insn.ui << 16U);
        ctx->gpr[insn.ra] = ctx->gpr[insn.rs] ^ b;
        ctx->nip += 4U;
        break;
    /* ---- compares --------------------------------------------- */
    case PPC32_OP_CMP:
    case PPC32_OP_CMPL: {
        uint32_t bf = (raw >> 23U) & 7U;
        bool l = ((raw >> 21U) & 1U) != 0U;

        if (l) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            break;
        }
        a = ctx->gpr[insn.ra];
        b = ctx->gpr[insn.rb];
        if (insn.op == PPC32_OP_CMP) {
            set_crf(ctx, bf, (int32_t)a < (int32_t)b,
                (int32_t)a > (int32_t)b, a == b);
        } else {
            set_crf(ctx, bf, a < b, a > b, a == b);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_CMPI:
    case PPC32_OP_CMPLI: {
        uint32_t bf = (raw >> 23U) & 7U;
        bool l = ((raw >> 21U) & 1U) != 0U;

        if (l) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            break;
        }
        a = ctx->gpr[insn.ra];
        if (insn.op == PPC32_OP_CMPI) {
            int32_t s = insn.si;
            set_crf(ctx, bf, (int32_t)a < s, (int32_t)a > s,
                (int32_t)a == s);
        } else {
            set_crf(ctx, bf, a < insn.ui, a > insn.ui, a == insn.ui);
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- XO-form ALU ------------------------------------------ */
    case PPC32_OP_ADD:
    case PPC32_OP_ADDC:
    case PPC32_OP_ADDE:
    case PPC32_OP_ADDME:
    case PPC32_OP_ADDZE:
        a = ctx->gpr[insn.ra];
        b = ctx->gpr[insn.rb];
        wide = (uint64_t)a + (uint64_t)b;
        if (insn.op == PPC32_OP_ADDE) {
            wide += (uint64_t)((ctx->xer >> 29U) & 1U);
        } else if (insn.op == PPC32_OP_ADDME) {
            wide = (uint64_t)a + (uint64_t)((ctx->xer >> 29U) & 1U) +
                0xFFFFFFFFULL;
        } else if (insn.op == PPC32_OP_ADDZE) {
            wide = (uint64_t)a + (uint64_t)((ctx->xer >> 29U) & 1U);
        }
        r = (uint32_t)wide;
        ctx->gpr[insn.rt] = r;
        if (insn.op != PPC32_OP_ADD) {
            xer_set_ca(ctx, (wide >> 32U) != 0U);
        }
        if (insn.oe != 0U) {
            ov = add_overflow(a, (uint32_t)(wide - a), r);
            xer_set_ov(ctx, ov);
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_SUBF:
    case PPC32_OP_SUBFC:
    case PPC32_OP_SUBFE:
    case PPC32_OP_SUBFME:
    case PPC32_OP_SUBFZE:
        a = ctx->gpr[insn.ra];
        b = ctx->gpr[insn.rb];
        if (insn.op == PPC32_OP_SUBFME) {
            wide = (uint64_t)(~a) +
                (uint64_t)((ctx->xer >> 29U) & 1U) + 0xFFFFFFFFULL;
        } else if (insn.op == PPC32_OP_SUBFZE) {
            wide = (uint64_t)(~a) +
                (uint64_t)((ctx->xer >> 29U) & 1U);
        } else {
            wide = (uint64_t)(~a) + (uint64_t)b + 1ULL;
            if (insn.op == PPC32_OP_SUBFE) {
                wide += (uint64_t)((ctx->xer >> 29U) & 1U) - 1ULL;
            }
        }
        r = (uint32_t)wide;
        ctx->gpr[insn.rt] = r;
        if (insn.op != PPC32_OP_SUBF) {
            xer_set_ca(ctx, (wide >> 32U) != 0U);
        }
        if (insn.oe != 0U) {
            if (insn.op == PPC32_OP_SUBFME ||
                insn.op == PPC32_OP_SUBFZE) {
                ov = ((r >> 31U) & 1U) != ((~a >> 31U) & 1U);
                xer_set_ov(ctx, ov);
            } else {
                xer_set_ov(ctx, sub_overflow(a, b, r));
            }
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_NEG:
        a = ctx->gpr[insn.ra];
        r = (uint32_t)(0U - a);
        ctx->gpr[insn.rt] = r;
        xer_set_ca(ctx, a == 0U);
        if (insn.oe != 0U) {
            xer_set_ov(ctx, a == 0x80000000U);
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_MULLW: {
        int64_t prod = (int64_t)(int32_t)ctx->gpr[insn.ra] *
            (int64_t)(int32_t)ctx->gpr[insn.rb];

        r = (uint32_t)prod;
        ctx->gpr[insn.rt] = r;
        if (insn.oe != 0U) {
            xer_set_ov(ctx, prod != (int64_t)(int32_t)r);
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_MULHW: {
        int64_t prod = (int64_t)(int32_t)ctx->gpr[insn.ra] *
            (int64_t)(int32_t)ctx->gpr[insn.rb];

        r = (uint32_t)((uint64_t)prod >> 32U);
        ctx->gpr[insn.rt] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_MULHWU:
        wide = (uint64_t)ctx->gpr[insn.ra] * (uint64_t)ctx->gpr[insn.rb];
        r = (uint32_t)(wide >> 32U);
        ctx->gpr[insn.rt] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_DIVW:
    case PPC32_OP_DIVWU: {
        int32_t sa = (int32_t)ctx->gpr[insn.ra];
        int32_t sb = (int32_t)ctx->gpr[insn.rb];

        if (insn.op == PPC32_OP_DIVW) {
            if (sb == 0) {
                r = 0U;
            } else if (sa == (int32_t)0x80000000U && sb == -1) {
                r = 0x80000000U;
            } else {
                r = (uint32_t)(sa / sb);
            }
        } else {
            if (ctx->gpr[insn.rb] == 0U) {
                r = 0U;
            } else {
                r = ctx->gpr[insn.ra] / ctx->gpr[insn.rb];
            }
        }
        ctx->gpr[insn.rt] = r;
        if (insn.oe != 0U) {
            xer_set_ov(ctx, insn.op == PPC32_OP_DIVW && sb != 0 &&
                sa == (int32_t)0x80000000U && sb == -1);
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- XO-form logical -------------------------------------- */
    case PPC32_OP_AND:
    case PPC32_OP_ANDC:
    case PPC32_OP_OR:
    case PPC32_OP_ORC:
    case PPC32_OP_XOR:
    case PPC32_OP_NAND:
    case PPC32_OP_NOR:
    case PPC32_OP_EQV:
        a = ctx->gpr[insn.rs];
        b = ctx->gpr[insn.rb];
        switch (insn.op) {
        case PPC32_OP_AND:
            r = a & b;
            break;
        case PPC32_OP_ANDC:
            r = a & ~b;
            break;
        case PPC32_OP_OR:
            r = a | b;
            break;
        case PPC32_OP_ORC:
            r = a | ~b;
            break;
        case PPC32_OP_XOR:
            r = a ^ b;
            break;
        case PPC32_OP_NAND:
            r = ~(a & b);
            break;
        case PPC32_OP_NOR:
            r = ~(a | b);
            break;
        default:
            r = ~(a ^ b);
            break;
        }
        ctx->gpr[insn.ra] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_EXTSB:
        r = (uint32_t)(int32_t)(int8_t)(ctx->gpr[insn.rs] & 0xFFU);
        ctx->gpr[insn.ra] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_EXTSH:
        r = (uint32_t)(int32_t)(int16_t)(ctx->gpr[insn.rs] & 0xFFFFU);
        ctx->gpr[insn.ra] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    case PPC32_OP_CNTLZW:
        a = ctx->gpr[insn.rs];
        r = 0U;
        while (r < 32U && ((a >> (31U - r)) & 1U) == 0U) {
            r++;
        }
        ctx->gpr[insn.ra] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    /* ---- shifts ------------------------------------------------ */
    case PPC32_OP_SLW:
    case PPC32_OP_SRW: {
        uint32_t n = ctx->gpr[insn.rb] & 0x3FU;

        if (n >= 32U) {
            r = 0U;
        } else if (insn.op == PPC32_OP_SLW) {
            r = ctx->gpr[insn.rs] << n;
        } else {
            r = ctx->gpr[insn.rs] >> n;
        }
        ctx->gpr[insn.ra] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_SRAW:
    case PPC32_OP_SRAWI: {
        uint32_t n;
        int32_t s;
        bool drop;

        if (insn.op == PPC32_OP_SRAW) {
            n = ctx->gpr[insn.rb] & 0x3FU;
        } else {
            n = (raw >> 11U) & 31U;
        }
        s = (int32_t)ctx->gpr[insn.rs];
        if (n == 0U) {
            r = (uint32_t)s;
            xer_set_ca(ctx, false);
        } else if (n >= 32U) {
            r = (s < 0) ? 0xFFFFFFFFU : 0U;
            xer_set_ca(ctx, s < 0 && ctx->gpr[insn.rs] != 0U);
        } else {
            r = (uint32_t)(s >> n);
            drop = s < 0 &&
                (ctx->gpr[insn.rs] & ((1U << n) - 1U)) != 0U;
            xer_set_ca(ctx, drop);
        }
        ctx->gpr[insn.ra] = r;
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- rotate/mask (E02) ------------------------------------- */
    case PPC32_OP_RLWINM:
    case PPC32_OP_RLWIMI:
    case PPC32_OP_RLWNM: {
        uint32_t sh;
        uint32_t mb = (raw >> 6U) & 31U;
        uint32_t me = (raw >> 1U) & 31U;
        uint32_t mask = ppc_mask32(mb, me);
        uint32_t rot;

        if (insn.op == PPC32_OP_RLWNM) {
            sh = ctx->gpr[insn.rb] & 31U;
        } else {
            sh = (raw >> 11U) & 31U;
        }
        rot = rotl32(ctx->gpr[insn.rs], sh);
        if (insn.op == PPC32_OP_RLWIMI) {
            r = (rot & mask) | (ctx->gpr[insn.ra] & ~mask);
            ctx->gpr[insn.ra] = r;
        } else {
            r = rot & mask;
            ctx->gpr[insn.ra] = r;
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- CR logical ops (decoder: single PPC32_OP_CR, XO picks) - */
    case PPC32_OP_CR: {
        uint32_t ba = (raw >> 16U) & 31U;
        uint32_t bb = (raw >> 11U) & 31U;
        uint32_t bd = (raw >> 21U) & 31U;
        uint32_t abit = cr_bit(ctx, ba);
        uint32_t bbit = cr_bit(ctx, bb);
        uint32_t out = 0U;

        switch (insn.xo) {
        case 257u: /* crand */
            out = abit & bbit;
            break;
        case 129u: /* crandc */
            out = abit & (bbit ^ 1U);
            break;
        case 449u: /* cror */
            out = abit | bbit;
            break;
        case 417u: /* crorc */
            out = abit | (bbit ^ 1U);
            break;
        case 193u: /* crxor */
            out = abit ^ bbit;
            break;
        case 225u: /* crnand */
            out = (abit & bbit) ^ 1U;
            break;
        case 33u: /* crnor */
            out = (abit | bbit) ^ 1U;
            break;
        case 289u: /* creqv */
        default:
            out = (abit ^ bbit) ^ 1U;
            break;
        }
        if (out != 0U) {
            ctx->cr |= 0x80000000U >> bd;
        } else {
            ctx->cr &= ~(0x80000000U >> bd);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_MCRF: {
        uint32_t crd = (raw >> 23U) & 7U;
        uint32_t crs = (raw >> 18U) & 7U;
        uint32_t v = (ctx->cr >> ((7U - crs) * 4U)) & 0xFU;

        ctx->cr = (ctx->cr & ~(0xFU << ((7U - crd) * 4U))) |
            (v << ((7U - crd) * 4U));
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_MCRXR: {
        uint32_t crd = (raw >> 23U) & 7U;
        uint32_t v = (ctx->xer >> 28U) & 0xFU;

        ctx->cr = (ctx->cr & ~(0xFU << ((7U - crd) * 4U))) |
            (v << ((7U - crd) * 4U));
        ctx->xer &= 0x0FFFFFFFU;
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_MFCR:
        ctx->gpr[insn.rt] = ctx->cr;
        ctx->nip += 4U;
        break;
    case PPC32_OP_MTCRF: {
        uint32_t crm = (raw >> 12U) & 0xFFU;
        uint32_t i;

        for (i = 0U; i < 8U; i++) {
            if (((crm >> (7U - i)) & 1U) != 0U) {
                uint32_t shift = (7U - i) * 4U;
                ctx->cr = (ctx->cr & ~(0xFU << shift)) |
                    ((ctx->gpr[insn.rs] >> shift) & 0xFU) << shift;
            }
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_MFSPR:
    case PPC32_OP_MTSPR: {
        uint32_t spr = (((raw >> 11U) & 31U) << 5U) | ((raw >> 16U) & 31U);

        if (insn.op == PPC32_OP_MFSPR) {
            switch (spr) {
            case PPC32_SPR_XER:
                ctx->gpr[insn.rt] = ctx->xer;
                break;
            case PPC32_SPR_LR:
                ctx->gpr[insn.rt] = ctx->lr;
                break;
            case PPC32_SPR_CTR:
                ctx->gpr[insn.rt] = ctx->ctr;
                break;
            case 268U:
            case 269U:
                ctx->gpr[insn.rt] = 0U;
                break;
            case PPC32_SPR_PVR: /* mfpvr: glibc IFUNC dispatch reads it */
                ctx->gpr[insn.rt] = (ctx->profile == PPC32_PROFILE_SPE) ?
                    PPC32_PVR_E500V2 : PPC32_PVR_750;
                break;
            default:
                ctx->exit_reason = PPC32_EXIT_UNDEF;
                break;
            }
        } else {
            switch (spr) {
            case PPC32_SPR_XER:
                ctx->xer = ctx->gpr[insn.rs];
                break;
            case PPC32_SPR_LR:
                ctx->lr = ctx->gpr[insn.rs];
                break;
            case PPC32_SPR_CTR:
                ctx->ctr = ctx->gpr[insn.rs];
                break;
            default:
                ctx->exit_reason = PPC32_EXIT_UNDEF;
                break;
            }
        }
        if (ctx->exit_reason == PPC32_EXIT_NONE) {
            ctx->nip += 4U;
        }
        break;
    }
    /* ---- branches (no delay slots) ------------------------------ */
    case PPC32_OP_B: {
        uint32_t aa = (raw >> 1U) & 1U;
        uint32_t target = (aa != 0U) ? (uint32_t)insn.li
                                     : ctx->nip + (uint32_t)insn.li;

        branch_to(ctx, target, (uint8_t)(raw & 1U));
        break;
    }
    case PPC32_OP_BC: {
        uint32_t aa = (raw >> 1U) & 1U;
        uint32_t target = (aa != 0U) ? (uint32_t)insn.bd
                                     : ctx->nip + (uint32_t)insn.bd;
        /* NOTE: branch_cond decrements CTR; evaluate exactly once. */
        bool take = branch_cond(ctx, insn.bo, insn.bi);

        if (take) {
            branch_to(ctx, target, (uint8_t)(raw & 1U));
        } else {
            if ((raw & 1U) != 0U) {
                ctx->lr = ctx->nip + 4U;
            }
            ctx->nip += 4U;
        }
        break;
    }
    case PPC32_OP_BCLR: {
        uint32_t target = ctx->lr;
        /* NOTE: branch_cond decrements CTR; evaluate exactly once. */
        bool take = branch_cond(ctx, insn.bo, insn.bi);

        if (take) {
            branch_to(ctx, target, (uint8_t)(raw & 1U));
        } else {
            if ((raw & 1U) != 0U) {
                ctx->lr = ctx->nip + 4U;
            }
            ctx->nip += 4U;
        }
        break;
    }
    case PPC32_OP_BCCTR: {
        uint32_t target = ctx->ctr;
        /* NOTE: branch_cond decrements CTR; evaluate exactly once. */
        bool take =
            branch_cond(ctx, (uint8_t)(insn.bo | 4U), insn.bi);

        if (take) {
            branch_to(ctx, target, (uint8_t)(raw & 1U));
        } else {
            if ((raw & 1U) != 0U) {
                ctx->lr = ctx->nip + 4U;
            }
            ctx->nip += 4U;
        }
        break;
    }
    /* ---- D-form loads/stores ----------------------------------- */
    case PPC32_OP_LBZ:
    case PPC32_OP_LBZU:
    case PPC32_OP_LHZ:
    case PPC32_OP_LHZU:
    case PPC32_OP_LHA:
    case PPC32_OP_LHAU:
    case PPC32_OP_LWZ:
    case PPC32_OP_LWZU:
    case PPC32_OP_STB:
    case PPC32_OP_STBU:
    case PPC32_OP_STH:
    case PPC32_OP_STHU:
    case PPC32_OP_STW:
    case PPC32_OP_STWU: {
        interp_exec_dform_mem(ctx, &insn);
        break;
    }
    /* ---- X-form indexed loads/stores ---------------------------- */
    case PPC32_OP_LBZX:
    case PPC32_OP_LBZUX:
    case PPC32_OP_LHZX:
    case PPC32_OP_LHZUX:
    case PPC32_OP_LHAX:
    case PPC32_OP_LHAUX:
    case PPC32_OP_LWZX:
    case PPC32_OP_LWZUX:
    case PPC32_OP_STBX:
    case PPC32_OP_STBUX:
    case PPC32_OP_STHX:
    case PPC32_OP_STHUX:
    case PPC32_OP_STWX:
    case PPC32_OP_STWUX: {
        interp_exec_xform_mem(ctx, &insn);
        break;
    }
    /* ---- multiple/string word ops (E05) ------------------------- */
    case PPC32_OP_LMW:
    case PPC32_OP_STMW: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            (uint32_t)insn.d;
        uint32_t rt = insn.rt;
        uint32_t idx;

        if ((ea & 3U) != 0U) {
            fault(ctx, ea);
            break;
        }
        for (idx = rt; idx < 32U; idx++) {
            if (insn.op == PPC32_OP_LMW) {
                ctx->gpr[idx] = ld32(ctx, ea);
            } else {
                st32(ctx, ea, ctx->gpr[idx]);
            }
            ea += 4U;
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_LSWI:
    case PPC32_OP_STSWI: {
        uint32_t ea = (insn.ra == 0U) ? 0U : ctx->gpr[insn.ra];
        uint32_t nb = ((raw >> 11U) & 31U);
        uint32_t n = (nb == 0U) ? 32U : nb;
        uint32_t i;

        if (insn.op == PPC32_OP_LSWI) {
            uint32_t cur = 0U;
            uint32_t cur_reg = 0U;
            bool have = false;

            for (i = 0U; i < n; i++) {
                uint32_t reg = (insn.rt + i / 4U) & 31U;
                uint32_t shift = (3U - (i % 4U)) * 8U;

                if (!have || reg != cur_reg) {
                    if (have) {
                        ctx->gpr[cur_reg] = cur;
                    }
                    cur = ctx->gpr[reg];
                    cur_reg = reg;
                    have = true;
                }
                cur = (cur & ~(0xFFU << shift)) |
                    ((uint32_t)ld8(ctx, ea + i) << shift);
            }
            if (have) {
                ctx->gpr[cur_reg] = cur;
            }
        } else {
            for (i = 0U; i < n; i++) {
                uint32_t reg = (insn.rs + i / 4U) & 31U;
                uint32_t shift = (3U - (i % 4U)) * 8U;

                st8(ctx, ea + i,
                    (uint8_t)((ctx->gpr[reg] >> shift) & 0xFFU));
            }
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- byte-reverse loads/stores: no swap (E05) --------------- */
    case PPC32_OP_LWBRX:
    case PPC32_OP_LHBRX:
    case PPC32_OP_STWBRX:
    case PPC32_OP_STHBRX: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            ctx->gpr[insn.rb];

        switch (insn.op) {
        case PPC32_OP_LWBRX:
            ctx->gpr[insn.rt] = ld32r(ctx, ea);
            break;
        case PPC32_OP_LHBRX:
            ctx->gpr[insn.rt] = ld16r(ctx, ea);
            break;
        case PPC32_OP_STWBRX:
            st32r(ctx, ea, ctx->gpr[insn.rs]);
            break;
        default:
            st16r(ctx, ea, (uint16_t)ctx->gpr[insn.rs]);
            break;
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- reservation ops (E06) ---------------------------------- */
    case PPC32_OP_LWARX: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            ctx->gpr[insn.rb];
        uint32_t al = ea & ~3U;

        if ((ea & 3U) != 0U) {
            fault(ctx, ea);
            break;
        }
        ctx->gpr[insn.rt] = ld32(ctx, ea);
        ctx->res_addr = al;
        ctx->res_val = ctx->gpr[insn.rt];
        ctx->res_valid = 1;
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_STWCX: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            ctx->gpr[insn.rb];
        bool ok = ctx->res_valid != 0U &&
            ctx->res_addr == (ea & ~3U);

        if ((ea & 3U) != 0U) {
            fault(ctx, ea);
            break;
        }
        if (ok) {
            st32(ctx, ea, ctx->gpr[insn.rs]);
        }
        ctx->res_valid = 0;
        ctx->reservation_epoch++;
        set_crf(ctx, 0U, false, false, ok);
        ctx->nip += 4U;
        break;
    }
    /* ---- traps -------------------------------------------------- */
    case PPC32_OP_TWI:
    case PPC32_OP_TW: {
        uint32_t to = (raw >> 21U) & 31U;
        bool hit;

        if (insn.op == PPC32_OP_TWI) {
            hit = trap_cond(to, ctx->gpr[insn.ra], (uint32_t)insn.si,
                false, 0, 0);
        } else {
            hit = trap_cond(to, ctx->gpr[insn.ra], ctx->gpr[insn.rb],
                false, 0, 0);
        }
        if (hit) {
            ctx->exit_reason = PPC32_EXIT_TRAP;
        } else {
            ctx->nip += 4U;
        }
        break;
    }
    /* ---- syscall ------------------------------------------------ */
    case PPC32_OP_SC:
        /* Leave nip AT the sc: ppc32_syscall_min advances past it on
         * return (its documented contract). Advancing here too would
         * skip the instruction after every syscall (RC1). */
        ctx->exit_reason = PPC32_EXIT_SYSCALL;
        res_invalidate(ctx);
        break;
    /* ---- memory-order / cache no-ops ---------------------------- */
    case PPC32_OP_SYNC:
    case PPC32_OP_DCBT:
        ctx->nip += 4U;
        break;
    case PPC32_OP_DCBZ: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            ctx->gpr[insn.rb];
        uint32_t base = ea & ~31U;
        uint32_t i;

        for (i = 0U; i < 32U; i++) {
            st8(ctx, base + i, 0U);
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- classic-FPU data moves + Phase 3 FP/SPE (interp/fp.c) ----- */
    case PPC32_OP_LFS:
    case PPC32_OP_LFSU:
    case PPC32_OP_LFD:
    case PPC32_OP_LFDU:
    case PPC32_OP_STFS:
    case PPC32_OP_STFSU:
    case PPC32_OP_STFD:
    case PPC32_OP_STFDU:
    case PPC32_OP_FPU_SINGLE:
    case PPC32_OP_FPU_DOUBLE:
    case PPC32_OP_FPU_X:
    case PPC32_OP_SPE:
        ppc32_fp_step(ctx, &insn);
        break;
    default:
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        break;
    }
}

/* ------------------------------------------------------------------ */
/* interp_run                                                         */
/* ------------------------------------------------------------------ */

void interp_run(ppc32_ctx_t *ctx)
{
    uint32_t start_page = ppc32_page_down(ctx->nip);
    uint32_t budget = PPC32_INTERP_BLOCK_BUDGET;

    while (ctx->exit_reason == PPC32_EXIT_NONE && budget > 0U) {
        interp_step(ctx);
        if (ctx->exit_reason != PPC32_EXIT_NONE) {
            return;
        }
        budget--;
        if (ppc32_page_down(ctx->nip) != start_page) {
            return;
        }
    }
}
