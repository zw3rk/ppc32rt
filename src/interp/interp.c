/*
 * src/interp/interp.c — Base integer reference interpreter (Phase 1 L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPEC 2.2 Book I integer ISA (FPU/SPE in Phase 3): ALU, CR/SPR ops,
 * branches, sc, string/multiple/update memops, lwarx/stwcx. (E06).
 * BE guest; unaligned access via memcpy; lmw/stmw/lwarx/stwcx. fault
 * on misaligned EA.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ppc32rt.h"
#include "interp/interp.h"
#include "interp/fp.h"
#include "vm/vm32.h"

/* lwarx/stwcx. lines (Wave U3 §4.4): SEQ_CST epoch + owner/addr/val snapshot (vm/vm32.h). */
typedef struct {
    uint64_t epoch;
    const ppc32_ctx_t *owner;
    uint32_t addr;
    uint32_t val;
} ppc32_ll_line_t;

static ppc32_ll_line_t g_ll_table[1024];
static _Atomic uint32_t g_ll_lock = 0U;
static _Thread_local int g_ll_lock_held = 0;

static void ll_lock_acquire(void)
{
    ppc32_spin_lock(&g_ll_lock);
    g_ll_lock_held = 1;
}

static void ll_lock_release(void)
{
    g_ll_lock_held = 0;
    ppc32_spin_unlock(&g_ll_lock);
}

void vm32_ll_unlock_if_held_by_self(void)
{
    if (g_ll_lock_held != 0) {
        g_ll_lock_held = 0;
        ppc32_spin_unlock(&g_ll_lock);
    }
}

/* Shared mapping generation (RC-U3-r2 #1): guest-mm teardowns bump it
 * via vm32_ll_note_remap, so a pre-teardown reservation can never
 * succeed after it (line epochs alone cannot see a remap). */
static uint64_t g_ll_generation;
void vm32_ll_note_remap(void) { __atomic_fetch_add(&g_ll_generation, 1ULL, __ATOMIC_SEQ_CST); }

void vm32_ll_record(ppc32_ctx_t *ctx, uint32_t gva_aligned, uint32_t val)
{
    uint32_t al = gva_aligned & ~3U;
    uint32_t h = (al >> 6U) & 1023U;

    ll_lock_acquire();
    ctx->res_addr = al;
    ctx->res_val = val;
    ctx->res_valid = 1;
    ctx->res_snap = __atomic_load_n(&g_ll_table[h].epoch, __ATOMIC_SEQ_CST);
    ctx->res_gensnap = __atomic_load_n(&g_ll_generation, __ATOMIC_SEQ_CST);
    g_ll_table[h].owner = ctx;
    g_ll_table[h].addr = al;
    g_ll_table[h].val = val;
    ll_lock_release();
}

/* STWCX. as one SEQ_CST compare-exchange (vm/vm32.h): shared mapping
 * generation + reservation_valid/addr gate the store; consumed either way. */
bool vm32_sc_attempt(ppc32_ctx_t *ctx, uint32_t gva_aligned, uint32_t val)
{
    uint32_t al = gva_aligned & ~3U;
    uint32_t h = (al >> 6U) & 1023U;
    uint32_t *hva = (uint32_t *)ppc32_guest_ptr(ctx, al);
    uint32_t exp = ppc32_be32(ctx->res_val);
    uint32_t des = ppc32_be32(val);
    bool pre_ok;
    bool ok = false;

    ll_lock_acquire();
    pre_ok = ctx->res_valid != 0U && ctx->res_addr == al && g_ll_table[h].owner == ctx &&
        g_ll_table[h].addr == al && g_ll_table[h].val == ctx->res_val &&
        __atomic_load_n(&g_ll_table[h].epoch, __ATOMIC_SEQ_CST) == ctx->res_snap &&
        __atomic_load_n(&g_ll_generation, __ATOMIC_SEQ_CST) == ctx->res_gensnap;
    ctx->res_valid = 0;
    if (g_ll_table[h].owner == ctx) {
        g_ll_table[h].owner = NULL;
    }
    ctx->reservation_epoch++;
    if (pre_ok) {
        ok = __atomic_compare_exchange_n(hva, &exp, des, false,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        if (ok) {
            __atomic_fetch_add(&g_ll_table[h].epoch, 1ULL, __ATOMIC_SEQ_CST);
        }
    }
    ll_lock_release();
    return ok;
}

/* Store hook: bump the line epoch so a peer stwcx. on the line fails. */
void vm32_reservation_bump(uint32_t gva_aligned)
{
    __atomic_fetch_add(&g_ll_table[((gva_aligned & ~3U) >> 6U) & 1023U].epoch, 1ULL,
        __ATOMIC_SEQ_CST);
}

/* Memory/branch/trap helpers live in interp.h; interp_step below. */

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
    if (!interp_mem_ok(ctx->nip, 4U)) { fault(ctx, ctx->nip); return; }
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
    case PPC32_OP_ADDZE: {
        int64_t swide;

        a = ctx->gpr[insn.ra];
        b = ctx->gpr[insn.rb];
        wide = (uint64_t)a + (uint64_t)b;
        swide = (int64_t)(int32_t)a + (int64_t)(int32_t)b;
        if (insn.op == PPC32_OP_ADDE) {
            uint32_t ca = (ctx->xer >> 29U) & 1U;
            wide += (uint64_t)ca;
            swide += (int64_t)ca;
        } else if (insn.op == PPC32_OP_ADDME) {
            uint32_t ca = (ctx->xer >> 29U) & 1U;
            wide = (uint64_t)a + (uint64_t)ca + 0xFFFFFFFFULL;
            swide = (int64_t)(int32_t)a + (int64_t)ca - 1LL;
        } else if (insn.op == PPC32_OP_ADDZE) {
            uint32_t ca = (ctx->xer >> 29U) & 1U;
            wide = (uint64_t)a + (uint64_t)ca;
            swide = (int64_t)(int32_t)a + (int64_t)ca;
        }
        r = (uint32_t)wide;
        ctx->gpr[insn.rt] = r;
        if (insn.op != PPC32_OP_ADD) {
            xer_set_ca(ctx, (wide >> 32U) != 0U);
        }
        if (insn.oe != 0U) {
            ov = (swide < -2147483648LL) || (swide > 2147483647LL);
            xer_set_ov(ctx, ov);
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_SUBF:
    case PPC32_OP_SUBFC:
    case PPC32_OP_SUBFE:
    case PPC32_OP_SUBFME:
    case PPC32_OP_SUBFZE: {
        int64_t swide;
        uint32_t ca = (ctx->xer >> 29U) & 1U;

        a = ctx->gpr[insn.ra];
        b = ctx->gpr[insn.rb];
        if (insn.op == PPC32_OP_SUBFME) {
            wide = (uint64_t)(~a) + (uint64_t)ca + 0xFFFFFFFFULL;
            swide = (int64_t)(int32_t)(~a) + (int64_t)ca - 1LL;
        } else if (insn.op == PPC32_OP_SUBFZE) {
            wide = (uint64_t)(~a) + (uint64_t)ca;
            swide = (int64_t)(int32_t)(~a) + (int64_t)ca;
        } else {
            wide = (uint64_t)(~a) + (uint64_t)b + 1ULL;
            swide = (int64_t)(int32_t)b - (int64_t)(int32_t)a;
            if (insn.op == PPC32_OP_SUBFE) {
                wide += (uint64_t)ca - 1ULL;
                swide = (int64_t)(int32_t)(~a) + (int64_t)(int32_t)b + (int64_t)ca;
            }
        }
        r = (uint32_t)wide;
        ctx->gpr[insn.rt] = r;
        if (insn.op != PPC32_OP_SUBF) {
            xer_set_ca(ctx, (wide >> 32U) != 0U);
        }
        if (insn.oe != 0U) {
            ov = (swide < -2147483648LL) || (swide > 2147483647LL);
            xer_set_ov(ctx, ov);
        }
        if (insn.rc != 0U) {
            set_cr0(ctx, r);
        }
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_NEG:
        a = ctx->gpr[insn.ra];
        r = (uint32_t)(0U - a);
        ctx->gpr[insn.rt] = r;
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
            bool div_ov = (ctx->gpr[insn.rb] == 0U) ||
                (insn.op == PPC32_OP_DIVW &&
                 sa == (int32_t)0x80000000U && sb == -1);
            xer_set_ov(ctx, div_ov);
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
    /* ---- CR / SPR ops ------------------------------------------ */
    case PPC32_OP_CR:
    case PPC32_OP_MCRF:
    case PPC32_OP_MCRXR:
    case PPC32_OP_MFCR:
    case PPC32_OP_MTCRF:
    case PPC32_OP_MFSPR:
    case PPC32_OP_MTSPR:
        interp_exec_cr_spr(ctx, &insn, raw);
        break;
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
        if (!interp_mem_ok(ea, (32U - rt) * 4U)) { fault(ctx, ea); break; }
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

        if (!interp_mem_ok(ea, n)) { fault(ctx, ea); break; }
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
            if (!interp_mem_ok(ea, 4U)) { fault(ctx, ea); break; }
            ctx->gpr[insn.rt] = ld32r(ctx, ea);
            break;
        case PPC32_OP_LHBRX:
            if (!interp_mem_ok(ea, 2U)) { fault(ctx, ea); break; }
            ctx->gpr[insn.rt] = ld16r(ctx, ea);
            break;
        case PPC32_OP_STWBRX:
            if (!interp_mem_ok(ea, 4U)) { fault(ctx, ea); break; }
            st32r(ctx, ea, ctx->gpr[insn.rs]);
            break;
        default:
            if (!interp_mem_ok(ea, 2U)) { fault(ctx, ea); break; }
            st16r(ctx, ea, (uint16_t)ctx->gpr[insn.rs]);
            break;
        }
        ctx->nip += 4U;
        break;
    }
    /* ---- reservation ops (E06): SEQ_CST LL/SC over g_ll_table ---- */
    case PPC32_OP_LWARX: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) + ctx->gpr[insn.rb];
        uint32_t al = ea & ~3U;
        uint32_t *hva;
        uint32_t val;

        if (((ea & 3U) != 0U) || !interp_mem_ok(ea, 4U)) { fault(ctx, ea); break; }
        ppc32_vm_lock();
        hva = (uint32_t *)ppc32_access_checked(ctx, al, 4U, false);
        if (hva == NULL) { ppc32_vm_unlock(); break; }
        val = ppc32_be32(__atomic_load_n(hva, __ATOMIC_SEQ_CST));
        ctx->gpr[insn.rt] = val;
        vm32_ll_record(ctx, al, val);
        ppc32_vm_unlock();
        ctx->nip += 4U;
        break;
    }
    case PPC32_OP_STWCX: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) + ctx->gpr[insn.rb];
        uint32_t al = ea & ~3U;
        bool ok;

        if (((ea & 3U) != 0U) || !interp_mem_ok(ea, 4U)) { fault(ctx, ea); break; }
        ppc32_vm_lock();
        if (ppc32_access_checked(ctx, al, 4U, true) == NULL) { ppc32_vm_unlock(); break; }
        ok = vm32_sc_attempt(ctx, al, ctx->gpr[insn.rs]);
        ppc32_vm_unlock();
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
        /* Leave nip AT the sc (E01 contract); advancing here too would skip
          * the instruction after every syscall (RC1). */
        ctx->exit_reason = PPC32_EXIT_SYSCALL;
        res_invalidate(ctx);
        break;
    /* ---- memory-order / cache ops ------------------------------- */
    case PPC32_OP_SYNC:
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        ctx->nip += 4U;
        break;
    case PPC32_OP_DCBT:
        ctx->nip += 4U;
        break;
    case PPC32_OP_DCBZ: {
        uint32_t ea = (insn.ra == 0U ? 0U : ctx->gpr[insn.ra]) +
            ctx->gpr[insn.rb];
        uint32_t base = ea & ~31U;
        uint32_t i;

        if (!interp_mem_ok(ea, 32U)) { fault(ctx, ea); break; }
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

/* interp_run */

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
