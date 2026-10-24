/*
 * src/interp/interp.h — Base integer reference interpreter API (Phase 1 L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The interpreter is the correctness oracle: interp_step executes exactly
 * one guest instruction at ctx->nip; interp_run executes a bounded block
 * until a terminal exit, a page-boundary block end, or a step budget.
 *
 * Consumes the L1a decoder API (src/interp/decode.h, owned by lane L1a):
 *   typedef struct { uint32_t raw, op, xo; uint8_t rt, ra, rb, rs, bo, bi,
 *     oe, rc; int32_t d, si; uint32_t ui, li, bd; } ppc32_insn_t;
 *   int ppc_decode(uint32_t raw, ppc32_insn_t *out);
 * with opcode ids PPC32_OP_* (PPC32_OP_UNDEF for unknown words). Fields
 * with L1a semantics: d/SI are sign-extended; ui is zero-extended; li/bd
 * are sign-extended branch displacements (already shifted, i.e. the final
 * signed byte offset); xo is the 10-bit XO field; oe/rc are 0/1.
 */

#ifndef PPC32RT_INTERP_INTERP_H
#define PPC32RT_INTERP_INTERP_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ppc32rt.h"
#include "interp/decode.h"

/* Bounded block length for interp_run (SPEC section 3: DBT translates up
 * to 64 guest instructions per block; the interpreter chunk matches it so
 * --difftest compares equal-length blocks). */
#define PPC32_INTERP_BLOCK_BUDGET 64U

/* Execute exactly one guest instruction at ctx->nip (SPEC section 2.2).
 * Advances nip by 4 (no delay slots on PPC) or to a taken branch target.
 * Terminal instructions set ctx->exit_reason (SYSCALL/UNDEF/FAULT/TRAP);
 * sc also advances nip past itself and clears the lwarx reservation.
 * Unknown words set PPC32_EXIT_UNDEF and leave nip at the faulting word. */
void interp_step(ppc32_ctx_t *ctx);

/* Execute guest code from ctx->nip until ctx->exit_reason != NONE, or the
 * next nip crosses a guest page boundary (block end), or the block budget
 * above is exhausted. Page/block-budget stops return with exit_reason
 * unchanged (NONE: caller re-invokes to continue). */
void interp_run(ppc32_ctx_t *ctx);


/* Internal static-inline helpers shared with interp.c.
 * All guest memory access goes through the BE ld/st helpers;
 * lmw/stmw/lwarx/stwcx. require word-aligned EA (fault() else).
 * Kept in the header so the Phase-2 DBT can reuse the exact
 * same semantics during --difftest bring-up. */

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static inline uint32_t rotl32(uint32_t v, uint32_t n)
{
    n &= 31U;
    if (n == 0U) {
        return v;
    }
    return (v << n) | (v >> (32U - n));
}

/* Rotate/mask helper with MB>ME wrap (E02): MB<=ME selects [MB,ME];
 * MB>ME selects [MB,31]+[0,ME]. */
static inline uint32_t ppc_mask32(uint32_t mb, uint32_t me)
{
    uint32_t ml;
    uint32_t mh;
    uint32_t x;

    mb &= 31U;
    me &= 31U;
    ml = 0xFFFFFFFFU >> mb;
    mh = (me == 31U) ? 0U : (0xFFFFFFFFU >> (me + 1U));
    x = ml ^ mh;
    if (mb <= me) {
        return x;
    }
    return ~x;
}

static inline uint32_t cr_bit(const ppc32_ctx_t *ctx, uint32_t bi)
{
    return (ctx->cr >> (31U - (bi & 31U))) & 1U;
}

/* CR0 = [LT,GT,EQ from signed result, SO copied live from XER.SO]. */
static inline void set_cr0(ppc32_ctx_t *ctx, uint32_t result)
{
    uint32_t cr0;

    if ((int32_t)result < 0) {
        cr0 = 0x80000000U;
    } else if (result != 0U) {
        cr0 = 0x40000000U;
    } else {
        cr0 = 0x20000000U;
    }
    if ((ctx->xer & 0x80000000U) != 0U) {
        cr0 |= 0x10000000U;
    }
    ctx->cr = (ctx->cr & 0x0FFFFFFFU) | cr0;
}

/* CR field bf = [LT,GT,EQ,SO<-XER.SO] (cmp/cmpl/mcrf/stwcx. shape). */
static inline void set_crf(ppc32_ctx_t *ctx, uint32_t bf, bool lt, bool gt, bool eq)
{
    uint32_t shift = (7U - (bf & 7U)) * 4U;
    uint32_t v = 0U;

    if (lt) {
        v |= 8U;
    }
    if (gt) {
        v |= 4U;
    }
    if (eq) {
        v |= 2U;
    }
    v |= (ctx->xer >> 31U) & 1U;
    ctx->cr = (ctx->cr & ~(0xFU << shift)) | (v << shift);
}

static inline void xer_set_ca(ppc32_ctx_t *ctx, bool ca)
{
    if (ca) {
        ctx->xer |= 0x20000000U;
    } else {
        ctx->xer &= ~0x20000000U;
    }
}

/* OE=1 overflow accounting: OV set/cleared, SO sticky-set on overflow. */
static inline void xer_set_ov(ppc32_ctx_t *ctx, bool ov)
{
    if (ov) {
        ctx->xer |= 0xC0000000U;
    } else {
        ctx->xer &= ~0x40000000U;
    }
}

static inline uint32_t add_overflow(uint32_t a, uint32_t b, uint32_t r)
{
    return (((a ^ r) & (b ^ r)) >> 31U) & 1U;
}

static inline uint32_t sub_overflow(uint32_t a, uint32_t b, uint32_t r)
{
    return (((a ^ r) & (a ^ b)) >> 31U) & 1U;
}

/* Invalidate the lwarx reservation (E06: syscall/fault entry, helpers,
 * signals, thread switches all clear it; spurious failure is legal). */
static inline void res_invalidate(ppc32_ctx_t *ctx)
{
    ctx->res_valid = 0;
    ctx->reservation_epoch++;
}

/* ------------------------------------------------------------------ */
/* Guest memory (big-endian; unaligned byte/half/word access is OK)   */
/* ------------------------------------------------------------------ */

static inline uint8_t ld8(const ppc32_ctx_t *ctx, uint32_t ea)
{
    uint8_t v = 0;

    memcpy(&v, ppc32_guest_ptr(ctx, ea), 1);
    return v;
}

static inline uint16_t ld16(const ppc32_ctx_t *ctx, uint32_t ea)
{
    uint16_t r = 0;

    memcpy(&r, ppc32_guest_ptr(ctx, ea), sizeof(r));
    return ppc32_be16(r);
}

static inline uint16_t ld16r(const ppc32_ctx_t *ctx, uint32_t ea)
{
    uint16_t r = 0;

    memcpy(&r, ppc32_guest_ptr(ctx, ea), sizeof(r));
    return r;
}

static inline uint32_t ld32(const ppc32_ctx_t *ctx, uint32_t ea)
{
    uint32_t r = 0;

    memcpy(&r, ppc32_guest_ptr(ctx, ea), sizeof(r));
    return ppc32_be32(r);
}

static inline uint32_t ld32r(const ppc32_ctx_t *ctx, uint32_t ea)
{
    uint32_t r = 0;

    memcpy(&r, ppc32_guest_ptr(ctx, ea), sizeof(r));
    return r;
}

static inline void st8(const ppc32_ctx_t *ctx, uint32_t ea, uint8_t v)
{
    memcpy(ppc32_guest_ptr(ctx, ea), &v, 1);
}

static inline void st16(const ppc32_ctx_t *ctx, uint32_t ea, uint16_t v)
{
    uint16_t r = ppc32_be16(v);

    memcpy(ppc32_guest_ptr(ctx, ea), &r, sizeof(r));
}

static inline void st16r(const ppc32_ctx_t *ctx, uint32_t ea, uint16_t v)
{
    memcpy(ppc32_guest_ptr(ctx, ea), &v, sizeof(v));
}

static inline void st32(const ppc32_ctx_t *ctx, uint32_t ea, uint32_t v)
{
    uint32_t r = ppc32_be32(v);

    memcpy(ppc32_guest_ptr(ctx, ea), &r, sizeof(r));
}

static inline void st32r(const ppc32_ctx_t *ctx, uint32_t ea, uint32_t v)
{
    memcpy(ppc32_guest_ptr(ctx, ea), &v, sizeof(v));
}

static inline uint32_t fetch_raw(const ppc32_ctx_t *ctx)
{
    return ld32(ctx, ctx->nip);
}

/* ------------------------------------------------------------------ */
/* Branches (BO/BI/LK; no delay slots on PPC)                        */
/* ------------------------------------------------------------------ */

static inline bool branch_cond(ppc32_ctx_t *ctx, uint8_t bo, uint8_t bi)
{
    bool ctr_ok;
    bool cond_ok;

    if ((bo & 4U) == 0U) {
        ctx->ctr--;
    }
    ctr_ok = ((bo & 4U) != 0U) || ((ctx->ctr == 0U) == ((bo & 2U) != 0U));
    if ((bo & 16U) != 0U) {
        cond_ok = true;
    } else {
        cond_ok = cr_bit(ctx, bi) == (((bo & 8U) != 0U) ? 1U : 0U);
    }
    return ctr_ok && cond_ok;
}

static inline void branch_to(ppc32_ctx_t *ctx, uint32_t target, uint8_t lk)
{
    if (lk != 0U) {
        ctx->lr = ctx->nip + 4U;
    }
    ctx->nip = target & ~3U;
}

/* TO-bit trap test (tw/twi 32-bit; td/tdi use 64-bit sign-extended). */
static inline bool trap_cond(uint32_t to, uint32_t a, uint32_t b, bool is64,
    int64_t a64, int64_t b64)
{
    if (!is64) {
        if (((to & 16U) != 0U) && ((int32_t)a < (int32_t)b)) {
            return true;
        }
        if (((to & 8U) != 0U) && ((int32_t)a > (int32_t)b)) {
            return true;
        }
        if (((to & 4U) != 0U) && (a == b)) {
            return true;
        }
        if (((to & 2U) != 0U) && (a < b)) {
            return true;
        }
        if (((to & 1U) != 0U) && (a > b)) {
            return true;
        }
        return false;
    }
    if (((to & 16U) != 0U) && (a64 < b64)) {
        return true;
    }
    if (((to & 8U) != 0U) && (a64 > b64)) {
        return true;
    }
    if (((to & 4U) != 0U) && (a64 == b64)) {
        return true;
    }
    if (((to & 2U) != 0U) && ((uint64_t)a64 < (uint64_t)b64)) {
        return true;
    }
    if (((to & 1U) != 0U) && ((uint64_t)a64 > (uint64_t)b64)) {
        return true;
    }
    return false;
}

/* Fault helper: records fault_addr, clears the reservation, stops. */
static inline void fault(ppc32_ctx_t *ctx, uint32_t ea)
{
    ctx->fault_addr = ea;
    ctx->exit_reason = PPC32_EXIT_FAULT;
    res_invalidate(ctx);
}

static inline void interp_exec_dform_mem(ppc32_ctx_t *ctx,
    const ppc32_insn_t *insn)
{
    uint32_t ea;

    if (insn->ra == 0U) {
        if (insn->op == PPC32_OP_LBZU || insn->op == PPC32_OP_LHZU ||
            insn->op == PPC32_OP_LHAU || insn->op == PPC32_OP_LWZU ||
            insn->op == PPC32_OP_STBU || insn->op == PPC32_OP_STHU ||
            insn->op == PPC32_OP_STWU) {
            ctx->exit_reason = PPC32_EXIT_UNDEF;
            return;
        }
        ea = (uint32_t)insn->d;
    } else {
        ea = ctx->gpr[insn->ra] + (uint32_t)insn->d;
    }
    switch (insn->op) {
    case PPC32_OP_LBZ:
    case PPC32_OP_LBZU:
        ctx->gpr[insn->rt] = ld8(ctx, ea);
        break;
    case PPC32_OP_LHZ:
    case PPC32_OP_LHZU:
        ctx->gpr[insn->rt] = ld16(ctx, ea);
        break;
    case PPC32_OP_LHA:
    case PPC32_OP_LHAU:
        ctx->gpr[insn->rt] =
            (uint32_t)(int32_t)(int16_t)ld16(ctx, ea);
        break;
    case PPC32_OP_LWZ:
    case PPC32_OP_LWZU:
        ctx->gpr[insn->rt] = ld32(ctx, ea);
        break;
    case PPC32_OP_STB:
    case PPC32_OP_STBU:
        st8(ctx, ea, (uint8_t)ctx->gpr[insn->rs]);
        break;
    case PPC32_OP_STH:
    case PPC32_OP_STHU:
        st16(ctx, ea, (uint16_t)ctx->gpr[insn->rs]);
        break;
    default:
        st32(ctx, ea, ctx->gpr[insn->rs]);
        break;
    }
    if (insn->ra != 0U) {
        switch (insn->op) {
        case PPC32_OP_LBZU:
        case PPC32_OP_LHZU:
        case PPC32_OP_LHAU:
        case PPC32_OP_LWZU:
            ctx->gpr[insn->ra] = ea;
            break;
        case PPC32_OP_STBU:
        case PPC32_OP_STHU:
        case PPC32_OP_STWU:
            ctx->gpr[insn->ra] = ea;
            break;
        default:
            break;
        }
    }
    ctx->nip += 4U;
}

static inline void interp_exec_xform_mem(ppc32_ctx_t *ctx,
    const ppc32_insn_t *insn)
{
    uint32_t ea = (insn->ra == 0U ? 0U : ctx->gpr[insn->ra]) +
        ctx->gpr[insn->rb];

    if (insn->ra != 0U) {
        switch (insn->op) {
        case PPC32_OP_LBZUX:
        case PPC32_OP_LHZUX:
        case PPC32_OP_LHAUX:
        case PPC32_OP_LWZUX:
        case PPC32_OP_STBUX:
        case PPC32_OP_STHUX:
        case PPC32_OP_STWUX:
            ctx->gpr[insn->ra] = ea;
            break;
        default:
            break;
        }
    } else if (insn->op == PPC32_OP_LBZUX ||
        insn->op == PPC32_OP_LHZUX || insn->op == PPC32_OP_LHAUX ||
        insn->op == PPC32_OP_LWZUX) {
        ctx->exit_reason = PPC32_EXIT_UNDEF;
        return;
    }
    switch (insn->op) {
    case PPC32_OP_LBZX:
    case PPC32_OP_LBZUX:
        ctx->gpr[insn->rt] = ld8(ctx, ea);
        break;
    case PPC32_OP_LHZX:
    case PPC32_OP_LHZUX:
        ctx->gpr[insn->rt] = ld16(ctx, ea);
        break;
    case PPC32_OP_LHAX:
    case PPC32_OP_LHAUX:
        ctx->gpr[insn->rt] =
            (uint32_t)(int32_t)(int16_t)ld16(ctx, ea);
        break;
    case PPC32_OP_LWZX:
    case PPC32_OP_LWZUX:
        ctx->gpr[insn->rt] = ld32(ctx, ea);
        break;
    case PPC32_OP_STBX:
    case PPC32_OP_STBUX:
        st8(ctx, ea, (uint8_t)ctx->gpr[insn->rs]);
        break;
    case PPC32_OP_STHX:
    case PPC32_OP_STHUX:
        st16(ctx, ea, (uint16_t)ctx->gpr[insn->rs]);
        break;
    default:
        st32(ctx, ea, ctx->gpr[insn->rs]);
        break;
    }
    ctx->nip += 4U;
}

#endif /* PPC32RT_INTERP_INTERP_H */
