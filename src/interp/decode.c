/*
 * src/interp/decode.c — PowerPC Book I instruction decoder (Phase 1, lane L1a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single-pass primary-opcode switch; XO dispatch for primaries 19 and
 * 31. XO values follow Power ISA Book I and are cross-checked against
 * experiments/E02 (rotates/shifts, addc/addze/subfc/subfze), E03 (SPE
 * major opcode 4, classic FPU primaries), E05 (string/byte-reverse XOs)
 * and E06 (lwarx/stwcx., sc) FINDINGS.md vectors.
 */

#include "interp/decode.h"

#include "ppc32rt.h"

/* Bit-field positions (PowerPC numbering: bit 0 = MSB). */
#define PPC32_OP_SHIFT 26u

/* Primary 19 (XL) XO values. */
#define PPC32_XL_MCRF 0u
#define PPC32_XL_BCLR 16u
#define PPC32_XL_ISYNC 150u
#define PPC32_XL_CRAND 257u
#define PPC32_XL_CRANDC 129u
#define PPC32_XL_CREQV 289u
#define PPC32_XL_CRNAND 225u
#define PPC32_XL_CRNOR 33u
#define PPC32_XL_CROR 449u
#define PPC32_XL_CRORC 417u
#define PPC32_XL_CRXOR 193u
#define PPC32_XL_BCCTR 528u

static void ppc_decode_dform(uint32_t raw, uint32_t op, ppc32_insn_t *out)
{
    uint32_t u = raw & 0xffffu;

    out->op = op;
    out->rt = (uint8_t)((raw >> 21u) & 31u);
    out->rs = out->rt;
    out->ra = (uint8_t)((raw >> 16u) & 31u);
    out->si = (int32_t)(int16_t)u;
    out->d = out->si;
    out->ui = u;
}

int ppc_decode(uint32_t raw, ppc32_insn_t *out)
{
    uint32_t po;
    uint32_t rb;
    uint32_t xo;

    if (out == 0) {
        return -1;
    }
    out->raw = raw;
    out->op = (uint32_t)PPC32_OP_UNDEF;
    out->xo = 0;
    out->rt = 0;
    out->ra = 0;
    out->rb = 0;
    out->rs = 0;
    out->bo = 0;
    out->bi = 0;
    out->oe = 0;
    out->rc = 0;
    out->d = 0;
    out->si = 0;
    out->ui = 0;
    out->li = 0;
    out->bd = 0;

    /* The only primary-17 user instruction is `sc 0` (E01). */
    if (raw == (uint32_t)PPC32_INSN_SC) {
        out->op = (uint32_t)PPC32_OP_SC;
        return 0;
    }

    po = raw >> PPC32_OP_SHIFT;
    switch (po) {
    case 3u: /* twi */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_TWI, out);
        return 0;
    case 4u: /* e500v2 SPE: full 11-bit XO incl. Rc slot (E03) */
        out->op = (uint32_t)PPC32_OP_SPE;
        out->rt = (uint8_t)((raw >> 21u) & 31u);
        out->rs = out->rt;
        out->ra = (uint8_t)((raw >> 16u) & 31u);
        out->rb = (uint8_t)((raw >> 11u) & 31u);
        out->xo = raw & 0x7ffu;
        out->rc = (uint8_t)(raw & 1u);
        out->si = (int32_t)(int16_t)(raw & 0xffffu);
        out->d = out->si;
        out->ui = raw & 0xffffu;
        return 0;
    case 7u: /* mulli */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_MULLI, out);
        return 0;
    case 8u: /* subfic */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_SUBFIC, out);
        return 0;
    case 10u: /* cmpli */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_CMPLI, out);
        return 0;
    case 11u: /* cmpi */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_CMPI, out);
        return 0;
    case 12u: /* addic */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ADDIC, out);
        return 0;
    case 13u: /* addic. */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ADDIC_DOT, out);
        return 0;
    case 14u: /* addi */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ADDI, out);
        return 0;
    case 15u: /* addis */
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ADDIS, out);
        return 0;
    case 16u: /* bc: BO, BI, 14-bit BD, AA, LK */
        out->op = (uint32_t)PPC32_OP_BC;
        out->bo = (uint8_t)((raw >> 21u) & 31u);
        out->bi = (uint8_t)((raw >> 16u) & 31u);
        out->bd = (raw >> 2u) & 0x3fffu;
        out->oe = (uint8_t)((raw >> 1u) & 1u);
        out->rc = (uint8_t)(raw & 1u);
        return 0;
    case 17u: /* only `sc 0` is valid here; handled above */
        return -1;
    case 18u: /* b: 24-bit LI, AA, LK */
        out->op = (uint32_t)PPC32_OP_B;
        out->li = raw & 0x03fffffcu;
        out->oe = (uint8_t)((raw >> 1u) & 1u);
        out->rc = (uint8_t)(raw & 1u);
        return 0;
    case 19u: /* XL-form: BO, BI, BH-in-RB, 10-bit XO, LK */
        out->rt = (uint8_t)((raw >> 21u) & 31u);
        out->rs = out->rt;
        out->ra = (uint8_t)((raw >> 16u) & 31u);
        out->rb = (uint8_t)((raw >> 11u) & 31u);
        out->bo = out->rt;
        out->bi = out->ra;
        xo = (raw >> 1u) & 0x3ffu;
        out->xo = xo;
        out->rc = (uint8_t)(raw & 1u);
        switch (xo) {
        case PPC32_XL_MCRF:
            out->op = (uint32_t)PPC32_OP_MCRF;
            return 0;
        case PPC32_XL_BCLR:
            out->op = (uint32_t)PPC32_OP_BCLR;
            return 0;
        case PPC32_XL_BCCTR:
            out->op = (uint32_t)PPC32_OP_BCCTR;
            return 0;
        case PPC32_XL_ISYNC:
            out->op = (uint32_t)PPC32_OP_SYNC;
            return 0;
        case PPC32_XL_CRAND:
        case PPC32_XL_CRANDC:
        case PPC32_XL_CREQV:
        case PPC32_XL_CRNAND:
        case PPC32_XL_CRNOR:
        case PPC32_XL_CROR:
        case PPC32_XL_CRORC:
        case PPC32_XL_CRXOR:
            out->op = (uint32_t)PPC32_OP_CR;
            return 0;
        default:
            out->op = (uint32_t)PPC32_OP_UNDEF;
            return -1;
        }
    case 20u: /* rlwimi */
    case 21u: /* rlwinm */
    case 23u: /* rlwnm */
        out->rt = (uint8_t)((raw >> 21u) & 31u);
        out->rs = out->rt;
        out->ra = (uint8_t)((raw >> 16u) & 31u);
        out->rb = (uint8_t)((raw >> 11u) & 31u);
        out->bo = (uint8_t)((raw >> 6u) & 31u);
        out->bi = (uint8_t)((raw >> 1u) & 31u);
        out->rc = (uint8_t)(raw & 1u);
        if (po == 20u) {
            out->op = (uint32_t)PPC32_OP_RLWIMI;
        } else if (po == 21u) {
            out->op = (uint32_t)PPC32_OP_RLWINM;
        } else {
            out->op = (uint32_t)PPC32_OP_RLWNM;
        }
        return 0;
    case 24u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ORI, out);
        return 0;
    case 25u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ORIS, out);
        return 0;
    case 26u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_XORI, out);
        return 0;
    case 27u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_XORIS, out);
        return 0;
    case 28u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ANDI, out);
        return 0;
    case 29u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_ANDIS, out);
        return 0;
    case 30u: /* rld*: 64-bit only */
        return -1;
    case 31u: /* X-form */
        break;
    case 32u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LWZ, out);
        return 0;
    case 33u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LWZU, out);
        return 0;
    case 34u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LBZ, out);
        return 0;
    case 35u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LBZU, out);
        return 0;
    case 36u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STW, out);
        return 0;
    case 37u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STWU, out);
        return 0;
    case 38u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STB, out);
        return 0;
    case 39u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STBU, out);
        return 0;
    case 40u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LHZ, out);
        return 0;
    case 41u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LHZU, out);
        return 0;
    case 42u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LHA, out);
        return 0;
    case 43u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LHAU, out);
        return 0;
    case 44u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STH, out);
        return 0;
    case 45u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STHU, out);
        return 0;
    case 46u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LMW, out);
        return 0;
    case 47u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STMW, out);
        return 0;
    case 48u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LFS, out);
        return 0;
    case 49u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LFSU, out);
        return 0;
    case 50u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LFD, out);
        return 0;
    case 51u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_LFDU, out);
        return 0;
    case 52u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STFS, out);
        return 0;
    case 53u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STFSU, out);
        return 0;
    case 54u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STFD, out);
        return 0;
    case 55u:
        ppc_decode_dform(raw, (uint32_t)PPC32_OP_STFDU, out);
        return 0;
    case 59u: /* single-precision A-form (fields only) */
        out->op = (uint32_t)PPC32_OP_FPU_SINGLE;
        out->rt = (uint8_t)((raw >> 21u) & 31u);
        out->rs = out->rt;
        out->ra = (uint8_t)((raw >> 16u) & 31u);
        out->rb = (uint8_t)((raw >> 11u) & 31u);
        out->bi = (uint8_t)((raw >> 6u) & 31u);
        out->xo = (raw >> 1u) & 31u;
        out->rc = (uint8_t)(raw & 1u);
        return 0;
    case 63u: /* double-precision A/X-form (fields only) */
        out->op = (uint32_t)PPC32_OP_FPU_DOUBLE;
        out->rt = (uint8_t)((raw >> 21u) & 31u);
        out->rs = out->rt;
        out->ra = (uint8_t)((raw >> 16u) & 31u);
        out->rb = (uint8_t)((raw >> 11u) & 31u);
        out->bi = (uint8_t)((raw >> 6u) & 31u);
        out->oe = (uint8_t)((raw >> 10u) & 1u);
        out->xo = (raw >> 1u) & 0x3ffu;
        out->rc = (uint8_t)(raw & 1u);
        return 0;
    default:
        return -1;
    }

    /* Primary 31 X-form: RT/RS, RA, RB, OE (bit 21), 10-bit XO, Rc. */
    rb = (raw >> 11u) & 31u;
    xo = (raw >> 1u) & 0x3ffu;
    out->rt = (uint8_t)((raw >> 21u) & 31u);
    out->rs = out->rt;
    out->ra = (uint8_t)((raw >> 16u) & 31u);
    out->rb = (uint8_t)rb;
    out->oe = (uint8_t)((raw >> 10u) & 1u);
    out->xo = xo;
    out->rc = (uint8_t)(raw & 1u);
    switch (xo) {
    case 0u:
        out->op = (uint32_t)PPC32_OP_CMP;
        return 0;
    case 4u:
        out->op = (uint32_t)PPC32_OP_TW;
        return 0;
    case 8u:
        out->op = (uint32_t)PPC32_OP_SUBFC;
        return 0;
    case 9u:
        out->op = (uint32_t)PPC32_OP_MULHDU;
        return 0;
    case 10u:
        out->op = (uint32_t)PPC32_OP_ADDC;
        return 0;
    case 11u:
        out->op = (uint32_t)PPC32_OP_MULHWU;
        return 0;
    case 19u:
        out->op = (uint32_t)PPC32_OP_MFCR;
        return 0;
    case 20u:
        out->op = (uint32_t)PPC32_OP_LWARX;
        return 0;
    case 23u:
        out->op = (uint32_t)PPC32_OP_LWZX;
        return 0;
    case 24u:
        out->op = (uint32_t)PPC32_OP_SLW;
        return 0;
    case 26u:
        out->op = (uint32_t)PPC32_OP_CNTLZW;
        return 0;
    case 28u:
        out->op = (uint32_t)PPC32_OP_AND;
        return 0;
    case 32u:
        out->op = (uint32_t)PPC32_OP_CMPL;
        return 0;
    case 40u:
        out->op = (uint32_t)PPC32_OP_SUBF;
        return 0;
    case 55u:
        out->op = (uint32_t)PPC32_OP_LWZUX;
        return 0;
    case 60u:
        out->op = (uint32_t)PPC32_OP_ANDC;
        return 0;
    case 75u:
        out->op = (uint32_t)PPC32_OP_MULHW;
        return 0;
    case 87u:
        out->op = (uint32_t)PPC32_OP_LBZX;
        return 0;
    case 104u:
        out->op = (uint32_t)PPC32_OP_NEG;
        return 0;
    case 119u:
        out->op = (uint32_t)PPC32_OP_LBZUX;
        return 0;
    case 124u:
        out->op = (uint32_t)PPC32_OP_NOR;
        return 0;
    case 136u:
        out->op = (uint32_t)PPC32_OP_SUBFE;
        return 0;
    case 138u:
        out->op = (uint32_t)PPC32_OP_ADDE;
        return 0;
    case 144u: /* mtcrf: FXM mask (bits 12-19) rides in ui */
        out->op = (uint32_t)PPC32_OP_MTCRF;
        out->ui = (raw >> 12u) & 0xffu;
        return 0;
    case 150u:
        out->op = (uint32_t)PPC32_OP_STWCX;
        return 0;
    case 151u:
        out->op = (uint32_t)PPC32_OP_STWX;
        return 0;
    case 183u:
        out->op = (uint32_t)PPC32_OP_STWUX;
        return 0;
    case 200u:
        out->op = (uint32_t)PPC32_OP_SUBFZE;
        return 0;
    case 202u:
        out->op = (uint32_t)PPC32_OP_ADDZE;
        return 0;
    case 215u:
        out->op = (uint32_t)PPC32_OP_STBX;
        return 0;
    case 232u:
        out->op = (uint32_t)PPC32_OP_SUBFME;
        return 0;
    case 234u:
        out->op = (uint32_t)PPC32_OP_ADDME;
        return 0;
    case 235u:
        out->op = (uint32_t)PPC32_OP_MULLW;
        return 0;
    case 246u: /* dcbtst (ANALYTICAL XO): cache-hint nop */
    case 278u: /* dcbt (ANALYTICAL XO): cache-hint nop */
        out->op = (uint32_t)PPC32_OP_DCBT;
        return 0;
    case 247u:
        out->op = (uint32_t)PPC32_OP_STBUX;
        return 0;
    case 266u:
        out->op = (uint32_t)PPC32_OP_ADD;
        return 0;
    case 279u:
        out->op = (uint32_t)PPC32_OP_LHZX;
        return 0;
    case 284u:
        out->op = (uint32_t)PPC32_OP_EQV;
        return 0;
    case 311u:
        out->op = (uint32_t)PPC32_OP_LHZUX;
        return 0;
    case 316u:
        out->op = (uint32_t)PPC32_OP_XOR;
        return 0;
    case 339u: /* mfspr: 10-bit SPR number rides in ui */
        out->op = (uint32_t)PPC32_OP_MFSPR;
        out->ui = (((raw >> 16u) & 31u) << 5u) | rb;
        return 0;
    case 343u:
        out->op = (uint32_t)PPC32_OP_LHAX;
        return 0;
    case 375u:
        out->op = (uint32_t)PPC32_OP_LHAUX;
        return 0;
    case 407u:
        out->op = (uint32_t)PPC32_OP_STHX;
        return 0;
    case 412u:
        out->op = (uint32_t)PPC32_OP_ORC;
        return 0;
    case 439u:
        out->op = (uint32_t)PPC32_OP_STHUX;
        return 0;
    case 444u:
        out->op = (uint32_t)PPC32_OP_OR;
        return 0;
    case 459u:
        out->op = (uint32_t)PPC32_OP_DIVWU;
        return 0;
    case 467u: /* mtspr: 10-bit SPR number rides in ui */
        out->op = (uint32_t)PPC32_OP_MTSPR;
        out->ui = (((raw >> 16u) & 31u) << 5u) | rb;
        return 0;
    case 476u:
        out->op = (uint32_t)PPC32_OP_NAND;
        return 0;
    case 491u:
        out->op = (uint32_t)PPC32_OP_DIVW;
        return 0;
    case 512u:
        out->op = (uint32_t)PPC32_OP_MCRXR;
        return 0;
    case 533u:
        out->op = (uint32_t)PPC32_OP_LSWX;
        return 0;
    case 534u:
        out->op = (uint32_t)PPC32_OP_LWBRX;
        return 0;
    case 535u: /* float indexed (fields only) */
    case 567u:
    case 599u:
    case 631u:
    case 663u:
    case 695u:
    case 727u:
    case 759u:
        out->op = (uint32_t)PPC32_OP_FPU_X;
        return 0;
    case 536u:
        out->op = (uint32_t)PPC32_OP_SRW;
        return 0;
    case 597u:
        out->op = (uint32_t)PPC32_OP_LSWI;
        return 0;
    case 598u:
        out->op = (uint32_t)PPC32_OP_SYNC;
        return 0;
    case 661u:
        out->op = (uint32_t)PPC32_OP_STSWX;
        return 0;
    case 662u:
        out->op = (uint32_t)PPC32_OP_STWBRX;
        return 0;
    case 725u:
        out->op = (uint32_t)PPC32_OP_STSWI;
        return 0;
    case 790u:
        out->op = (uint32_t)PPC32_OP_LHBRX;
        return 0;
    case 792u:
        out->op = (uint32_t)PPC32_OP_SRAW;
        return 0;
    case 824u:
        out->op = (uint32_t)PPC32_OP_SRAWI;
        return 0;
    case 854u:
        out->op = (uint32_t)PPC32_OP_SYNC;
        return 0;
    case 918u:
        out->op = (uint32_t)PPC32_OP_STHBRX;
        return 0;
    case 922u:
        out->op = (uint32_t)PPC32_OP_EXTSH;
        return 0;
    case 954u:
        out->op = (uint32_t)PPC32_OP_EXTSB;
        return 0;
    default:
        out->op = (uint32_t)PPC32_OP_UNDEF;
        return -1;
    }
}
