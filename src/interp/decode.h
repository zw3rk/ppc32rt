/*
 * src/interp/decode.h — PowerPC Book I instruction decoder (Phase 1, lane L1a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frozen contract consumed by lane L1b (`src/interp/interp.c`): every
 * named 32-bit Book I integer encoding decodes to a distinct
 * `ppc32_op_t`; classic-FPU (`59/63`, `48-55`, float `31`-XOs) and
 * e500v2 SPE (major opcode `4`) words decode to coarse family ids with
 * all register/immediate/XO fields preserved ("decode fields only",
 * full semantics land in Phase 3). Anything else — reserved primaries,
 * 64-bit-only forms (primary `30` `rld*`, `58`/`62` `ld`/`std`), and
 * privileged-only XOs — returns `-1` (`PPC32_OP_UNDEF`).
 *
 * Include as `#include "interp/decode.h"` (`-Isrc`).
 */

#ifndef PPC32RT_INTERP_DECODE_H
#define PPC32RT_INTERP_DECODE_H

#include <stdint.h>

/*
 * One id per decoded family. Integer instructions get per-mnemonic ids
 * (the interpreter switches on them); float/SPE get per-family ids and
 * the consumer refines on `xo` (XO values for those families are listed
 * in SPEC 2.2 and experiments/E03/FINDINGS.md).
 */
typedef enum ppc32_op {
    PPC32_OP_UNDEF = 0, /* unknown/reserved/64-bit-only/privileged */
    PPC32_OP_SC,        /* `sc 0` == PPC32_INSN_SC (0x44000002) */

    /* D-form integer immediates (TO/RT/RS at bits 6-10, RA, 16-bit D). */
    PPC32_OP_TWI,       /* 3: trap word immediate */
    PPC32_OP_MULLI,     /* 7 */
    PPC32_OP_SUBFIC,    /* 8 */
    PPC32_OP_CMPLI,     /* 10 */
    PPC32_OP_CMPI,      /* 11 */
    PPC32_OP_ADDIC,     /* 12 */
    PPC32_OP_ADDIC_DOT, /* 13: addic. (Rc implied) */
    PPC32_OP_ADDI,      /* 14 */
    PPC32_OP_ADDIS,     /* 15 */
    PPC32_OP_ORI,       /* 24 */
    PPC32_OP_ORIS,      /* 25 */
    PPC32_OP_XORI,      /* 26 */
    PPC32_OP_XORIS,     /* 27 */
    PPC32_OP_ANDI,      /* 28 (Rc implied) */
    PPC32_OP_ANDIS,     /* 29 (Rc implied) */

    /* Branches. B/I-form: `li` = 24-bit LI field, `oe` = AA bit 30,
     * `rc` = LK bit 31. B-form: `bo`, `bi`, `bd` = raw 14-bit BD field
     * (displacement = signExtend(BD || 0b00)); `oe` = AA, `rc` = LK.
     * XL-form (19): `bo`, `bi`, `xo` = 10-bit XO, `rc` = LK; `rb` holds
     * the raw RB field (BH hint in its low 2 bits for bclr/bcctr). */
    PPC32_OP_B,     /* 18 */
    PPC32_OP_BC,    /* 16 */
    PPC32_OP_BCLR,  /* 19, XO 16 */
    PPC32_OP_BCCTR, /* 19, XO 528 */
    PPC32_OP_CR,    /* 19 CR-logical (xo: 257 crand, 129 crandc,
                      * 289 creqv, 225 crnand, 33 crnor, 449 cror,
                      * 417 crorc, 193 crxor). crD/crA/crB sit in the
                      * RT/RA/RB fields (3-bit ids at bits 8/13/18,
                      * i.e. crD = rt >> 2 & 7, crA = ra >> 2 & 7,
                      * crB = rb >> 2 & 7). */
    PPC32_OP_MCRF,  /* 19, XO 0: rt holds crD << 2, ra holds crS << 2 */
    PPC32_OP_SYNC,  /* barrier nop: 31/XO 598 sync, 19/XO 150 isync,
                     * 31/XO 854 eieio */

    /* M-form rotates (20/21/23): `rs`/`rt` = RS, `ra` = RA, `rb` = SH
     * (rlwimi/rlwinm) or RB (rlwnm), `bo` = MB, `bi` = ME, `rc` = Rc. */
    PPC32_OP_RLWIMI, /* 20 */
    PPC32_OP_RLWINM, /* 21 */
    PPC32_OP_RLWNM,  /* 23 */

    /* D-form integer loads/stores (RT, RA, D; RA == 0 means literal 0). */
    PPC32_OP_LWZ,  /* 32 */ PPC32_OP_LWZU, /* 33 */
    PPC32_OP_LBZ,  /* 34 */ PPC32_OP_LBZU, /* 35 */
    PPC32_OP_STW,  /* 36 */ PPC32_OP_STWU, /* 37 */
    PPC32_OP_STB,  /* 38 */ PPC32_OP_STBU, /* 39 */
    PPC32_OP_LHZ,  /* 40 */ PPC32_OP_LHZU, /* 41 */
    PPC32_OP_LHA,  /* 42 */ PPC32_OP_LHAU, /* 43 */
    PPC32_OP_STH,  /* 44 */ PPC32_OP_STHU, /* 45 */
    PPC32_OP_LMW,  /* 46: load multiple word */
    PPC32_OP_STMW, /* 47: store multiple word */

    /* Classic-FPU D-forms (FRT in `rt`, RA, D). */
    PPC32_OP_LFS,  /* 48 */ PPC32_OP_LFSU, /* 49 */
    PPC32_OP_LFD,  /* 50 */ PPC32_OP_LFDU, /* 51 */
    PPC32_OP_STFS, /* 52 */ PPC32_OP_STFSU, /* 53 */
    PPC32_OP_STFD, /* 54 */ PPC32_OP_STFDU, /* 55 */

    /* Classic-FPU extended + SPE (fields only; semantics in Phase 3).
     * A-form (59/63): rt=FRT, ra=FRA, rb=FRB, bi=FRC, xo=5-bit XO,
     * rc=Rc. X-form float (63): rt/ra/rb/oe/xo(10-bit)/rc. */
    PPC32_OP_FPU_SINGLE, /* 59 single-precision A-form */
    PPC32_OP_FPU_DOUBLE, /* 63 double-precision A/X-form */
    PPC32_OP_FPU_X,      /* 31 float indexed (XO 535/567/599/631/
                          * 663/695/727/759): rt/ra/rb filled */

    /* e500v2 SPE, major opcode 4 (fields only): rt/rs=RD/RS, ra, rb,
     * xo = FULL 11-bit field (raw & 0x7ff, Rc slot included per
     * E03: evaddw 512, evand 529, evfsadd 640, efsadd 704, efdadd 736,
     * evldd 769, evstdd 801, ...), rc = raw & 1. d/si/ui mirror the
     * low 16 bits for displacement variants. Never a classic-750
     * instruction; classic profile treats it as data for UNDEF. */
    PPC32_OP_SPE, /* 4 */

    /* X-form integer (primary 31): rt/rs, ra, rb, oe (bit 21),
     * xo (10-bit XO), rc (bit 31). Specials: MTCRF stores the 8-bit
     * FXM mask (bits 12-19) in `ui`; MFSPR/MTSPR store the 10-bit SPR
     * number (SPR = RA<<5 | RB split field) in `ui`; LSWI/STSWI store
     * the NB count (0 means 32) in `rb`; SRAWI stores SH in `rb`;
     * TWI/TW store TO in `rt`/`rs`, CMP/CMPL store BF<<2 in `rt`. */
    PPC32_OP_ADD,    /* 266 */ PPC32_OP_ADDC,   /* 10 */
    PPC32_OP_ADDE,   /* 138 */ PPC32_OP_ADDME,  /* 234 */
    PPC32_OP_ADDZE,  /* 202 */
    PPC32_OP_SUBF,   /* 40 */ PPC32_OP_SUBFC,  /* 8 */
    PPC32_OP_SUBFE,  /* 136 */ PPC32_OP_SUBFME, /* 232 */
    PPC32_OP_SUBFZE, /* 200 */ PPC32_OP_NEG,    /* 104 */
    PPC32_OP_MULHW,  /* 75 */ PPC32_OP_MULHWU, /* 11 */
    PPC32_OP_MULHDU, /* 9 */
    PPC32_OP_MULLW,  /* 235 */
    PPC32_OP_DIVW,   /* 491 */ PPC32_OP_DIVWU, /* 459 */
    PPC32_OP_AND,    /* 28 */ PPC32_OP_ANDC,  /* 60 */
    PPC32_OP_OR,     /* 444 */ PPC32_OP_ORC,  /* 412 */
    PPC32_OP_XOR,    /* 316 */ PPC32_OP_NAND, /* 476 */
    PPC32_OP_NOR,    /* 124 */ PPC32_OP_EQV,  /* 284 */
    PPC32_OP_EXTSB,  /* 954 */ PPC32_OP_EXTSH, /* 922 */
    PPC32_OP_CNTLZW, /* 26 */
    PPC32_OP_SLW,   /* 24 */ PPC32_OP_SRW,   /* 536 */
    PPC32_OP_SRAW,  /* 792 */ PPC32_OP_SRAWI, /* 824 */
    PPC32_OP_CMP,   /* 0 */ PPC32_OP_CMPL,  /* 32 */
    PPC32_OP_TW,    /* 4 */
    PPC32_OP_MFCR,  /* 19 */ PPC32_OP_MTCRF,  /* 144 */
    PPC32_OP_MFSPR, /* 339 */ PPC32_OP_MTSPR, /* 467 */
    PPC32_OP_MCRXR, /* 512 */
    PPC32_OP_LWZX,  /* 23 */ PPC32_OP_LWZUX, /* 55 */
    PPC32_OP_LBZX,  /* 87 */ PPC32_OP_LBZUX, /* 119 */
    PPC32_OP_STWX,  /* 151 */ PPC32_OP_STWUX, /* 183 */
    PPC32_OP_STBX,  /* 215 */ PPC32_OP_STBUX, /* 247 */
    PPC32_OP_LHZX,  /* 279 */ PPC32_OP_LHZUX, /* 311 */
    PPC32_OP_LHAX,  /* 343 */ PPC32_OP_LHAUX, /* 375 */
    PPC32_OP_STHX,  /* 407 */ PPC32_OP_STHUX, /* 439 */
    PPC32_OP_LWARX, /* 20, Rc must be 0 */
    PPC32_OP_STWCX, /* 150, Rc must be 1 (`stwcx.`) */
    PPC32_OP_LWBRX, /* 534 */ PPC32_OP_LHBRX, /* 790 */
    PPC32_OP_STWBRX, /* 662 */ PPC32_OP_STHBRX, /* 918 */
    PPC32_OP_LSWI,  /* 597 */ PPC32_OP_LSWX,  /* 533 */
    PPC32_OP_STSWI, /* 725 */ PPC32_OP_STSWX, /* 661 */
    PPC32_OP_DCBT   /* 278 dcbt / 246 dcbtst: cache-hint nop */
} ppc32_op_t;

/* Decoded instruction. Only the fields meaningful to `op` (see above)
 * are filled; the rest read 0. `rs` always mirrors `rt` (same bit
 * field, two names so callers need no renaming). `raw` echoes input,
 * `op` is a `ppc32_op_t`, `xo` the raw 10-bit XO (11-bit for SPE). */
typedef struct ppc32_insn {
    uint32_t raw;
    uint32_t op;
    uint32_t xo;
    uint8_t  rt;
    uint8_t  ra;
    uint8_t  rb;
    uint8_t  rs;
    uint8_t  bo;
    uint8_t  bi;
    uint8_t  oe;
    uint8_t  rc;
    int32_t  d;
    int32_t  si;
    uint32_t ui;
    uint32_t li;
    uint32_t bd;
} ppc32_insn_t;

/* Decode one big-endian instruction word. Returns 0 and fills `*out`
 * on success, -1 (leaving `*out` zeroed) when the word is not a known
 * 32-bit encoding or `out` is null. Never fails on any input word. */
int ppc_decode(uint32_t raw, ppc32_insn_t *out);

#endif /* PPC32RT_INTERP_DECODE_H */
