/*
 * src/dbt/emit_fp.h — classic-FPU + e500v2 SPE AArch64 emitter (Phase 3, lane L3b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lower every Phase 3 FP/SPE instruction (SPEC 2.2) to baseline
 * ARMv8.0 AArch64 machine words (all encodings verified against the
 * host assembler): classic FPU arithmetic (fadd[s]/fsub[s]/fmul[s]/
 * fdiv[s]/fsqrt[s], fused fmadd[s]/fmsub[s]/fnmadd[s]/fnmsub[s],
 * fsel, fcmpu/fcmpo, fctiw[z], frsp, fmr/fabs/fnabs/fneg,
 * mffs/mtfsf, lfs/lfd/stfs/stfd + update/indexed forms),
 * SPE vector integer/logical/merge (evaddw, evsubfw, evand, evor,
 * evmr, evxor, evmerge*), indexed 64-bit loads/stores
 * (evlddx/evldwx/evstddx/evstdwx), scalar single efs* and scalar
 * double efd* arithmetic and converts, and vector float evfs*
 * arithmetic. FPSCR maps to A64 NZCV (compare/CR1 fields) and
 * FPCR.RMode/DN (rounding); FPSR cumulative bits accumulate into
 * FPSCR exception bits; FPRF is classified exactly from the result.
 * Anything outside the covered set returns PPC32_EMIT_FALLBACK so
 * the runner single-steps it in interp (always correct).
 *
 * HWCAP note: every instruction emitted here is ARMv8.0 baseline,
 * so no AT_HWCAP gating is required. Future SVE/SVE2, FP16, AES/SHA
 * or LSE use in this file must be phase-gated on AT_HWCAP with an
 * interp fallback when the bit is clear.
 */

#ifndef PPC32_EMIT_FP_H
#define PPC32_EMIT_FP_H

#include "interp/decode.h"
#include "dbt/emit_int.h"

/* Lower one FP/SPE instruction; anything outside the covered set
 * (including D-form update with rA == 0) returns PPC32_EMIT_FALLBACK. */
int ppc32_emit_fp(ppc32_emit_ctx_t *e, const ppc32_insn_t *insn,
    uint32_t pc);

/* FPSCR value-bit masks (shared with emit_fp_class.c). */
#define FP_FX 0x80000000U
#define FP_VXVC 0x00080000U /* FPSCR invalid-compare summary bit */
#define FP_VX 0x20000000U
#define FP_OX 0x10000000U
#define FP_UX 0x08000000U
#define FP_ZX 0x04000000U
#define FP_XX 0x02000000U
#define FP_VXSNAN 0x01000000U
#define FP_VXISI 0x00800000U
#define FP_VXIDI 0x00400000U
#define FP_VXZDZ 0x00200000U
#define FP_VXIMZ 0x00100000U
#define FP_FR 0x00040000U
#define FP_FI 0x00020000U
#define FP_VXCVI 0x00000100U
#define FP_FPRF_MASK 0x0003F000U

/* NZCV (w10) -> PPC [LT,GT,EQ,UN] in EI_R/w11, and the exact FPRF
 * classify helper (src/dbt/emit_fp_class.c); shared by compare and
 * arithmetic emitters. */
struct a64_buf;
void fp_nzcv_field(struct a64_buf *b);
void fp_fprf(struct a64_buf *b, unsigned vd, bool dbl);
/* Guest FPSCR traffic (emit_fp_class.c; same encoding as the emit_fp.c
 * statics, exposed for the post-store FR fixups below). */
void fp_fpscr_ld(struct a64_buf *b, unsigned wd);
void fp_fpscr_st(struct a64_buf *b, unsigned ws);
/* P32-R8-6: preclassify the IOC mask for a binary op (iop: 0 add, 1 sub,
 * 2 mul, 3 div; anything else keeps VXSNAN) from the live inputs into
 * w17 for fp_accum. */
void fp_inv_classify(struct a64_buf *b, unsigned iop, bool dbl);
/* P32-R8-5: post-store FR fixups (oracle fp_rounded_up). fp_fr_arith
 * repeats the op (redo writes v5 from A in v7) under RZ for RN mode and
 * uses sign rules otherwise; fp_fr_mag compares a double/int result
 * against the saved original (to_int selects SCVTF W->D first). */
void fp_fr_arith(struct a64_buf *b, uint32_t redo, bool dbl);
void fp_fr_mag(struct a64_buf *b, unsigned orig_v, unsigned round_v,
    bool to_int);

#endif /* PPC32_EMIT_FP_H */
