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

#endif /* PPC32_EMIT_FP_H */
