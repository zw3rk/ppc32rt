/*
 * src/interp/altivec.h — PowerPC 7400/7450 (G4) AltiVec (VMX) reference
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * G04 Darwin G4 CPU profile: architectural VMX state lives in the
 * C-only tail of ppc32_ctx_t (vr[32][16] BE bytes, vscr, vrsave).
 * interp_step routes PPC32_OP_VMX / PPC32_OP_VMX_LDST here (and
 * PPC32_OP_SPE on non-SPE profiles, so shared primary-4 encodings
 * resolve by profile). DBT has no native VMX lowering yet and falls
 * back to interp_step via EXIT_UNDEF, which keeps --difftest exact.
 *
 * XO values follow PowerISA Book I / QEMU tcg/ppc and LLVM
 * PPCInstrAltivec: e.g. VADDUBM 0, VADDUHM 64, VADDUWM 128,
 * VCMPEQUB 6, VCMPGTUB 518, VAND 1028, VOR 1156, VXOR 1220,
 * VSPLTB 524, VPERM 43, VSEL 42, MFVSCR 1540, MTVSCR 1604,
 * LVX 103 / STVX 231 (primary 31), DST 342 / DSTST 374 / DSS 822
 * (decoded to SYNC no-ops), DCBA 758 (= DCBZ), DCBF 86 (= DCBT).
 */

#ifndef PPC32RT_INTERP_ALTIVEC_H
#define PPC32RT_INTERP_ALTIVEC_H

#include <stdint.h>

#include "ppc32rt.h"
#include "interp/decode.h"

/* Execute one primary-4 VMX arithmetic/logical/permute/compare/FP op.
 * Unknown XOs set PPC32_EXIT_UNDEF. Rc=1 on compares sets CR6. */
void ppc32_altivec_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);

/* Execute one primary-31 VMX load/store (lvx/lvxl/lvebx/stvebx/lvsl/lvsr).
 * Unknown XOs set PPC32_EXIT_UNDEF. */
void ppc32_vmx_ldst_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);

#endif /* PPC32RT_INTERP_ALTIVEC_H */
