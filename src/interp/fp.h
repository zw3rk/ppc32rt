/*
 * src/interp/fp.h — classic-FPU data-movement reference (RC2 subset).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * RC2 subset (static-libc enablement: setjmp/longjmp save/restore FPRs):
 * lfs/lfsu/lfd/lfdu/stfs/stfsu/stfd/stfdu as pure bit-pattern moves
 * (lfs zero-extends the 32-bit pattern; no float conversion). All FP
 * arithmetic, compares, conversions, FPSCR rules, and SPE belong to
 * Phase 3 (lane L3a extends this file).
 */

#ifndef PPC32_FP_H
#define PPC32_FP_H

#include <stdint.h>

#include "ppc32rt.h"
#include "interp/decode.h"

/* Execute one FP data-movement instruction. Unknown FP opcodes set
 * PPC32_EXIT_UNDEF (single-step fallback path uses the same). */
void ppc32_fp_step(ppc32_ctx_t *ctx, const ppc32_insn_t *insn);

#endif /* PPC32_FP_H */
