/*
 * src/dbt/emit_fp.h — classic-FPU data-movement emitter (RC2 subset).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * RC2 subset matching interp/fp.h (lfs/lfd/stfs/stfd + update forms as
 * bit-pattern moves). Lane L3b owns FP arithmetic/SPE and extends the
 * matching emit_fp.c.
 */

#ifndef PPC32_EMIT_FP_H
#define PPC32_EMIT_FP_H

#include "interp/decode.h"
#include "dbt/emit_int.h"

/* Lower one FP data-movement instruction; anything else (including
 * update forms with rA == 0) returns PPC32_EMIT_FALLBACK. */
int ppc32_emit_fp(ppc32_emit_ctx_t *e, const ppc32_insn_t *insn,
    uint32_t pc);

#endif /* PPC32_EMIT_FP_H */
