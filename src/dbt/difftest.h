/*
 * src/dbt/difftest.h — interp-vs-dbt differential comparator (Phase 2, lane L2d)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * After each guest insn/block, the --difftest driver snapshots the
 * interpreter oracle state and the DBT state and calls difftest_check()
 * to compare them. Integer state (gpr[32], nip, lr, ctr, cr, xer) is
 * always compared; fpr[32]/fpscr are compared unconditionally too (they
 * are part of ppc32_ctx_t and read zero until Phase 3 wires the FPU);
 * e500v2 SPE state (gpr_hi[32], acc, spefscr) is compared only when
 * either side has is_spe set.
 */

#ifndef PPC32RT_DBT_DIFFTEST_H
#define PPC32RT_DBT_DIFFTEST_H

#include <stdint.h>

#include "ppc32rt.h"

/*
 * Compare interp_ctx (oracle) against dbt_ctx at guest PC pc.
 * Adds one to *mismatches per differing field and prints the first
 * divergence with the PC plus a register dump of both sides.
 * Either pointer and mismatches must be non-null.
 */
void difftest_check(ppc32_ctx_t *interp_ctx, ppc32_ctx_t *dbt_ctx,
    uint32_t pc, int *mismatches);

#endif /* PPC32RT_DBT_DIFFTEST_H */
