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

#include <stdbool.h>
#include <stddef.h>
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

/* Snapshot of one initially-writable guest region for difftest reset.
 * Moved from main.c under the file-size discipline; the --difftest
 * drivers in main.c and the Darwin bridge share these helpers. */
typedef struct {
    uint32_t start;
    uint32_t len;
    uint8_t *bytes;
} ppc32_difftest_snap_t;

#define PPC32_DIFFTEST_SNAP_CAP 64U

/* Capture every writable tracked region (cap or 16 MiB limit aborts
 * loudly via *incomplete instead of silently mis-comparing). */
size_t ppc32_difftest_snapshot(ppc32_ctx_t *ctx,
    ppc32_difftest_snap_t *segs, size_t cap, bool *incomplete);
void ppc32_difftest_snap_free(ppc32_difftest_snap_t *segs, size_t n);

/* Revert the oracle's segment writes so the DUT starts the segment
 * from the exact post-boundary state. */
void ppc32_difftest_restore(ppc32_ctx_t *ctx, ppc32_difftest_snap_t *segs,
    size_t n);

/* Copy the dispatched-syscall outcome (and VM mirrors) from the oracle
 * ctx to the DUT ctx after a shared dispatch. */
void ppc32_difftest_sync_dut(ppc32_ctx_t *dut, const ppc32_ctx_t *ref);

/* Refresh the snapshot after state-changing work on ref (syscall
 * dispatch or signal-frame delivery). Returns 0, or 2 with an
 * INCONCLUSIVE report when the snapshot has a gap. */
int ppc32_difftest_refresh(ppc32_ctx_t *ctx, ppc32_difftest_snap_t *snap,
    size_t *n);

#endif /* PPC32RT_DBT_DIFFTEST_H */
