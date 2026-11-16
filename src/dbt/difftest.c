/*
 * src/dbt/difftest.c — interp-vs-dbt differential comparator (Phase 2, lane L2d)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Compares the interpreter oracle state against the DBT state after
 * each guest insn/block: gpr[32], nip, lr, ctr, cr, xer (always),
 * fpr[32]/fpscr (always; zero until Phase 3 wires the FPU), plus the
 * e500v2 SPE upper state (gpr_hi[32], acc, spefscr) only when either
 * side has is_spe set. The first divergence prints the guest PC and a
 * register dump of both sides; each differing field bumps *mismatches.
 *
 * NOTE: this TU deliberately does NOT define ppc32_dbt_invalidate_range
 * (extern in src/rt32/ppc32_vm.c once any src/dbt C file exists). The real
 * definition belongs to lane L2b's src/dbt/cache.c; the full-binary
 * link needs that TU. This file alone keeps `make check` (syntax-only)
 * and the host selftest green.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbt/difftest.h"

static void dump_side(const char *tag, const ppc32_ctx_t *c)
{
    int i;

    printf("difftest: %s nip=0x%08" PRIX32 " lr=0x%08" PRIX32
        " ctr=0x%08" PRIX32 " cr=0x%08" PRIX32 " xer=0x%08" PRIX32 "\n",
        tag, c->nip, c->lr, c->ctr, c->cr, c->xer);
    for (i = 0; i < 32; i += 4) {
        printf("difftest: %s r%-2d=0x%08" PRIX32 " r%-2d=0x%08" PRIX32
            " r%-2d=0x%08" PRIX32 " r%-2d=0x%08" PRIX32 "\n",
            tag, i, c->gpr[i], i + 1, c->gpr[i + 1],
            i + 2, c->gpr[i + 2], i + 3, c->gpr[i + 3]);
    }
}

void difftest_check(ppc32_ctx_t *interp_ctx, ppc32_ctx_t *dbt_ctx,
    uint32_t pc, int *mismatches)
{
    int i;
    int before;

    if (interp_ctx == NULL || dbt_ctx == NULL || mismatches == NULL) {
        return;
    }
    before = *mismatches;
    for (i = 0; i < 32; i++) {
        if (interp_ctx->gpr[i] != dbt_ctx->gpr[i]) {
            printf("difftest: MISMATCH pc=0x%08" PRIX32
                " gpr[%d] interp=0x%08" PRIX32 " dbt=0x%08" PRIX32 "\n",
                pc, i, interp_ctx->gpr[i], dbt_ctx->gpr[i]);
            (*mismatches)++;
        }
    }
    if (interp_ctx->nip != dbt_ctx->nip) {
        printf("difftest: MISMATCH pc=0x%08" PRIX32 " nip interp=0x%08" PRIX32
            " dbt=0x%08" PRIX32 "\n", pc, interp_ctx->nip, dbt_ctx->nip);
        (*mismatches)++;
    }
    if (interp_ctx->lr != dbt_ctx->lr) {
        printf("difftest: MISMATCH pc=0x%08" PRIX32 " lr interp=0x%08" PRIX32
            " dbt=0x%08" PRIX32 "\n", pc, interp_ctx->lr, dbt_ctx->lr);
        (*mismatches)++;
    }
    if (interp_ctx->ctr != dbt_ctx->ctr) {
        printf("difftest: MISMATCH pc=0x%08" PRIX32 " ctr interp=0x%08" PRIX32
            " dbt=0x%08" PRIX32 "\n", pc, interp_ctx->ctr, dbt_ctx->ctr);
        (*mismatches)++;
    }
    if (interp_ctx->cr != dbt_ctx->cr) {
        printf("difftest: MISMATCH pc=0x%08" PRIX32 " cr interp=0x%08" PRIX32
            " dbt=0x%08" PRIX32 "\n", pc, interp_ctx->cr, dbt_ctx->cr);
        (*mismatches)++;
    }
    if (interp_ctx->xer != dbt_ctx->xer) {
        printf("difftest: MISMATCH pc=0x%08" PRIX32 " xer interp=0x%08" PRIX32
            " dbt=0x%08" PRIX32 "\n", pc, interp_ctx->xer, dbt_ctx->xer);
        (*mismatches)++;
    }
    if (interp_ctx->fpscr != dbt_ctx->fpscr) {
        printf("difftest: MISMATCH pc=0x%08" PRIX32 " fpscr interp=0x%08" PRIX32
            " dbt=0x%08" PRIX32 "\n", pc, interp_ctx->fpscr,
            dbt_ctx->fpscr);
        (*mismatches)++;
    }
    for (i = 0; i < 32; i++) {
        if (interp_ctx->fpr[i] != dbt_ctx->fpr[i]) {
            printf("difftest: MISMATCH pc=0x%08" PRIX32
                " fpr[%d] interp=0x%016" PRIX64 " dbt=0x%016" PRIX64 "\n",
                pc, i, interp_ctx->fpr[i], dbt_ctx->fpr[i]);
            (*mismatches)++;
        }
    }
    if (interp_ctx->is_spe != 0 || dbt_ctx->is_spe != 0) {
        for (i = 0; i < 32; i++) {
            if (interp_ctx->gpr_hi[i] != dbt_ctx->gpr_hi[i]) {
                printf("difftest: MISMATCH pc=0x%08" PRIX32
                    " gpr_hi[%d] interp=0x%08" PRIX32 " dbt=0x%08" PRIX32 "\n",
                    pc, i, interp_ctx->gpr_hi[i], dbt_ctx->gpr_hi[i]);
                (*mismatches)++;
            }
        }
        if (interp_ctx->acc != dbt_ctx->acc) {
            printf("difftest: MISMATCH pc=0x%08" PRIX32
                " acc interp=0x%016" PRIX64 " dbt=0x%016" PRIX64 "\n",
                pc, interp_ctx->acc, dbt_ctx->acc);
            (*mismatches)++;
        }
        if (interp_ctx->spefscr != dbt_ctx->spefscr) {
            printf("difftest: MISMATCH pc=0x%08" PRIX32
                " spefscr interp=0x%08" PRIX32 " dbt=0x%08" PRIX32 "\n",
                pc, interp_ctx->spefscr, dbt_ctx->spefscr);
            (*mismatches)++;
        }
    }
    if (*mismatches != before) {
        printf("difftest: first divergence at pc=0x%08" PRIX32
            " (%d new mismatch(es))\n", pc, *mismatches - before);
        dump_side("interp", interp_ctx);
        dump_side("dbt   ", dbt_ctx);
    }
}

/* Per-segment snapshot of every writable tracked region (stack, heap,
 * image data). The two engines share one window and the oracle runs
 * ahead, so without a restore the DUT would read the oracle's later
 * writes. The snapshot is refreshed after load and after every
 * syscall dispatch (brk/mmap can reshape the region table); restoring
 * before each DUT segment reverts exactly the oracle's segment writes.
 * Any writable region that cannot be captured (cap or 16 MiB limit)
 * aborts loudly via *incomplete instead of silently mis-comparing. */
size_t ppc32_difftest_snapshot(ppc32_ctx_t *ctx, ppc32_difftest_snap_t *segs,
    size_t cap, bool *incomplete)
{
    size_t n = 0U;
    size_t i;

    if (incomplete != NULL) {
        *incomplete = false;
    }
    for (i = 0U; i < ctx->region_count; i++) {
        uint32_t start = ctx->regions[i].start;
        uint32_t end = ctx->regions[i].end;

        if (end <= start || (ctx->regions[i].prot & 0x2U) == 0U) {
            continue;
        }
        if (n >= cap ||
            (uint64_t)end - (uint64_t)start > 16ULL * 1024ULL * 1024ULL) {
            if (incomplete != NULL) {
                *incomplete = true;
            }
            break;
        }
        segs[n].start = start;
        segs[n].len = end - start;
        segs[n].bytes = malloc(segs[n].len);
        if (segs[n].bytes == NULL) {
            if (incomplete != NULL) {
                *incomplete = true;
            }
            break;
        }
        memcpy(segs[n].bytes, ppc32_guest_ptr(ctx, start), segs[n].len);
        n++;
    }
    return n;
}

void ppc32_difftest_snap_free(ppc32_difftest_snap_t *segs, size_t n)
{
    size_t i;

    for (i = 0U; i < n; i++) {
        free(segs[i].bytes);
        segs[i].bytes = NULL;
        segs[i].len = 0U;
    }
}

void ppc32_difftest_restore(ppc32_ctx_t *ctx, ppc32_difftest_snap_t *segs,
    size_t n)
{
    size_t i;

    for (i = 0U; i < n; i++) {
        memcpy(ppc32_guest_ptr(ctx, segs[i].start), segs[i].bytes,
            segs[i].len);
    }
}

void ppc32_difftest_sync_dut(ppc32_ctx_t *dut, const ppc32_ctx_t *ref)
{
    size_t i;

    for (i = 0U; i < 32U; i++) {
        dut->gpr[i] = ref->gpr[i];
    }
    dut->nip = ref->nip;
    dut->lr = ref->lr;
    dut->ctr = ref->ctr;
    dut->cr = ref->cr;
    dut->xer = ref->xer;
    dut->exit_arg = ref->exit_arg;
    dut->brk_base = ref->brk_base;
    dut->brk_curr = ref->brk_curr;
    dut->mmap_cursor = ref->mmap_cursor;
    dut->region_count = ref->region_count;
    if (ref->region_count > 0U) {
        memcpy(dut->regions, ref->regions,
            ref->region_count * sizeof(dut->regions[0]));
    }
    dut->exit_reason = PPC32_EXIT_NONE;
}

int ppc32_difftest_refresh(ppc32_ctx_t *ctx, ppc32_difftest_snap_t *snap,
    size_t *n)
{
    bool incomplete = false;

    ppc32_difftest_snap_free(snap, *n);
    *n = ppc32_difftest_snapshot(ctx, snap, PPC32_DIFFTEST_SNAP_CAP,
        &incomplete);
    if (incomplete) {
        printf("DIFFTEST: INCONCLUSIVE (snapshot gap)\n");
        ppc32_difftest_snap_free(snap, *n);
        return 2;
    }
    return 0;
}

/*
 * Standalone host selftest driver: compile with
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc -DPPC32RT_DIFFTEST_SELFTEST \
 *     src/dbt/difftest.c -o /tmp/difftest_selftest && /tmp/difftest_selftest
 * Prints L2D OK when identical states are clean and injected
 * gpr/nip/cr divergences are each detected.
 */
#ifdef PPC32RT_DIFFTEST_SELFTEST
#include <string.h>

static ppc32_ctx_t t_interp;
static ppc32_ctx_t t_dbt;

static int selftest_case(const char *name, int want_nonzero)
{
    int mismatches = 0;

    difftest_check(&t_interp, &t_dbt, 0x1000U, &mismatches);
    if (want_nonzero == 0 && mismatches != 0) {
        printf("L2D FAIL: %s: want clean, got %d mismatch(es)\n",
            name, mismatches);
        return 1;
    }
    if (want_nonzero != 0 && mismatches == 0) {
        printf("L2D FAIL: %s: divergence not detected\n", name);
        return 1;
    }
    return 0;
}

int main(void)
{
    int rc = 0;
    int i;

    memset(&t_interp, 0, sizeof(t_interp));
    memset(&t_dbt, 0, sizeof(t_dbt));
    for (i = 0; i < 32; i++) {
        t_interp.gpr[i] = 0xA5000000U | (uint32_t)i;
        t_dbt.gpr[i] = t_interp.gpr[i];
    }
    t_interp.nip = 0x1000U;
    t_dbt.nip = 0x1000U;
    t_interp.lr = 0x2000U;
    t_dbt.lr = 0x2000U;
    t_interp.ctr = 0x10U;
    t_dbt.ctr = 0x10U;
    t_interp.cr = 0x20000000U;
    t_dbt.cr = 0x20000000U;

    rc |= selftest_case("identical", 0);

    t_dbt.gpr[3] ^= 1U;
    rc |= selftest_case("gpr", 1);
    t_dbt.gpr[3] = t_interp.gpr[3];

    t_dbt.nip += 4U;
    rc |= selftest_case("nip", 1);
    t_dbt.nip = t_interp.nip;

    t_dbt.cr ^= 0x20000000U;
    rc |= selftest_case("cr", 1);
    t_dbt.cr = t_interp.cr;

    rc |= selftest_case("restored", 0);

    if (rc == 0) {
        printf("L2D OK\n");
    }
    return rc;
}
#endif /* PPC32RT_DIFFTEST_SELFTEST */
