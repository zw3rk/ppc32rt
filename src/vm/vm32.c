/*
 * src/vm/vm32.c — Two-regime window reservation (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements UNIFICATION-PLAN.md Rev 4 section 4.6 for ppc32:
 *
 *   Regime A1 (H == 4096): reserve [G, G + 4 GiB) MAP_PRIVATE anonymous,
 *   publish x20 = G (ctx->guest_base), DBT emits 1-instruction
 *   [x20, wAddr, uxtw] (already the lowering in src/dbt/emit_int.c and
 *   src/rt32/ppc32_a64_emit.c). Native fork() COW applies.
 *
 *   Regime A2 (H > 4096): reserve the same span as one MAP_PRIVATE
 *   anonymous arena; active host pages are mapped with the union of
 *   their 4 KiB sub-page protections (PROT_READ | PROT_WRITE, never
 *   PROT_EXEC) so RELRO + .data sharing a 16 KiB host page costs zero
 *   SIGSEGV traps (M3); DBT binds x20 = &tlb[0] and emits the 7-insn
 *   Soft-TLB (src/vm/vm32_tlb.c) with mov w1, wAddr zero-extension.
 *
 * Runs beside the legacy ppc32_vm_init owner: exactly one of them
 * reserves the window per process boot (both use MAP_FIXED_NOREPLACE
 * probing, so double ownership fails loudly instead of overlapping).
 *
 * Curated C11, no x18, no inline asm. Throws no signals itself.
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x1000
#endif
#endif

static _Atomic int g_regime = VM32_REGIME_UNSET;
static _Atomic uintptr_t g_arena_base = 0U;
static size_t g_arena_len = 0U;

vm32_regime_t vm32_select_regime(size_t host_page_size)
{
    vm32_regime_t r;

    if (host_page_size == VM32_GUEST_PAGE_SIZE) {
        r = VM32_REGIME_A1_DIRECT;
    } else {
        r = VM32_REGIME_A2_SOFT_TLB;
    }
    atomic_store_explicit(&g_regime, (int)r, memory_order_seq_cst);
    return r;
}

vm32_regime_t vm32_current_regime(void)
{
    return (vm32_regime_t)atomic_load_explicit(&g_regime,
        memory_order_seq_cst);
}

uintptr_t vm32_arena_base(void)
{
    return atomic_load_explicit(&g_arena_base, memory_order_seq_cst);
}

void vm32_shadow_window(uint64_t base)
{
    (void)vm32_select_regime(vm32_host_page_size());
    atomic_store_explicit(&g_arena_base, (uintptr_t)base,
        memory_order_seq_cst);
}

void *vm32_hva(const ppc32_ctx_t *ctx, uint32_t gva)
{
    uintptr_t base;

    (void)ctx;
    base = atomic_load_explicit(&g_arena_base, memory_order_seq_cst);
    if (base == 0U) {
        base = (uintptr_t)ctx->guest_base;
    }
    return (void *)(base + (uintptr_t)gva);
}

/* Probe one 4 GiB-aligned candidate with PROT_NONE / NOREPLACE. */
static int reserve_span(uint64_t base, size_t len)
{
    void *res;

    if ((base & (VM32_WINDOW_SIZE - 1ULL)) != 0ULL) {
        return -EINVAL;
    }
    res = mmap((void *)(uintptr_t)base, len, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (res == MAP_FAILED && (errno == EINVAL || errno == EOPNOTSUPP)) {
        res = mmap((void *)(uintptr_t)base, len, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (res == MAP_FAILED) {
        return -errno;
    }
    if ((uint64_t)(uintptr_t)res != base) {
        (void)munmap(res, len);
        return -EEXIST;
    }
    return 0;
}

static uint64_t pick_window(uint64_t requested)
{
    uint64_t cand;

    if (requested != UINT64_MAX) {
        return requested;
    }
    if (reserve_span(0ULL, (size_t)VM32_WINDOW_SIZE) == 0) {
        (void)munmap((void *)(uintptr_t)0, (size_t)VM32_WINDOW_SIZE);
        return 0ULL;
    }
    for (cand = 0x100000000ULL; cand < 0x1000000000ULL;
        cand += 0x100000000ULL) {
        if (reserve_span(cand, (size_t)VM32_WINDOW_SIZE) == 0) {
            (void)munmap((void *)(uintptr_t)cand,
                (size_t)VM32_WINDOW_SIZE);
            return cand;
        }
    }
    return UINT64_MAX;
}

int vm32_init(ppc32_ctx_t *ctx, uint64_t requested_window)
{
    long host_page;
    uint64_t base;
    int rc;

    if (ctx == NULL) {
        return -EINVAL;
    }
    host_page = sysconf(_SC_PAGESIZE);
    if (host_page <= 0L) {
        return -ENOSYS;
    }
    (void)vm32_select_regime((size_t)host_page);

    base = pick_window(requested_window);
    if (base == UINT64_MAX) {
        return -ENOMEM;
    }
    rc = reserve_span(base, (size_t)VM32_WINDOW_SIZE);
    if (rc != 0) {
        return rc;
    }
    ctx->guest_base = base;
    atomic_store_explicit(&g_arena_base, (uintptr_t)base,
        memory_order_seq_cst);
    g_arena_len = (size_t)VM32_WINDOW_SIZE;
    if (vm32_current_regime() == VM32_REGIME_A2_SOFT_TLB) {
        /* A2 starts with a cold TLB: every access misses into
         * vm32_tlb_miss until its 4 KiB page is filled, so no
         * stale addend can predate the arena. */
        vm32_tlb_invalidate_all();
    }
    ctx->vm_ready = true;
    return 0;
}
