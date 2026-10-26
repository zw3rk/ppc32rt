/*
 * src/vm/vm32_tlb.c — Regime A2 7-instruction Soft-TLB (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Data side of UNIFICATION-PLAN.md Rev 4 section 4.3 for ppc32 Regime A2
 * (H > 4096). The DBT fast path (emitted by a later DBT lane) executes:
 *
 *   ubfx x2, x1, #12, #12 | add x2, x20, x2, lsl #5 |
 *   ldp x2, x3, [x2, #0] (load) or ldp x3, x2, [x2, #8] (store) |
 *   and x4, x1, #mask | sub x4, x4, x2 | cbnz x4, miss |
 *   ldr/str [x1, x3]
 *
 * with x20 = &tlb[0] and x1 = zero-extended 32-bit guest address
 * (mov w1, wAddr on entry). Steps 1-6 touch neither PSTATE nor x0/x1,
 * so a miss lands in the 2-insn per-site stub with full guest state
 * intact and funnels into vm32_tlb_miss below.
 *
 * write_tag discipline (section 4.4): a page is inline-storable iff
 * writable && !cow_clean && !has_code && !has_reservation. Anything else
 * forces write_tag = ~0 so stores trap into the miss helper, which is
 * also where COW promotion, SMC invalidation, and reservation bumps
 * happen exactly once per transition.
 *
 * Lane scope: single global table (the per-thread 128 KiB split arrives
 * with the threading lane); all fills/invalidations are serialized by
 * an internal spinlock while probes stay lock-free (aligned 64-bit tag
 * loads are single-copy atomic on AArch64).
 */

#include "vm/vm32.h"

#include <errno.h>
#include <string.h>

#define VM32_PAGE_COUNT (VM32_WINDOW_SIZE / VM32_GUEST_PAGE_SIZE)

#define VM32_PAGE_UNMAPPED 0U
#define VM32_PAGE_ANON 1U
#define VM32_PAGE_COW_CLEAN 2U
#define VM32_PAGE_COW_DIRTY 3U
#define VM32_PAGE_SHARED 4U

#define VM32_PAGE_HAS_CODE 0x01U
#define VM32_PAGE_HAS_RESERVATION 0x02U

static vm32_tlb_entry_t g_tlb[VM32_TLB_SIZE];
static uint8_t g_page_prot[VM32_PAGE_COUNT];
static uint8_t g_page_state[VM32_PAGE_COUNT];
static uint8_t g_page_flags[VM32_PAGE_COUNT];
static _Atomic uint32_t g_tlb_lock = 0U;

static void tlb_lock(void)
{
    while (atomic_exchange_explicit(&g_tlb_lock, 1U,
        memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static void tlb_unlock(void)
{
    atomic_store_explicit(&g_tlb_lock, 0U, memory_order_release);
}

static uint64_t page_tag(uint32_t gva)
{
    return (uint64_t)(gva & ~VM32_GUEST_PAGE_MASK);
}

static bool page_writable_locked(uint32_t vpn)
{
    if ((g_page_prot[vpn] & 0x2U) == 0U) {
        return false;
    }
    if (g_page_state[vpn] == VM32_PAGE_COW_CLEAN) {
        return false;
    }
    if ((g_page_flags[vpn] &
        (VM32_PAGE_HAS_CODE | VM32_PAGE_HAS_RESERVATION)) != 0U) {
        return false;
    }
    return g_page_state[vpn] == VM32_PAGE_ANON ||
        g_page_state[vpn] == VM32_PAGE_COW_DIRTY ||
        g_page_state[vpn] == VM32_PAGE_SHARED;
}

bool vm32_tlb_probe(uint32_t gva, bool is_store, uint32_t width,
    uintptr_t *addend_out)
{
    uint32_t idx = (gva >> 12U) & (VM32_TLB_SIZE - 1U);
    uint64_t align_mask = (width <= 1U) ? 0ULL : (uint64_t)(width - 1U);
    uint64_t masked;
    uint64_t tag;

    if (addend_out == NULL) {
        return false;
    }
    if (width != 1U && width != 2U && width != 4U && width != 8U &&
        width != 16U) {
        return false;
    }
    if (((uint64_t)gva & align_mask) != 0ULL) {
        return false;
    }
    /* Matches the emitted sequence: x4 = VPN | (gva & (N-1)) equals the
     * stored tag iff the VPN matches and the access is N-aligned. */
    masked = (uint64_t)page_tag(gva);
    if (is_store) {
        tag = __atomic_load_n(&g_tlb[idx].write_tag, __ATOMIC_SEQ_CST);
        if (masked != tag) {
            return false;
        }
    } else {
        tag = __atomic_load_n(&g_tlb[idx].read_tag, __ATOMIC_SEQ_CST);
        if (masked != tag) {
            return false;
        }
    }
    *addend_out = g_tlb[idx].addend;
    return true;
}

void vm32_tlb_fill(uint32_t gva_page, uintptr_t host_page_base,
    bool readable, bool writable)
{
    uint32_t vpn = gva_page >> 12U;
    uint32_t idx = (gva_page >> 12U) & (VM32_TLB_SIZE - 1U);
    uint64_t tag = page_tag(gva_page);

    if (vpn >= VM32_PAGE_COUNT) {
        return;
    }
    tlb_lock();
    g_tlb[idx].addend = host_page_base - (uintptr_t)tag;
    if (readable) {
        g_tlb[idx].read_tag = tag;
    } else {
        g_tlb[idx].read_tag = VM32_TLB_INVALID_TAG;
    }
    if (writable && page_writable_locked(vpn)) {
        g_tlb[idx].write_tag = tag;
    } else {
        g_tlb[idx].write_tag = VM32_TLB_INVALID_TAG;
    }
    tlb_unlock();
}

int vm32_tlb_miss(ppc32_ctx_t *ctx, uint32_t gva, bool is_store,
    void **hva_out)
{
    uint32_t vpn = gva >> 12U;
    uint32_t page = gva & ~VM32_GUEST_PAGE_MASK;
    uintptr_t base;
    bool ok;

    if (hva_out == NULL) {
        return -EINVAL;
    }
    if (gva < PPC32_LOW_GUARD_SIZE) {
        return -EACCES;
    }
    if (vpn >= VM32_PAGE_COUNT) {
        return -EFAULT;
    }
    base = vm32_arena_base();
    if (base == 0U) {
        if (ctx == NULL) {
            return -ENODEV;
        }
        base = (uintptr_t)ctx->guest_base;
    }
    tlb_lock();
    if (g_page_state[vpn] == VM32_PAGE_UNMAPPED) {
        ok = false;
    } else if (!is_store) {
        ok = (g_page_prot[vpn] & 0x1U) != 0U;
    } else {
        ok = page_writable_locked(vpn);
    }
    if (ok) {
        uint32_t idx = vpn & (VM32_TLB_SIZE - 1U);
        uint64_t tag = page_tag(gva);

        g_tlb[idx].addend = base + (uintptr_t)page - (uintptr_t)tag;
        g_tlb[idx].read_tag =
            ((g_page_prot[vpn] & 0x1U) != 0U) ? tag : VM32_TLB_INVALID_TAG;
        g_tlb[idx].write_tag =
            page_writable_locked(vpn) ? tag : VM32_TLB_INVALID_TAG;
        *hva_out = (void *)(base + (uintptr_t)gva);
    }
    tlb_unlock();
    if (!ok) {
        return -EACCES;
    }
    (void)page;
    return 0;
}

void vm32_tlb_invalidate_range(uint32_t start_gva, uint32_t end_gva)
{
    uint32_t first = start_gva >> 12U;
    uint32_t last = end_gva >> 12U;
    uint64_t pages;
    uint32_t vpn;

    if (end_gva <= start_gva) {
        return;
    }
    pages = (uint64_t)last - (uint64_t)first;
    tlb_lock();
    if (pages >= 512ULL) {
        size_t i;

        for (i = 0U; i < VM32_TLB_SIZE; i++) {
            g_tlb[i].read_tag = VM32_TLB_INVALID_TAG;
            g_tlb[i].write_tag = VM32_TLB_INVALID_TAG;
        }
    } else {
        for (vpn = first; vpn < last; vpn++) {
            uint32_t idx = vpn & (VM32_TLB_SIZE - 1U);

            g_tlb[idx].read_tag = VM32_TLB_INVALID_TAG;
            g_tlb[idx].write_tag = VM32_TLB_INVALID_TAG;
        }
    }
    tlb_unlock();
}

void vm32_tlb_invalidate_all(void)
{
    size_t i;

    tlb_lock();
    for (i = 0U; i < VM32_TLB_SIZE; i++) {
        g_tlb[i].read_tag = VM32_TLB_INVALID_TAG;
        g_tlb[i].write_tag = VM32_TLB_INVALID_TAG;
        g_tlb[i].addend = 0U;
        g_tlb[i].flags_reserved = 0U;
    }
    (void)memset(g_page_prot, 0, sizeof g_page_prot);
    (void)memset(g_page_state, 0, sizeof g_page_state);
    (void)memset(g_page_flags, 0, sizeof g_page_flags);
    tlb_unlock();
}
