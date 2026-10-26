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
#include <sched.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define VM32_PAGE_COUNT (VM32_WINDOW_SIZE / VM32_GUEST_PAGE_SIZE)

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
    } else if (g_page_state[vpn] == VM32_PAGE_COW_CLEAN &&
        (g_page_prot[vpn] & 0x2U) != 0U &&
        (g_page_flags[vpn] &
            (VM32_PAGE_HAS_CODE | VM32_PAGE_HAS_RESERVATION)) == 0U) {
        /* First write to a clean COW page: promote in place
         * (PAGE_COW_CLEAN -> PAGE_COW_DIRTY) so this very access
         * succeeds below without a second miss. */
        g_page_state[vpn] = (uint8_t)VM32_PAGE_COW_DIRTY;
        ok = true;
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

/* ---- Regime A2 host-page permission unions (RC-U3 finding 3) ---- */

static _Atomic size_t g_host_page_cached = 0U;

size_t vm32_host_page_size(void)
{
    size_t h = atomic_load_explicit(&g_host_page_cached,
        memory_order_relaxed);

    if (h == 0U) {
        long v = sysconf(_SC_PAGESIZE);

        h = (v > 0L) ? (size_t)v : (size_t)VM32_GUEST_PAGE_SIZE;
        atomic_store_explicit(&g_host_page_cached, h,
            memory_order_relaxed);
    }
    return h;
}

bool vm32_is_a2(void)
{
    return vm32_host_page_size() > (size_t)VM32_GUEST_PAGE_SIZE;
}

/* Invalidate one direct-mapped TLB slot; caller holds tlb_lock. The
 * table is a direct-mapped cache, so evicting the aliased slot is a
 * conservative forced miss refilled from the arrays below. */
static void tlb_evict_slot_locked(uint32_t vpn)
{
    uint32_t idx = vpn & (VM32_TLB_SIZE - 1U);

    g_tlb[idx].read_tag = VM32_TLB_INVALID_TAG;
    g_tlb[idx].write_tag = VM32_TLB_INVALID_TAG;
}

/* Refill one slot from the recorded arrays (canonical in-place HVA =
 * arena_base + gva); caller holds tlb_lock. Unmapped or unreadable
 * pages keep INVALID tags so accesses trap into the miss path. */
static void tlb_refill_slot_locked(uint32_t vpn, uintptr_t base)
{
    uint32_t idx = vpn & (VM32_TLB_SIZE - 1U);
    uint64_t tag = (uint64_t)vpn << 12U;

    g_tlb[idx].addend = base;
    if ((g_page_prot[vpn] & (uint8_t)PROT_READ) != 0U) {
        g_tlb[idx].read_tag = tag;
    } else {
        g_tlb[idx].read_tag = VM32_TLB_INVALID_TAG;
    }
    if (page_writable_locked(vpn)) {
        g_tlb[idx].write_tag = tag;
    } else {
        g_tlb[idx].write_tag = VM32_TLB_INVALID_TAG;
    }
}

/* Clamp [start_gva, end_gva) to the window; false when empty. */
static bool clamp_range(uint32_t start_gva, uint32_t end_gva,
    uint32_t *first_out, uint32_t *last_out)
{
    uint64_t first = (uint64_t)(start_gva >> 12U);
    uint64_t last = ((uint64_t)end_gva + (uint64_t)VM32_GUEST_PAGE_MASK) >> 12U;

    if (end_gva <= start_gva || first >= (uint64_t)VM32_PAGE_COUNT) {
        return false;
    }
    if (last > (uint64_t)VM32_PAGE_COUNT) {
        last = (uint64_t)VM32_PAGE_COUNT;
    }
    *first_out = (uint32_t)first;
    *last_out = (uint32_t)last;
    return true;
}

/* Refresh one slot after the arrays changed: refill when the arena
 * base is published, else evict to force a later miss. */
static void tlb_refresh_slot_locked(uint32_t vpn, uintptr_t base)
{
    if (base == 0U) {
        tlb_evict_slot_locked(vpn);
    } else {
        tlb_refill_slot_locked(vpn, base);
    }
}

void vm32_record_map(uint32_t start_gva, uint32_t end_gva, uint8_t prot,
    uint8_t state)
{
    uint32_t first;
    uint32_t last;
    uint32_t vpn;
    uintptr_t base;

    if (state > VM32_PAGE_SHARED) {
        state = (uint8_t)VM32_PAGE_ANON;
    }
    if (!clamp_range(start_gva, end_gva, &first, &last)) {
        return;
    }
    prot = (uint8_t)((uint32_t)prot &
        ((uint32_t)PROT_READ | (uint32_t)PROT_WRITE));
    base = vm32_arena_base();
    tlb_lock();
    for (vpn = first; vpn < last; vpn++) {
        g_page_prot[vpn] = prot;
        g_page_state[vpn] = state;
        tlb_refresh_slot_locked(vpn, base);
    }
    tlb_unlock();
}

void vm32_record_protect(uint32_t start_gva, uint32_t end_gva,
    uint8_t prot)
{
    uint32_t first;
    uint32_t last;
    uint32_t vpn;
    uintptr_t base;

    if (!clamp_range(start_gva, end_gva, &first, &last)) {
        return;
    }
    prot = (uint8_t)((uint32_t)prot &
        ((uint32_t)PROT_READ | (uint32_t)PROT_WRITE));
    base = vm32_arena_base();
    tlb_lock();
    for (vpn = first; vpn < last; vpn++) {
        g_page_prot[vpn] = prot;
        tlb_refresh_slot_locked(vpn, base);
    }
    tlb_unlock();
}

/* Mark pages beyond a shrunk EOF as EOF_TRAP: accesses trap (the
 * state is neither readable-map nor writable, so probes miss and the
 * fault path delivers SIGBUS), while the identity survives for a later
 * regrow, which re-populates and re-records the range. */
void vm32_mark_eof_trap(uint32_t start_gva, uint32_t end_gva)
{
    uint32_t first;
    uint32_t last;
    uint32_t vpn;
    uintptr_t base;

    if (!clamp_range(start_gva, end_gva, &first, &last)) {
        return;
    }
    base = vm32_arena_base();
    tlb_lock();
    for (vpn = first; vpn < last; vpn++) {
        g_page_prot[vpn] = 0U;
        g_page_state[vpn] = (uint8_t)VM32_PAGE_EOF_TRAP;
        tlb_refresh_slot_locked(vpn, base);
    }
    tlb_unlock();
    /* Narrow fully-covered host pages to PROT_NONE so direct (A1) and
     * faulting accesses trap instead of reading stale bytes. Mirrors
     * the unmap path; on H == 4096 the sync is a no-op. */
    (void)vm32_sync_host_range(start_gva, end_gva);
}

bool vm32_page_is_eof_trap(uint32_t gva)
{
    uint32_t vpn = gva >> 12U;
    bool trapped;

    if (vpn >= VM32_PAGE_COUNT) {
        return false;
    }
    tlb_lock();
    trapped = (g_page_state[vpn] == (uint8_t)VM32_PAGE_EOF_TRAP);
    tlb_unlock();
    return trapped;
}

void vm32_record_unmap(uint32_t start_gva, uint32_t end_gva)
{
    uint32_t first;
    uint32_t last;
    uint32_t vpn;
    uintptr_t base;

    if (!clamp_range(start_gva, end_gva, &first, &last)) {
        return;
    }
    base = vm32_arena_base();
    tlb_lock();
    for (vpn = first; vpn < last; vpn++) {
        g_page_prot[vpn] = 0U;
        g_page_state[vpn] = (uint8_t)VM32_PAGE_UNMAPPED;
        tlb_refresh_slot_locked(vpn, base);
    }
    tlb_unlock();
}

void vm32_note_cow_dirty(uint32_t gva_page)
{
    uint32_t vpn = gva_page >> 12U;
    uintptr_t base;

    if (vpn >= VM32_PAGE_COUNT) {
        return;
    }
    base = vm32_arena_base();
    tlb_lock();
    if (g_page_state[vpn] == VM32_PAGE_COW_CLEAN) {
        g_page_state[vpn] = (uint8_t)VM32_PAGE_COW_DIRTY;
    }
    /* Refill (or evict when no arena is published) so the promotion
     * is visible to the very next probe without a forced miss. */
    tlb_refresh_slot_locked(vpn, base);
    tlb_unlock();
}

/* Union of mapped sub-pages' R/W bits over one host page starting at
 * guest page vpn_first (vpn_first holds H / 4096 sub-pages). Caller
 * holds tlb_lock. Never includes PROT_EXEC (W^X). */
static int host_union_locked(uint32_t vpn_first, uint32_t sub_pages)
{
    uint32_t k;
    int uni = 0;

    for (k = 0U; k < sub_pages; k++) {
        uint32_t vpn = vpn_first + k;

        if (vpn >= VM32_PAGE_COUNT) {
            break;
        }
        if (g_page_state[vpn] == VM32_PAGE_UNMAPPED) {
            continue;
        }
        uni |= (int)(g_page_prot[vpn] &
            (uint8_t)((uint32_t)PROT_READ | (uint32_t)PROT_WRITE));
    }
    return uni;
}

int vm32_sync_host_range(uint32_t start_gva, uint32_t end_gva)
{
    size_t host_page;
    uint32_t subs_per_host;
    uintptr_t base;
    uint64_t first_hp;
    uint64_t last_hp;
    uint64_t hp;

    if (end_gva <= start_gva) {
        return 0;
    }
    host_page = vm32_host_page_size();
    if (host_page <= (size_t)VM32_GUEST_PAGE_SIZE) {
        return 0;
    }
    base = vm32_arena_base();
    if (base == 0U) {
        return 0;
    }
    subs_per_host = (uint32_t)(host_page / (size_t)VM32_GUEST_PAGE_SIZE);
    first_hp = (uint64_t)start_gva / (uint64_t)host_page;
    last_hp = ((uint64_t)end_gva + (uint64_t)host_page - 1U) /
        (uint64_t)host_page;
    tlb_lock();
    for (hp = first_hp; hp < last_hp; hp++) {
        uint64_t vpn_first64 = hp * (uint64_t)subs_per_host;
        void *host_addr;
        int uni;

        if (vpn_first64 >= (uint64_t)VM32_PAGE_COUNT) {
            break;
        }
        uni = host_union_locked((uint32_t)vpn_first64, subs_per_host);
        host_addr = (void *)(base + hp * (uint64_t)host_page);
        if (mprotect(host_addr, host_page, uni) != 0) {
            int e = errno;

            tlb_unlock();
            return -e;
        }
    }
    tlb_unlock();
    return 0;
}

int vm32_protect_union(uint32_t start_gva, uint32_t len, uint8_t prot)
{
    uint64_t end64;
    int rc;

    if (len == 0U) {
        return 0;
    }
    end64 = (uint64_t)start_gva + (uint64_t)len;
    if (end64 > (uint64_t)VM32_WINDOW_SIZE) {
        return -EINVAL;
    }
    vm32_record_protect(start_gva, (uint32_t)end64, prot);
    rc = vm32_sync_host_range(start_gva, (uint32_t)end64);
    return rc;
}

int vm32_unmap_union(uint32_t start_gva, uint32_t len)
{
    uint64_t end64;
    int rc;

    if (len == 0U) {
        return 0;
    }
    end64 = (uint64_t)start_gva + (uint64_t)len;
    if (end64 > (uint64_t)VM32_WINDOW_SIZE) {
        return -EINVAL;
    }
    vm32_record_unmap(start_gva, (uint32_t)end64);
    rc = vm32_sync_host_range(start_gva, (uint32_t)end64);
    return rc;
}
