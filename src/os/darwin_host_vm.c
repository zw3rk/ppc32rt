/*
 * src/os/darwin_host_vm.c — G02 VMA mirrors + SYNC_VM_PROT (A32H 1.2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The vm32 page tables are global (keyed by guest VA) while the legacy
 * ctx->regions mirror is per context, so SYNC_VM_PROT keeps every
 * registered mirror (main + workers) consistent under the bridge mutex.
 * prot == 0 is a true unmap: fresh PROT_NONE anon (stale bytes gone),
 * vm32 record dropped, mirrors carved, TLB + DBT invalidated. Later
 * re-maps read fresh zeros and faults report unmapped (fault_is_prot
 * = 0). All VA+len math is 64-bit so wrapped 32-bit sums can never
 * escape the 4 GiB window.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/darwin_bridge_priv.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include "dbt/dbt.h"
#include "vm/vm32.h"

#define DARWIN_MAX_CTX (1U + 8U)

static ppc32_ctx_t *g_mirrors[DARWIN_MAX_CTX];
static size_t g_mirror_n;

void bridge_mirror_add(ppc32_ctx_t *ctx)
{
    size_t k;

    for (k = 0U; k < g_mirror_n; k++) {
        if (g_mirrors[k] == ctx) {
            return;
        }
    }
    if (g_mirror_n < DARWIN_MAX_CTX) {
        g_mirrors[g_mirror_n++] = ctx;
    }
}

void bridge_mirror_remove(ppc32_ctx_t *ctx)
{
    size_t k;

    for (k = 0U; k < g_mirror_n; k++) {
        if (g_mirrors[k] == ctx) {
            g_mirrors[k] = g_mirrors[--g_mirror_n];
            g_mirrors[g_mirror_n] = NULL;
            return;
        }
    }
}

void bridge_mirrors_reset(void)
{
    g_mirror_n = 0U;
}

/* Guest->host protection for the [G, G+4GiB) window (W^X: guest EXEC
 * never maps host EXEC; EXEC implies READ so code stays fetchable). */
static int bridge_host_prot(uint32_t prot)
{
    uint32_t q = prot & 7U;
    int hp = 0;

    if ((q & 4U) != 0U) {
        q |= 1U;
    }
    if ((q & 2U) != 0U) {
        q &= ~4U;
    }
    if ((q & 1U) != 0U) {
        hp |= PROT_READ;
    }
    if ((q & 2U) != 0U) {
        hp |= PROT_WRITE;
    }
    return hp;
}

/* Push the recorded guest protections of [va, end) to the host:
 * union sync on A2 (one 16K/64K host page spans several 4 KiB guest
 * sub-pages), exact mprotect on A1 (4 KiB 1:1). Contents are kept. */
static void bridge_protect_host(uint64_t window_base, uint32_t va,
    uint32_t len, uint32_t prot)
{
    uint64_t end64 = (uint64_t)va + (uint64_t)len;

    if (len == 0U || window_base == 0U || end64 > 0x100000000ULL) {
        return;
    }
    if (vm32_is_a2()) {
        (void)vm32_sync_host_range(va, (uint32_t)end64);
        return;
    }
    (void)mprotect((void *)(uintptr_t)(window_base + (uint64_t)va),
        (size_t)len, bridge_host_prot(prot));
}

void bridge_register_vma(uint32_t va, uint32_t end, uint8_t prot,
    uint64_t window_base)
{
    size_t m;

    vm32_record_map(va, end, prot, (uint8_t)VM32_PAGE_ANON);
    if ((prot & 4U) != 0U) {
        vm32_mark_guest_exec(va, end);
    }
    for (m = 0U; m < g_mirror_n; m++) {
        ppc32_ctx_t *c = g_mirrors[m];

        if (c->region_count < PPC32_MAX_REGIONS) {
            ppc32_region_t *r = &c->regions[c->region_count++];

            r->start = va;
            r->end = end;
            r->prot = prot;
            r->flags = 0U;
            r->fd = -1;
            r->offset = 0U;
            r->name[0] = '\0';
        }
    }
    bridge_protect_host(window_base, va, end - va, prot);
}

/* Sort and coalesce adjacent same-prot mirror regions so repeated
 * mprotect calls cannot fragment a context past PPC32_MAX_REGIONS. */
static void mirror_coalesce(ppc32_ctx_t *m)
{
    size_t i;
    size_t j;
    size_t out = 0U;

    for (i = 1U; i < m->region_count; i++) {
        ppc32_region_t cur = m->regions[i];

        j = i;
        while (j > 0U && m->regions[j - 1U].start > cur.start) {
            m->regions[j] = m->regions[j - 1U];
            j--;
        }
        m->regions[j] = cur;
    }
    for (i = 0U; i < m->region_count; i++) {
        if (out > 0U &&
            m->regions[out - 1U].end == m->regions[i].start &&
            m->regions[out - 1U].prot == m->regions[i].prot) {
            m->regions[out - 1U].end = m->regions[i].end;
        } else {
            m->regions[out++] = m->regions[i];
        }
    }
    m->region_count = out;
}

/* Set [va, end) to prot p in one mirror: carve overlapping regions
 * into non-overlapping pieces, append the exact range, and coalesce. */
static void mirror_set_prot(ppc32_ctx_t *m, uint32_t va, uint32_t end,
    uint8_t p)
{
    ppc32_region_t kept[PPC32_MAX_REGIONS];
    size_t n = 0U;
    size_t i;

    for (i = 0U; i < m->region_count; i++) {
        uint32_t s = m->regions[i].start;
        uint32_t e = m->regions[i].end;

        if (e <= va || s >= end) {
            if (n < PPC32_MAX_REGIONS) {
                kept[n++] = m->regions[i];
            }
            continue;
        }
        if (s < va && n < PPC32_MAX_REGIONS) {
            kept[n] = m->regions[i];
            kept[n].end = va;
            n++;
        }
        if (e > end && n < PPC32_MAX_REGIONS) {
            kept[n] = m->regions[i];
            kept[n].start = end;
            n++;
        }
    }
    if (n < PPC32_MAX_REGIONS) {
        ppc32_region_t *r = &kept[n++];

        r->start = va;
        r->end = end;
        r->prot = p;
        r->flags = 0U;
        r->fd = -1;
        r->offset = 0U;
        r->name[0] = '\0';
    }
    memcpy(m->regions, kept, n * sizeof kept[0]);
    m->region_count = n;
    mirror_coalesce(m);
}

/* Remove [va, end) from one mirror (unmap path). */
static void mirror_carve_remove(ppc32_ctx_t *m, uint32_t va, uint32_t end)
{
    ppc32_region_t kept[PPC32_MAX_REGIONS];
    size_t n = 0U;
    size_t i;

    for (i = 0U; i < m->region_count; i++) {
        uint32_t s = m->regions[i].start;
        uint32_t e = m->regions[i].end;

        if (e <= va || s >= end) {
            if (n < PPC32_MAX_REGIONS) {
                kept[n++] = m->regions[i];
            }
            continue;
        }
        if (s < va && n < PPC32_MAX_REGIONS) {
            kept[n] = m->regions[i];
            kept[n].end = va;
            n++;
        }
        if (e > end && n < PPC32_MAX_REGIONS) {
            kept[n] = m->regions[i];
            kept[n].start = end;
            n++;
        }
    }
    memcpy(m->regions, kept, n * sizeof kept[0]);
    m->region_count = n;
}

/* Is [va, end64) fully covered by mapped 4 KiB pages in vm32? */
static bool bridge_range_mapped(uint32_t va, uint64_t end64)
{
    uint64_t pg = (uint64_t)va & ~0xFFFULL;
    uint64_t end_pg;

    if (end64 <= (uint64_t)va || end64 > 0x100000000ULL) {
        return end64 == (uint64_t)va;
    }
    end_pg = (end64 + 0xFFFULL) & ~0xFFFULL;
    if (end_pg > 0x100000000ULL) {
        end_pg = 0x100000000ULL;
    }
    while (pg < end_pg) {
        if (!vm32_page_query((uint32_t)pg, NULL)) {
            return false;
        }
        pg += 0x1000ULL;
    }
    return true;
}

void bridge_apply_sync_prot(ppc32_ctx_t *caller_ctx, uint32_t va,
    uint32_t len, uint32_t prot)
{
    uint64_t end64 = (uint64_t)va + (uint64_t)len;
    uint8_t p = (uint8_t)(prot & 7U);
    uint32_t end32;
    size_t m;

    if (len == 0U || end64 > 0x100000000ULL || g_mirror_n == 0U) {
        return;
    }
    end32 = (end64 >= 0x100000000ULL) ? 0xFFFFFFFFU : (uint32_t)end64;
    if (p == 0U) {
        /* munmap: clear stale bytes, drop the vm32 record, recompute host
         * protections (A2 sub-page union or A1 exact MAP_FIXED PROT_NONE),
         * carve every mirror, and invalidate TLB + DBT (cache.c bumps
         * g_cache_epoch globally under s_cache_lock; only caller_ctx's own
         * IBTC/RAS is cleared synchronously so sibling threads are never
         * poked cross-thread). */
        uint64_t s64 = (uint64_t)va & ~0xFFFULL;
        uint64_t e64 = (end64 + 0xFFFULL) & ~0xFFFULL;
        uint64_t gbase = g_mirrors[0]->guest_base;
        uint32_t s32;
        uint32_t e32;

        if (e64 > 0x100000000ULL) {
            e64 = 0x100000000ULL;
        }
        if (e64 <= s64 || gbase == 0U) {
            return;
        }
        s32 = (uint32_t)s64;
        e32 = (e64 >= 0x100000000ULL) ? 0xFFFFFFFFU : (uint32_t)e64;
        if (vm32_is_a2()) {
            size_t hp = vm32_host_page_size();
            uint64_t hs = s64 & ~(uint64_t)(hp - 1U);
            uint64_t he = (e64 + (uint64_t)hp - 1ULL) & ~(uint64_t)(hp - 1U);

            if (he > 0x100000000ULL) {
                he = 0x100000000ULL;
            }
            if (mprotect((void *)(uintptr_t)(gbase + hs), (size_t)(he - hs),
                PROT_READ | PROT_WRITE) != 0) {
                return;
            }
            memset((void *)(uintptr_t)(gbase + s64), 0, (size_t)(e64 - s64));
            vm32_record_unmap(s32, e32);
            (void)vm32_sync_host_range(s32, e32);
        } else {
            void *at = mmap((void *)(uintptr_t)(gbase + s64),
                (size_t)(e64 - s64), PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

            if (at == MAP_FAILED) {
                return;
            }
            vm32_record_unmap(s32, e32);
        }
        vm32_ll_note_remap();
        for (m = 0U; m < g_mirror_n; m++) {
            mirror_carve_remove(g_mirrors[m], s32, e32);
        }
        vm32_tlb_invalidate_range(s32, e32);
        ppc32_dbt_invalidate_range(caller_ctx, s32, e32);
        return;
    }
    if (!bridge_range_mapped(va, end64)) {
        /* Fresh mapping (unmapped-fault recovery): publish the range
         * before syncing host protections so the A2 union sees it. */
        vm32_record_map(va, end32, p, (uint8_t)VM32_PAGE_ANON);
        if ((p & 4U) != 0U) {
            vm32_mark_guest_exec(va, end32);
        }
        for (m = 0U; m < g_mirror_n; m++) {
            mirror_set_prot(g_mirrors[m], va, end32, p);
        }
    } else {
        vm32_record_protect(va, end32, p);
        if ((p & 4U) != 0U) {
            vm32_mark_guest_exec(va, end32);
        }
        for (m = 0U; m < g_mirror_n; m++) {
            mirror_set_prot(g_mirrors[m], va, end32, p);
        }
    }
    bridge_protect_host(g_mirrors[0]->guest_base, va, len, p);
    vm32_tlb_invalidate_range(va, end32);
    ppc32_dbt_invalidate_range(caller_ctx, va, end32);
}

/* Handler code patch for G02 SMC (test_a stub rewrite): bytes written
 * straight through the host mapping bypass the guest store path (and
 * the DBT SMC hook), so widen the covering host pages, copy, and
 * restore the recorded protections (A2 union, A1 exact). The caller
 * still replies FLUSH_ICACHE so translated blocks covering
 * [va, va+len) are dropped. Only for in-process handlers. */
int ppc32_darwin_patch_code(uint64_t window_base, uint32_t va,
    const void *src, size_t len, uint32_t restore_prot)
{
    size_t hp;
    uint64_t s;
    uint64_t e;

    if (src == NULL || len == 0U || window_base == 0U) {
        return -EINVAL;
    }
    hp = vm32_host_page_size();
    if (hp == 0U || (hp & (hp - 1U)) != 0U) {
        return -ENOSYS;
    }
    s = (uint64_t)va & ~(uint64_t)(hp - 1U);
    e = ((uint64_t)va + (uint64_t)len + (uint64_t)hp - 1U) &
        ~(uint64_t)(hp - 1U);
    if (e <= s || e > 0x100000000ULL) {
        return -EINVAL;
    }
    if (mprotect((void *)(uintptr_t)(window_base + s), (size_t)(e - s),
        PROT_READ | PROT_WRITE) != 0) {
        return -errno;
    }
    memcpy((void *)(uintptr_t)(window_base + (uint64_t)va), src, len);
    if (vm32_is_a2()) {
        (void)vm32_sync_host_range((uint32_t)s, (uint32_t)e);
    } else if (mprotect((void *)(uintptr_t)(window_base + s),
        (size_t)(e - s), bridge_host_prot(restore_prot)) != 0) {
        return -errno;
    }
    return 0;
}
