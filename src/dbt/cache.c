/*
 * src/dbt/cache.c — Translation-cache storage for the AArch64 DBT
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Direct-mapped cache of 1024 translated blocks keyed by guest NIP
 * (identity key, no T bit). Each block owns one executable mapping:
 * emitted RW into a staging copy, then mprotect(PROT_READ|PROT_EXEC)
 * plus __builtin___clear_cache before first execution (W^X: the mapping
 * is never writable and executable at the same time, and guest data
 * pages are never PROT_EXEC). Eviction munmaps immediately; every
 * invalidation path severs IBTC/RAS/slot pointers first so no emitted
 * chaining jump can observe a dangling code pointer.
 *
 * Invalidation is page-versioned: every guest page carries a version
 * bumped by ppc32_cache_invalidate_range; a cached block records the
 * version sampled at install and misses when it disagrees. Range
 * invalidation additionally evicts overlapping blocks eagerly (so slots
 * are reusable) and severs every ctx IBTC/RAS entry whose key falls in
 * [start, end). invalidate_all bumps the global epoch instead, which
 * retires every emitted epoch check at once.
 *
 * Phase 7 H1 (SMC): guest stores to translated pages are observed two
 * ways. (1) Every natively-emitted guest store carries a post-store
 * hook (emitted by src/dbt/dbt.c) calling ppc32_smc_store with the
 * exact [EA, EA+len); the range is evicted and severed eagerly, so a
 * chained re-entry can never run stale bytes. The currently-executing
 * entry is link-severed but never unmapped (a block rewriting itself
 * finishes its TB-atomic remainder, exactly like qemu). (2) Every
 * installed block records its guest [start, end) plus a byte snapshot
 * (ppc32_cache_record_guest, called from dbt.c); dispatch lookups
 * re-verify the snapshot and evict on mismatch, covering interpreter
 * single-step stores, difftest restores, and any out-of-band change.
 * Snapshot words ride in the block's spare pad words (pad0[1..3]); no
 * struct layout change. Guest data pages stay non-PROT_EXEC on the
 * host throughout (ppc32_host_prot strips X); only the JIT's own
 * mappings are ever PROT_EXEC.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#endif
#include <pthread.h>
#include <unistd.h>

#include "dbt/aot/aot_run.h"
#include "dbt/dbt.h"
#include "os/threads.h"
#include "rt32/ppc32.h"

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

/* One version word per guest page (1M pages over the 4 GiB window). */
#define PPC32_DBT_NPAGES (0x100000000ULL / 4096ULL)

static ppc32_block_t *s_table[PPC32_DBT_HT_SIZE];
static uint32_t s_page_ver[PPC32_DBT_NPAGES];
/* P32-R6-1: atomic generation counter observed by JIT epoch checks and
 * by dbt.c IBTC/RAS sync. All accesses use __atomic builtins; the
 * pointer exposed via ppc32_cache_epoch_ptr stays a plain uint32_t*. */
static uint32_t g_cache_epoch = 1U;
/* P32-R6-1: serializes lookup/install/invalidation. Held only for
 * table/pagever/epoch/retire-list mutation; mmap/mprotect and guest
 * byte copies happen outside it where noted. */
static pthread_mutex_t s_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t cache_epoch_load(void)
{
    return __atomic_load_n(&g_cache_epoch, __ATOMIC_ACQUIRE);
}

static void cache_epoch_bump(void)
{
    uint32_t next =
        __atomic_fetch_add(&g_cache_epoch, 1U, __ATOMIC_ACQ_REL) + 1U;

    if (next == 0U) {
        __atomic_store_n(&g_cache_epoch, 1U, __ATOMIC_RELEASE);
    }
}

/* P32-R6-1: deferred code reclamation. Evicted blocks are unlinked and
 * link-severed under lock but their host mappings stay live until a
 * later generation, so threads already executing them never observe
 * a munmap underfoot. Nodes carry the post-bump epoch; reclaim frees
 * only nodes from older generations. */
typedef struct retired_node {
    ppc32_block_t *blk;
    uint32_t epoch;
    struct retired_node *next;
} retired_node_t;

static retired_node_t *s_retired = NULL;

/* P32-R6-1: dispatcher sync registry for quiescent reclamation. Every
 * syncing/looking-up/installing ctx is tracked with its last synced
 * generation; a retired block is freed only after all tracked peers
 * synced past it (or when single-threaded). Epochs are by value, so
 * stale slots only delay freeing; forget_ctx releases dead slots, and
 * a full table latches overflow to stall freeing conservatively. */
#define PPC32_CACHE_MAX_REG 32U
static ppc32_ctx_t *s_reg_ctx[PPC32_CACHE_MAX_REG];
static uint32_t s_reg_epoch[PPC32_CACHE_MAX_REG];
static bool s_reg_overflow = false;

/* Caller holds s_cache_lock. */
static void reg_ctx_locked(ppc32_ctx_t *ctx, uint32_t cur)
{
    size_t i;

    if (ctx == NULL) {
        return;
    }
    ctx->ibtc_synced_epoch = cur;
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] == ctx) {
            s_reg_epoch[i] = cur;
            return;
        }
    }
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] == NULL) {
            s_reg_ctx[i] = ctx;
            s_reg_epoch[i] = cur;
            return;
        }
    }
    s_reg_overflow = true;
}

static void block_free_now(ppc32_block_t *e);

static void retire_block_locked(ppc32_block_t *e, uint32_t epoch)
{
    retired_node_t *n;

    if (e == NULL) {
        return;
    }
    __atomic_store_n(&e->keyepoch, 0ULL, __ATOMIC_RELEASE);
    n = (retired_node_t *)malloc(sizeof(*n));
    if (n == NULL) {
        /* OOM: leak the mapping rather than unmapping live code. */
        return;
    }
    n->blk = e;
    n->epoch = epoch;
    n->next = s_retired;
    s_retired = n;
}

/* Caller holds s_cache_lock. Frees only generations no thread can run:
 * single-threaded has no peer in chained code, otherwise every tracked
 * dispatcher must have synced past the retired node. */
static void reclaim_retired_locked(uint32_t cur)
{
    retired_node_t **pp = &s_retired;
    bool single = (ppc32_thread_count() <= 1U);
    bool quiet = !s_reg_overflow;

    while (*pp != NULL) {
        retired_node_t *n = *pp;
        bool freeable = false;

        if (n->epoch != cur) {
            freeable = single;
            if (!freeable && quiet) {
                size_t i;

                freeable = true;
                for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
                    if (s_reg_ctx[i] != NULL &&
                        s_reg_epoch[i] <= n->epoch) {
                        freeable = false;
                        break;
                    }
                }
            }
        }
        if (freeable) {
            *pp = n->next;
            block_free_now(n->blk);
            free(n);
        } else {
            pp = &n->next;
        }
    }
}

/* RC-H perf: one occupancy bit per guest 4 KiB page (1M bits = 128 KiB).
 * Set when a translated range covers the page, cleared only by
 * invalidate_all (which evicts everything, so the map is exact again
 * afterwards). The H1 post-store hook consults it first: a store to
 * pages with no translated code returns without the two full-table
 * sweeps (the common case — data pages never hold code). Stale set bits
 * (range eviction and replacement eviction do not clear) only cause
 * extra sweeps, never a missed invalidation: marks are a superset of
 * live-block pages, so an unmarked page provably holds no live block.
 * Range-granular clearing is deliberately absent: see the NOTE in
 * ppc32_cache_invalidate_range_skip. */
#define PPC32_CODE_PAGE_WORDS (PPC32_DBT_NPAGES / 64U)

static uint64_t s_code_pages[PPC32_CODE_PAGE_WORDS];

static void code_pages_mark(uint32_t start, uint32_t end)
{
    uint32_t pg;

    if (end <= start) {
        return;
    }
    for (pg = start >> 12U; ; pg++) {
        s_code_pages[pg >> 6U] |= 1ULL << (pg & 63U);
        if (pg == ((end - 1U) >> 12U) || pg == 0xFFFFFU) {
            break;
        }
    }
}

static bool code_pages_any(uint32_t start, uint32_t end)
{
    uint32_t pg;

    if (end <= start) {
        return false;
    }
    for (pg = start >> 12U; ; pg++) {
        if ((s_code_pages[pg >> 6U] & (1ULL << (pg & 63U))) != 0ULL) {
            return true;
        }
        if (pg == ((end - 1U) >> 12U) || pg == 0xFFFFFU) {
            break;
        }
    }
    return false;
}

uint32_t *ppc32_cache_epoch_ptr(void)
{
    return &g_cache_epoch;
}

/* P1 inline-guard base (see dbt_emit_smc_hook in dbt.c): the bitmap
 * address is fixed for the process lifetime; invalidate_all clears the
 * bits in place, so baked-in addresses stay valid. */
const uint64_t *ppc32_code_pages_base(void)
{
    return s_code_pages;
}

static uint32_t cache_index(uint32_t pc)
{
    return (pc >> 2U) & (PPC32_DBT_HT_SIZE - 1U);
}

/* Fill the ctx IBTC slot for pc from a live cache entry (also heals a
 * slot collided by an unrelated block). Caller holds s_cache_lock when
 * the entry comes from the shared table; the slot itself is ctx-local. */
static void ibtc_fill(ppc32_ctx_t *ctx, uint32_t pc, ppc32_block_t *e)
{
    ppc32_ibtc_entry_t *slot;

    if (ctx == NULL || e == NULL) {
        return;
    }
    slot = &ctx->ibtc[ppc32_ibtc_hash(pc)];
    slot->key = pc;
    slot->epoch = cache_epoch_load();
    slot->host_code = e->host_code;
    /* The inline IBTC probe loads {key|epoch, host_code} from *entry,
     * so entry must be the block pointer, not the code address. */
    slot->entry = (void *)e;
    slot->pad = 0U;
}

/* Sever every link that can reach entry `victim`: direct-chain slots
 * and call fallthroughs across the whole table. */
static void sever_links_to(ppc32_block_t *victim)
{
    size_t i;
    unsigned s;

    for (i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        ppc32_block_t *e = s_table[i];

        if (e == NULL || e == victim) {
            continue;
        }
        for (s = 0U; s < 8U; s++) {
            if (e->slot_entry[s] == victim) {
                e->slot_entry[s] = NULL;
            }
        }
        if (e->ret_entry == victim) {
            e->ret_entry = NULL;
        }
    }
}

/* Sever ctx IBTC/RAS entries whose key lies in [start, end). */
static void sever_ctx_range(ppc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    size_t i;

    if (ctx == NULL) {
        return;
    }
    for (i = 0U; i < PPC32_IBTC_SIZE; i++) {
        ppc32_ibtc_entry_t *s = &ctx->ibtc[i];

        if (s->key >= start && s->key < end) {
            s->host_code = NULL;
            s->entry = NULL;
        }
    }
    for (i = 0U; i < PPC32_RAS_SIZE; i++) {
        ppc32_ibtc_entry_t *s = &ctx->ras[i];

        if (s->key >= start && s->key < end) {
            s->host_code = NULL;
            s->entry = NULL;
        }
    }
}

/* Only called for retired generations no thread can enter via the
 * table/links/IBTC any more; the one-generation grace in retire/reclaim
 * keeps live execution safe. */
static void block_free_now(ppc32_block_t *e)
{
    if (e == NULL) {
        return;
    }
    if (e->host_code != NULL) {
        /* Install records the whole-page span in pad0[0]. */
        size_t len = (size_t)e->pad0[0];

        if (len != 0U) {
            (void)munmap(e->host_code, len);
        }
    }
    /* H1 SMC snapshot (pad0[3]); NULL when never recorded. */
    free((void *)(uintptr_t)e->pad0[3]);
    free(e);
}

/* Caller holds s_cache_lock. */
static ppc32_block_t *lookup_valid_locked(uint32_t pc)
{
    ppc32_block_t *e = s_table[cache_index(pc)];

    if (e == NULL || !e->occupied || e->guest_pc != pc) {
        return NULL;
    }
    if (e->pagever != s_page_ver[pc >> 12U]) {
        return NULL;
    }
    if ((uint32_t)(e->keyepoch >> 32U) != cache_epoch_load()) {
        return NULL;
    }
    if (e->host_code == NULL || e->entry == NULL) {
        return NULL;
    }
    return e;
}

/* H1 SMC: record the guest byte range a block was translated from,
 * plus a snapshot copy. dbt.c calls this right after install, while
 * the bytes just fetched are still current. Empty ranges (fallback
 * single-exit blocks) record no snapshot and always verify clean. */
void ppc32_cache_record_guest(ppc32_ctx_t *ctx, ppc32_block_t *e,
    uint32_t start, uint32_t end)
{
    uint64_t len;
    uint8_t *snap = NULL;

    if (e == NULL) {
        return;
    }
    len = (uint64_t)end - (uint64_t)start;
    if (ctx != NULL && ctx->vm_ready && end > start && len <= 4096ULL) {
        snap = (uint8_t *)malloc((size_t)len);
        if (snap != NULL) {
            memcpy(snap, ppc32_guest_ptr(ctx, start), (size_t)len);
        }
    }
    /* Every install path funnels through here: mark the covered pages
     * (even past the 4096 snapshot cap — the store hook must still
     * evict over-long blocks by range overlap). Empty ranges mark
     * nothing. Shared bitmap and block range publish under lock. */
    (void)pthread_mutex_lock(&s_cache_lock);
    code_pages_mark(start, end);
    e->pad0[1] = (uint64_t)start;
    e->pad0[2] = (uint64_t)end;
    /* H1 SMC snapshot (pad0[3]); NULL when never recorded. */
    free((void *)(uintptr_t)e->pad0[3]);
    e->pad0[3] = (uint64_t)(uintptr_t)snap;
    snap = NULL;
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* H1 SMC: verify the recorded guest bytes are still current. True
 * when no snapshot was recorded, or the bytes still match. Caller
 * holds s_cache_lock; the guest read uses the VM safe copy
 * (range-checked under the VM lock, never a raw fault), so a
 * concurrent munmap reports -EFAULT instead of siglongjmp'ing with
 * s_cache_lock held. Lock order stays cache -> VM (guest mm ops
 * invalidate only after releasing the VM lock). An unreadable range
 * counts dirty, so the caller evicts and retranslates into a fault. */
static bool snapshot_clean(ppc32_ctx_t *ctx, const ppc32_block_t *e)
{
    const uint8_t *snap;
    uint64_t len;
    uint32_t start;
    uint8_t buf[4096];

    if (ctx == NULL || e == NULL) {
        return true;
    }
    snap = (const uint8_t *)(uintptr_t)e->pad0[3];
    if (snap == NULL) {
        return true;
    }
    len = e->pad0[2] - e->pad0[1];
    if (len == 0ULL || len > 4096ULL || !ctx->vm_ready) {
        return true;
    }
    start = (uint32_t)e->pad0[1];
    if (ppc32_vm_copyin_safe(ctx, start, buf, (size_t)len) != 0) {
        return false;
    }
    return memcmp(snap, buf, (size_t)len) == 0;
}

/* Internal range invalidation; caller holds s_cache_lock. Severs and
 * retires overlapping blocks without unmapping live code, bumps the
 * generation once, and reclaims the previous generation. */
static void invalidate_range_skip_locked(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end, ppc32_block_t *skip);

/* P32-R6-1: serialized lookup. Snapshot mismatch evicts via the locked
 * path so no nested lock is taken. */
ppc32_block_t *ppc32_cache_lookup(ppc32_ctx_t *ctx, uint32_t pc)
{
    ppc32_block_t *e;

    (void)pthread_mutex_lock(&s_cache_lock);
    e = lookup_valid_locked(pc);
    if (e != NULL) {
        if (!snapshot_clean(ctx, e)) {
            uint32_t rs = (uint32_t)e->pad0[1];
            uint32_t re = (uint32_t)e->pad0[2];

            if (re > rs) {
                invalidate_range_skip_locked(ctx, rs, re, NULL);
            }
            (void)pthread_mutex_unlock(&s_cache_lock);
            return NULL;
        }
        ibtc_fill(ctx, pc, e);
    }
    (void)pthread_mutex_unlock(&s_cache_lock);
    return e;
}

/* Resolve a pc to a live entry without translating (slots/ret fill).
 * Caller holds s_cache_lock. */
static ppc32_block_t *lookup_nofill_locked(uint32_t pc)
{
    return lookup_valid_locked(pc);
}

ppc32_block_t *ppc32_cache_install(ppc32_ctx_t *ctx, uint32_t pc,
    const uint32_t *words, size_t nwords, const uint32_t *slot_pcs,
    unsigned nslots, bool is_call, uint32_t ret_pc)
{
    ppc32_block_t *e;
    size_t span;
    size_t pagesz;
    void *code;

    if (words == NULL || nwords == 0U) {
        return NULL;
    }
    if (nslots > 8U) {
        nslots = 8U;
    }
    e = (ppc32_block_t *)calloc(1, sizeof(*e));
    if (e == NULL) {
        return NULL;
    }
    pagesz = (size_t)sysconf(_SC_PAGESIZE);
    if (pagesz == 0U) {
        pagesz = 4096U;
    }
    span = ((nwords * sizeof(uint32_t)) + pagesz - 1U) & ~(pagesz - 1U);
#ifdef __APPLE__
    code = mmap(NULL, span, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (code == MAP_FAILED) {
        free(e);
        return NULL;
    }
    pthread_jit_write_protect_np(0);
    memcpy(code, words, nwords * sizeof(uint32_t));
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(code, nwords * sizeof(uint32_t));
#else
    code = mmap(NULL, span, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        free(e);
        return NULL;
    }
    memcpy(code, words, nwords * sizeof(uint32_t));
    /* W^X flip before any host fetch: drop WRITE, add EXEC, then flush
     * the I-cache over the exact emitted span. */
    if (mprotect(code, span, PROT_READ | PROT_EXEC) != 0) {
        (void)munmap(code, span);
        free(e);
        return NULL;
    }
    __builtin___clear_cache((char *)code,
        (char *)code + nwords * sizeof(uint32_t));
#endif

    /* P32-R6-1: table mutation under lock. The executable mapping is
     * already sealed above; eviction retires (never munmaps live code)
     * and bumps the generation so other threads stop entering it. */
    {
        uint32_t idx = cache_index(pc);
        ppc32_block_t *old;
        unsigned s;
        size_t i;
        uint32_t cur;

        (void)pthread_mutex_lock(&s_cache_lock);
        old = s_table[idx];
        if (old != NULL) {
            uint32_t old_pc = old->guest_pc;

            sever_links_to(old);
            s_table[idx] = NULL;
            cache_epoch_bump();
            cur = cache_epoch_load();
            retire_block_locked(old, cur);
            for (i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
                ppc32_block_t *o = s_table[i];

                if (o != NULL && o->occupied &&
                    o->pagever == s_page_ver[o->guest_pc >> 12U]) {
                    __atomic_store_n(&o->keyepoch,
                        (uint64_t)o->guest_pc | ((uint64_t)cur << 32U),
                        __ATOMIC_RELEASE);
                }
            }
            reclaim_retired_locked(cur);
            sever_ctx_range(ctx, old_pc, old_pc + 4U);
        } else {
            reclaim_retired_locked(cache_epoch_load());
        }
        cur = cache_epoch_load();
        reg_ctx_locked(ctx, cur);
        e->keyepoch = (uint64_t)pc | ((uint64_t)cur << 32U);
        e->host_code = code;
        e->entry = code;
        e->pad0[0] = (uint64_t)span;
        e->ret_entry = NULL;
        e->guest_pc = pc;
        e->pagever = s_page_ver[pc >> 12U];
        e->slot_count = nslots;
        e->ret_pc = is_call ? ret_pc : 0U;
        e->occupied = true;
        for (s = 0U; s < 8U; s++) {
            ppc32_block_t *t;

            if (s < nslots && slot_pcs != NULL) {
                e->slot_pc[s] = slot_pcs[s];
                t = lookup_nofill_locked(slot_pcs[s]);
                e->slot_entry[s] = (t != NULL) ? (void *)t : NULL;
            } else {
                e->slot_pc[s] = 0U;
                e->slot_entry[s] = NULL;
            }
        }
        if (is_call) {
            ppc32_block_t *t = lookup_nofill_locked(ret_pc);

            if (t != NULL) {
                e->ret_entry = (void *)t;
            }
        }
        s_table[idx] = e;
        for (i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
            ppc32_block_t *o = s_table[i];

            if (o == NULL || o == e || !o->occupied) {
                continue;
            }
            if (o->pagever != s_page_ver[o->guest_pc >> 12U]) {
                continue;
            }
            for (s = 0U; s < o->slot_count && s < 8U; s++) {
                if (o->slot_pc[s] == pc) {
                    o->slot_entry[s] = (void *)e;
                }
            }
            if (o->ret_pc == pc && o->ret_entry == NULL) {
                o->ret_entry = (void *)e;
            }
        }
        ibtc_fill(ctx, pc, e);
        if (ctx != NULL) {
            ctx->blocks_compiled++;
        }
        (void)pthread_mutex_unlock(&s_cache_lock);
    }
    /* Persistent AOT record (Wave C2 row): no-op without --cache. The
     * freshly emitted words are recorded once per guest pc; warm runs
     * consult before appending, so the file stays append-only. */
    ppc32_aot_note_block(ctx, pc, words,
        (uint32_t)(nwords * sizeof(uint32_t)));
    return e;
}

static void invalidate_range_skip_locked(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end, ppc32_block_t *skip)
{
    uint32_t pg;
    uint32_t cur;

    if (start >= end) {
        return;
    }
    /* Bump every covered page version first: blocks that survive the
     * eager sweep below still miss on lookup. */
    for (pg = start >> 12U; pg < (end >> 12U) + 1U; pg++) {
        if (pg < PPC32_DBT_NPAGES) {
            s_page_ver[pg]++;
        }
        if (pg == 0xFFFFFU) {
            break;
        }
    }
    /* P32-R6-1: bump the generation on every invalidation so other
     * threads' IBTC/RAS sync observes it, even when nothing is evicted. */
    cache_epoch_bump();
    cur = cache_epoch_load();
    /* NOTE: pages stay marked here even though the sweep below evicts
     * the range. Unmarking would need per-page live-block accounting:
     * a surviving block overlapped-but-not-evicted (its start lies
     * outside [start, end)) still needs its marks, and a later store
     * to a prematurely unmarked page would skip the sweep that must
     * evict it. Stale marks only cost extra sweeps on pages that once
     * held code (rare); the next invalidate_all resets the map. */
    for (uint32_t i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        ppc32_block_t *e = s_table[i];

        if (e == NULL || !e->occupied) {
            continue;
        }
        if (e->guest_pc >= start && e->guest_pc < end) {
            if (e == skip) {
                /* H1 SMC: the currently-executing entry is
                 * link-severed but never unmapped (see below). */
                continue;
            }
            sever_links_to(e);
            s_table[i] = NULL;
            retire_block_locked(e, cur);
        } else if (e->pagever == s_page_ver[e->guest_pc >> 12U]) {
            __atomic_store_n(&e->keyepoch,
                (uint64_t)e->guest_pc | ((uint64_t)cur << 32U),
                __ATOMIC_RELEASE);
        }
    }
    if (skip != NULL && (uint32_t)skip->pad0[1] < end &&
        (uint32_t)skip->pad0[2] > start) {
        /* The executing entry overlaps the stored range: sever
         * incoming chains to it (any later re-entry must dispatch
         * on the bumped page version and retranslate the fresh
         * bytes) but keep executing the TB-atomic remainder. */
        sever_links_to(skip);
    }
    /* Sweep links that referenced evicted entries from surviving blocks
     * whose slot lists were recorded before eviction (sever_links_to
     * already NULLed them entry-side; belt and braces for ret_entry). */
    for (uint32_t i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        ppc32_block_t *e = s_table[i];

        if (e != NULL && e->ret_pc >= start && e->ret_pc < end &&
            e->ret_entry != NULL) {
            ppc32_block_t *t = lookup_nofill_locked(e->ret_pc);

            if (t == NULL) {
                e->ret_entry = NULL;
            }
        }
    }
    sever_ctx_range(ctx, start, end);
    reg_ctx_locked(ctx, cur);
    reclaim_retired_locked(cur);
    if (ctx != NULL) {
        ctx->icache_flushes++;
    }
}

void ppc32_cache_invalidate_range_skip(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end, ppc32_block_t *skip)
{
    (void)pthread_mutex_lock(&s_cache_lock);
    invalidate_range_skip_locked(ctx, start, end, skip);
    (void)pthread_mutex_unlock(&s_cache_lock);
}

void ppc32_cache_invalidate_range(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end)
{
    ppc32_cache_invalidate_range_skip(ctx, start, end, NULL);
}

/* P32-R6-1: flush this ctx's IBTC/RAS when its entries predate the
 * current generation. Other threads' invalidations bump g_cache_epoch
 * without touching this ctx, so the dispatch loop calls this before
 * every lookup. */
void ppc32_cache_sync_ctx(ppc32_ctx_t *ctx)
{
    uint32_t cur;

    if (ctx == NULL) {
        return;
    }
    cur = cache_epoch_load();
    if (ctx->ibtc_synced_epoch == cur) {
        return;
    }
    memset(ctx->ibtc, 0, sizeof(ctx->ibtc));
    memset(ctx->ras, 0, sizeof(ctx->ras));
    ctx->ras_top = 0U;
    (void)pthread_mutex_lock(&s_cache_lock);
    reg_ctx_locked(ctx, cache_epoch_load());
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* H1 SMC post-store hook (called from JIT-emitted code right after a
 * natively-emitted guest store of `len` bytes at `ea`; `cur` is the
 * executing entry, x27 at the call site). Evicts and severs every
 * overlapping translation so no chained re-entry can run stale
 * bytes; the executing entry itself is only link-severed, never
 * unmapped mid-execution. Wrap-around ranges flush everything. */
static void invalidate_all_locked(ppc32_ctx_t *ctx)
{
    uint32_t i;
    uint32_t cur;

    /* P32-R6-1: retire everything without unmapping live code; the
     * generation bump retires every emitted epoch check at once and
     * lets other threads lazily flush via ppc32_cache_sync_ctx. */
    cache_epoch_bump();
    cur = cache_epoch_load();
    for (i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        if (s_table[i] != NULL) {
            retire_block_locked(s_table[i], cur);
            s_table[i] = NULL;
        }
    }
    /* No live block survives: clear the occupancy map with it. */
    memset(s_code_pages, 0, sizeof s_code_pages);
    reclaim_retired_locked(cur);
    if (ctx != NULL) {
        for (i = 0U; i < PPC32_IBTC_SIZE; i++) {
            ctx->ibtc[i].key = 0U;
            ctx->ibtc[i].epoch = 0U;
            ctx->ibtc[i].host_code = NULL;
            ctx->ibtc[i].entry = NULL;
            ctx->ibtc[i].pad = 0U;
        }
        for (i = 0U; i < PPC32_RAS_SIZE; i++) {
            ctx->ras[i].key = 0U;
            ctx->ras[i].epoch = 0U;
            ctx->ras[i].host_code = NULL;
            ctx->ras[i].entry = NULL;
            ctx->ras[i].pad = 0U;
        }
        ctx->ras_top = 0U;
    }
}

void ppc32_smc_store(ppc32_ctx_t *ctx, uint32_t ea, uint32_t len,
    void *cur)
{
    uint64_t end;
    bool has_code;

    if (ctx == NULL || len == 0U || len > 4096U) {
        return;
    }
    end = (uint64_t)ea + (uint64_t)len;
    if (end > 0x100000000ULL) {
        ppc32_cache_invalidate_all(ctx);
        return;
    }
    /* Fast path: no translated code on the touched pages, so the two
     * full-table sweeps below would evict and sever nothing. Data
     * writes (the overwhelmingly common store) return here. The bitmap
     * is checked under lock so a concurrent invalidate_all clear cannot
     * race the read. */
    (void)pthread_mutex_lock(&s_cache_lock);
    has_code = code_pages_any(ea, (uint32_t)end);
    if (has_code) {
        invalidate_range_skip_locked(ctx, ea, (uint32_t)end,
            (ppc32_block_t *)cur);
    }
    (void)pthread_mutex_unlock(&s_cache_lock);
}

void ppc32_cache_invalidate_all(ppc32_ctx_t *ctx)
{
    (void)pthread_mutex_lock(&s_cache_lock);
    invalidate_all_locked(ctx);
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* P32-R6-1 fork protocol: prepare holds s_cache_lock across the
 * address-space snapshot (the forker owns it at fork, so the child
 * just releases it); the child also drops peer registrations, whose
 * owners are gone, plus any overflow mark. */
void ppc32_cache_fork_prepare(void)
{
    (void)pthread_mutex_lock(&s_cache_lock);
}

void ppc32_cache_fork_parent(void)
{
    (void)pthread_mutex_unlock(&s_cache_lock);
}

void ppc32_cache_fork_child(void)
{
    size_t i;

    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        s_reg_ctx[i] = NULL;
        s_reg_epoch[i] = 0U;
    }
    s_reg_overflow = false;
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* Release one ctx slot before it is freed; epochs are by value, so a
 * missed call only delays freeing, never frees early. */
void ppc32_cache_forget_ctx(const ppc32_ctx_t *ctx)
{
    size_t i;

    if (ctx == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&s_cache_lock);
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] == ctx) {
            s_reg_ctx[i] = NULL;
            s_reg_epoch[i] = 0U;
        }
    }
    (void)pthread_mutex_unlock(&s_cache_lock);
}
