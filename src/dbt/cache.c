/*
 * src/dbt/cache.c — Translation-cache storage for the AArch64 DBT
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Direct-mapped cache of 1024 blocks keyed by guest NIP. Each block
 * owns one executable mapping (RW staging, then PROT_READ|PROT_EXEC +
 * I-cache flush; W^X; guest data pages never PROT_EXEC). Invalidation
 * is page-versioned with eager range eviction; invalidate_all bumps
 * the epoch. H1 SMC: post-store hooks evict eagerly, snapshots in
 * pad0[1..3] re-verify at dispatch, the executing entry is only
 * link-severed (TB-atomic, like qemu).
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
/* Atomic generation for JIT epoch checks; __atomic access only. */
static uint32_t g_cache_epoch = 1U;
/* Serializes table/pagever/epoch/retire mutation (never host IO). */
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

/* Deferred reclamation: evicted mappings stay live one generation. */
typedef struct retired_node {
    ppc32_block_t *blk;
    uint32_t epoch;
    struct retired_node *next;
} retired_node_t;

static retired_node_t *s_retired = NULL;

/* Dispatcher sync registry for quiescent reclamation. */
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
    if (ctx->ibtc_synced_epoch != cur) {
        memset(ctx->ibtc, 0, sizeof(ctx->ibtc));
        memset(ctx->ras, 0, sizeof(ctx->ras));
        ctx->ras_top = 0U;
        ctx->ibtc_synced_epoch = cur;
    }
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

/* Caller holds s_cache_lock. */
static void reclaim_retired_locked(uint32_t cur)
{
    retired_node_t **pp = &s_retired;
    bool quiet = !s_reg_overflow;

    while (*pp != NULL) {
        retired_node_t *n = *pp;
        bool freeable = false;

        if (n->epoch != cur && quiet) {
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
        if (freeable) {
            *pp = n->next;
            block_free_now(n->blk);
            free(n);
        } else {
            pp = &n->next;
        }
    }
}

/* One occupancy bit per guest 4 KiB page for the SMC store fast path. */
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

/* Bitmap base baked into emitted guards; cleared in place on flush. */
const uint64_t *ppc32_code_pages_base(void)
{
    return s_code_pages;
}

static uint32_t cache_index(uint32_t pc)
{
    return (pc >> 2U) & (PPC32_DBT_HT_SIZE - 1U);
}

/* Caller holds s_cache_lock for shared-table entries. */
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
    slot->entry = (void *)e;
    slot->pad = 0U;
}

/* P32-R13-6: outgoing-edge table keyed by target pc (slot 8 = ret).
 * Sever/backfill walk one bucket (O(1) avg). Caller holds the lock. */
#define EDGE_HT_BITS 8U
#define EDGE_HT_SIZE (1U << EDGE_HT_BITS)
typedef struct edge_node {
    ppc32_block_t *src;
    struct edge_node *next;
    uint32_t target;
    uint8_t slot;
} edge_node_t;
static edge_node_t *s_edge[EDGE_HT_SIZE];
static inline uint32_t edge_hash(uint32_t pc)
{
    return (pc >> 2U) & (EDGE_HT_SIZE - 1U);
}
static void edge_add_locked(ppc32_block_t *src, uint32_t target,
    unsigned slot)
{
    edge_node_t *n = (edge_node_t *)malloc(sizeof(*n));

    if (n == NULL || src == NULL) {
        free(n);
        return;
    }
    n->src = src;
    n->target = target;
    n->slot = (uint8_t)slot;
    n->next = s_edge[edge_hash(target)];
    s_edge[edge_hash(target)] = n;
}
static void edge_drop_locked(ppc32_block_t *src, uint32_t target,
    unsigned slot)
{
    uint32_t h = edge_hash(target);
    edge_node_t **pp = &s_edge[h];

    while (*pp != NULL) {
        edge_node_t *n = *pp;
        if (n->src == src && n->target == target && n->slot == slot) {
            *pp = n->next;
            free(n);
            return;
        }
        pp = &n->next;
    }
}
/* Drop every outgoing edge node owned by `old`. */
static void edge_drop_block_locked(const ppc32_block_t *old)
{
    unsigned s;

    if (old == NULL) {
        return;
    }
    for (s = 0U; s < old->slot_count && s < 8U; s++) {
        edge_drop_locked((ppc32_block_t *)old, old->slot_pc[s], s);
    }
    if (old->ret_pc != 0U) {
        edge_drop_locked((ppc32_block_t *)old, old->ret_pc, 8U);
    }
}
/* Sever incoming links to `target`: only sources in its bucket. */
static void edge_sever_target_locked(uint32_t target)
{
    edge_node_t *n = s_edge[edge_hash(target)];

    while (n != NULL) {
        if (n->target == target && n->src != NULL && n->src->occupied) {
            if (n->slot < 8U) {
                if (n->src->slot_pc[n->slot] == target) {
                    __atomic_store_n(&n->src->slot_entry[n->slot], NULL,
                        __ATOMIC_RELEASE);
                }
            } else if (n->src->ret_pc == target) {
                __atomic_store_n(&n->src->ret_entry, NULL,
                    __ATOMIC_RELEASE);
            }
        }
        n = n->next;
    }
}
/* Backfill incoming links to a fresh block: only its bucket. */
static void edge_backfill_locked(ppc32_block_t *fresh)
{
    edge_node_t *n;

    if (fresh == NULL) {
        return;
    }
    n = s_edge[edge_hash(fresh->guest_pc)];
    while (n != NULL) {
        if (n->target == fresh->guest_pc && n->src != NULL &&
            n->src != fresh && n->src->occupied &&
            n->src->pagever == s_page_ver[n->src->guest_pc >> 12U]) {
            if (n->slot < 8U) {
                if (n->src->slot_pc[n->slot] == fresh->guest_pc) {
                    n->src->slot_entry[n->slot] = (void *)fresh;
                }
            } else if (n->src->ret_pc == fresh->guest_pc &&
                n->src->ret_entry == NULL) {
                n->src->ret_entry = (void *)fresh;
            }
        }
        n = n->next;
    }
}
/* Clear the one IBTC slot that can hold `pc` in every tracked ctx. */
static void ibtc_drop_key_locked(ppc32_ctx_t *ctx, uint32_t pc)
{
    size_t i;
    uint32_t h = ppc32_ibtc_hash(pc);

    if (ctx != NULL && ctx->ibtc[h].key == pc) {
        ctx->ibtc[h].host_code = NULL;
        ctx->ibtc[h].entry = NULL;
    }
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        ppc32_ctx_t *c = s_reg_ctx[i];
        if (c != NULL && c != ctx && c->ibtc[h].key == pc) {
            c->ibtc[h].host_code = NULL;
            c->ibtc[h].entry = NULL;
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
    memset(ctx->ras, 0, sizeof(ctx->ras));
    ctx->ras_top = 0U;
}

/* Only for retired generations (one-generation grace keeps it safe). */
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

/* Record translated guest range + byte snapshot (called post-install). */
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
    (void)pthread_mutex_lock(&s_cache_lock);
    code_pages_mark(start, end);
    e->pad0[1] = (uint64_t)start;
    e->pad0[2] = (uint64_t)end;
    free((void *)(uintptr_t)e->pad0[3]);
    e->pad0[3] = (uint64_t)(uintptr_t)snap;
    snap = NULL;
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* Caller holds s_cache_lock. */
static void invalidate_range_skip_locked(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end, ppc32_block_t *skip);

/* P32-R13-5: snapshot descriptor copied under lock; guest re-read runs
 * unlocked; mismatch re-locks and re-verifies before evicting. */
ppc32_block_t *ppc32_cache_lookup(ppc32_ctx_t *ctx, uint32_t pc)
{
    ppc32_block_t *e;
    uint8_t expected[4096];
    uint8_t actual[4096];
    uint64_t len = 0ULL;
    uint64_t keyepoch = 0ULL;
    uint32_t start = 0U;
    bool have_snap = false;
    bool have_vm = false;

    (void)pthread_mutex_lock(&s_cache_lock);
    e = lookup_valid_locked(pc);
    if (e != NULL) {
        const uint8_t *snap = (const uint8_t *)(uintptr_t)e->pad0[3];

        len = e->pad0[2] - e->pad0[1];
        keyepoch = e->keyepoch;
        start = (uint32_t)e->pad0[1];
        have_vm = (ctx != NULL && ctx->vm_ready);
        if (snap != NULL && len > 0ULL && len <= 4096ULL && have_vm) {
            memcpy(expected, snap, (size_t)len);
            have_snap = true;
        }
    }
    (void)pthread_mutex_unlock(&s_cache_lock);
    if (e == NULL || !have_snap) {
        if (e != NULL) {
            (void)pthread_mutex_lock(&s_cache_lock);
            {
                ppc32_block_t *live = lookup_valid_locked(pc);
                if (live != NULL) {
                    ibtc_fill(ctx, pc, live);
                    e = live;
                } else {
                    e = NULL;
                }
            }
            (void)pthread_mutex_unlock(&s_cache_lock);
        }
        return e;
    }
    if (ppc32_vm_copyin_safe(ctx, start, actual, (size_t)len) != 0 ||
        memcmp(expected, actual, (size_t)len) != 0) {
        (void)pthread_mutex_lock(&s_cache_lock);
        {
            ppc32_block_t *live = lookup_valid_locked(pc);
            if (live != NULL && live->keyepoch == keyepoch &&
                (uint32_t)live->pad0[1] == start &&
                live->pad0[2] - live->pad0[1] == len) {
                uint32_t rs = (uint32_t)live->pad0[1];
                uint32_t re = (uint32_t)live->pad0[2];

                if (re > rs) {
                    invalidate_range_skip_locked(ctx, rs, re, NULL);
                }
            }
        }
        (void)pthread_mutex_unlock(&s_cache_lock);
        return NULL;
    }
    (void)pthread_mutex_lock(&s_cache_lock);
    {
        ppc32_block_t *live = lookup_valid_locked(pc);
        if (live != NULL) {
            ibtc_fill(ctx, pc, live);
            e = live;
        } else {
            e = NULL;
        }
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
    /* W^X flip: drop WRITE, add EXEC, flush I-cache. */
    if (mprotect(code, span, PROT_READ | PROT_EXEC) != 0) {
        (void)munmap(code, span);
        free(e);
        return NULL;
    }
    __builtin___clear_cache((char *)code,
        (char *)code + nwords * sizeof(uint32_t));
#endif

    /* Table mutation under lock; eviction retires, never unmaps live. */
    {
        uint32_t idx = cache_index(pc);
        ppc32_block_t *old;
        unsigned s;
        uint32_t cur;

        (void)pthread_mutex_lock(&s_cache_lock);
        old = s_table[idx];
        if (old != NULL) {
            uint32_t old_pc = old->guest_pc;

            /* P32-R13-6: bucket sever, drop edges, retire, drop IBTC. */
            edge_sever_target_locked(old_pc);
            s_table[idx] = NULL;
            edge_drop_block_locked(old);
            cur = cache_epoch_load();
            retire_block_locked(old, cur);
            ibtc_drop_key_locked(ctx, old_pc);
            sever_ctx_range(ctx, old_pc, old_pc + 4U);
        }
        cur = cache_epoch_load();
        reg_ctx_locked(ctx, cur);
        reclaim_retired_locked(cur);
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
        /* P32-R13-6: register edges, backfill only the pc bucket. */
        for (s = 0U; s < nslots && s < 8U; s++) {
            edge_add_locked(e, e->slot_pc[s], s);
        }
        if (is_call) {
            edge_add_locked(e, ret_pc, 8U);
        }
        edge_backfill_locked(e);
        ibtc_fill(ctx, pc, e);
        if (ctx != NULL) {
            ctx->blocks_compiled++;
        }
        (void)pthread_mutex_unlock(&s_cache_lock);
    }
    /* AOT record: no-op without --cache; append-only per guest pc. */
    ppc32_aot_note_block(ctx, pc, words,
        (uint32_t)(nwords * sizeof(uint32_t)));
    return e;
}

static void invalidate_range_skip_locked(ppc32_ctx_t *ctx, uint32_t start,
    uint32_t end, ppc32_block_t *skip)
{
    uint32_t pg;
    uint32_t prev_epoch;
    uint32_t cur;

    if (start >= end) {
        return;
    }
    /* Page versions first so survivors still miss on lookup. */
    for (pg = start >> 12U; pg < (end >> 12U) + 1U; pg++) {
        if (pg < PPC32_DBT_NPAGES) {
            s_page_ver[pg]++;
        }
        if (pg == 0xFFFFFU) {
            break;
        }
    }
    /* Bump every invalidation so peers' IBTC/RAS sync observes it. */
    prev_epoch = cache_epoch_load();
    cache_epoch_bump();
    cur = cache_epoch_load();
    /* Pages stay marked (stale marks only cost extra sweeps). */
    for (uint32_t i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        ppc32_block_t *e = s_table[i];

        if (e == NULL || !e->occupied) {
            continue;
        }
        if (e->guest_pc >= start && e->guest_pc < end) {
            if (e == skip) {
                continue; /* executing entry: severed only, never unmapped */
            }
            edge_sever_target_locked(e->guest_pc);
            edge_drop_block_locked(e);
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
        edge_sever_target_locked(skip->guest_pc);
    }
    /* Belt and braces: clear ret links to evicted entries. */
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
    if (skip == NULL) {
        if (ctx != NULL && ctx->ibtc_synced_epoch == prev_epoch) {
            ctx->ibtc_synced_epoch = cur;
        }
        reg_ctx_locked(ctx, cur);
        reclaim_retired_locked(cur);
    }
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
    (void)pthread_mutex_lock(&s_cache_lock);
    cur = cache_epoch_load();
    reg_ctx_locked(ctx, cur);
    reclaim_retired_locked(cur);
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
            edge_drop_block_locked(s_table[i]);
            retire_block_locked(s_table[i], cur);
            s_table[i] = NULL;
        }
    }
    for (i = 0U; i < EDGE_HT_SIZE; i++) {
        edge_node_t *n = s_edge[i];

        while (n != NULL) {
            edge_node_t *nx = n->next;

            free(n);
            n = nx;
        }
        s_edge[i] = NULL;
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
