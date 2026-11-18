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
#include "dbt/cache_edge.h"
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
/* Monotonic reclamation generation, decoupled from g_cache_epoch. */
static uint32_t s_reclaim_gen = 1U;
/* Retirements since the last reclaim bump (rate-limits reclaim bumps). */
static uint32_t s_cur_gen_retired = 0U;

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
    uint32_t reclaim_gen;
    struct retired_node *next;
} retired_node_t;

static retired_node_t *s_retired = NULL;
static uint32_t s_retired_count = 0U;
/* Bucket evictions retire at the current epoch and never bump it, so
 * without a drain the list (and every install's walk) grows without
 * bound. Batches of this size drain on the single-ctx fast path. */
#define PPC32_RETIRE_BATCH 64U

/* Dispatcher sync registry for quiescent reclamation. */
#define PPC32_CACHE_MAX_REG 256U
static ppc32_ctx_t *s_reg_ctx[PPC32_CACHE_MAX_REG];
static uint32_t s_reg_epoch[PPC32_CACHE_MAX_REG];
static uint32_t s_reg_reclaim[PPC32_CACHE_MAX_REG];
static bool s_reg_overflow = false;

/* Cut dead links in one IBTC/RAS array. Caller holds s_cache_lock. */
static void scrub_slots_locked(ppc32_ibtc_entry_t *slots, size_t n,
    uint32_t cur)
{
    size_t i;

    for (i = 0U; i < n; i++) {
        ppc32_ibtc_entry_t *s = &slots[i];

        if (s->entry == NULL) {
            continue;
        }
        if (s->epoch != cur) {
            s->host_code = NULL;
            s->entry = NULL;
            s->epoch = 0U;
            continue;
        }
        if (((const ppc32_block_t *)s->entry)->keyepoch == 0ULL) {
            s->host_code = NULL;
            s->entry = NULL;
        }
    }
}

/* Cut NULL IBTC/RAS links to retired blocks (keyepoch 0); slots from
 * older generations are cleared blind. Caller holds s_cache_lock. */
static void scrub_retired_locked(ppc32_ctx_t *owner)
{
    uint32_t cur;

    if (owner == NULL) {
        return;
    }
    cur = cache_epoch_load();
    scrub_slots_locked(owner->ibtc, PPC32_IBTC_SIZE, cur);
    scrub_slots_locked(owner->ras, PPC32_RAS_SIZE, cur);
}

/* Caller holds s_cache_lock: the mark below only advances past
 * retired links already cut (stale flushes, synced scrubs). */
static void reg_ctx_locked(ppc32_ctx_t *ctx, uint32_t cur)
{
    size_t i;
    uint32_t rgen = __atomic_load_n(&s_reclaim_gen, __ATOMIC_ACQUIRE);

    if (ctx == NULL) {
        return;
    }
    if (ctx->ibtc_synced_epoch != cur) {
        memset(ctx->ibtc, 0, sizeof(ctx->ibtc));
        memset(ctx->ras, 0, sizeof(ctx->ras));
        ctx->ras_top = 0U;
        ctx->ibtc_synced_epoch = cur;
    } else if (ctx->reclaim_synced_gen != rgen) {
        /* Advancing to a new reclamation generation: scrub retired
         * links before raising this ctx's s_reg_reclaim[] mark. */
        scrub_retired_locked(ctx);
    } else {
        /* Already synced to (cur, rgen) and present in s_reg_ctx[]. */
        return;
    }
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] == ctx) {
            s_reg_epoch[i] = cur;
            s_reg_reclaim[i] = rgen;
            ctx->reclaim_synced_gen = rgen;
            return;
        }
    }
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] == NULL) {
            s_reg_ctx[i] = ctx;
            s_reg_epoch[i] = cur;
            s_reg_reclaim[i] = rgen;
            ctx->reclaim_synced_gen = rgen;
            return;
        }
    }
    s_reg_overflow = true;
}

static void block_free_now(ppc32_block_t *e);

static void retire_block_locked(ppc32_block_t *e, uint32_t rgen)
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
    n->reclaim_gen = rgen;
    n->next = s_retired;
    s_retired = n;
    s_retired_count++;
    s_cur_gen_retired++;
}

/* Single live dispatcher (registry scan plus the live thread count as
 * the authoritative second check). M1: heals a sticky s_reg_overflow
 * once one owner remains, so drain and reclamation resume cleanly. */
static bool single_owner_locked(ppc32_ctx_t *owner)
{
    size_t i;

    if (owner == NULL || ppc32_thread_count() > 1U) {
        return false;
    }
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] != NULL && s_reg_ctx[i] != owner) {
            return false;
        }
    }
    s_reg_overflow = false;
    return true;
}

/* Reclaim rate limit: 256 retirements per generation bump, so a parked
 * peer cannot force a bump on every install. Caller holds s_cache_lock. */
#define PPC32_RETIRE_EPOCH_BATCH 256U
static void reclaim_retired_locked(uint32_t cur, ppc32_ctx_t *owner)
{
    retired_node_t **pp = &s_retired;
    bool drain = s_retired_count >= PPC32_RETIRE_BATCH &&
        single_owner_locked(owner);
    bool quiet = !s_reg_overflow;
    uint32_t min_reclaim;
    size_t i;

    (void)cur;
    if (!drain && s_retired_count >= PPC32_RETIRE_BATCH &&
        s_cur_gen_retired >= PPC32_RETIRE_EPOCH_BATCH) {
        /* No single owner to drain through: open a fresh reclamation
         * generation. The semantic epoch is untouched: live blocks keep
         * their keyepoch and never miss or retranslate. */
        uint32_t next =
            __atomic_load_n(&s_reclaim_gen, __ATOMIC_ACQUIRE) + 1U;

        if (next == 0U) {
            next = 1U;
        }
        __atomic_store_n(&s_reclaim_gen, next, __ATOMIC_RELEASE);
        s_cur_gen_retired = 0U;
    }
    if (drain) {
        scrub_retired_locked(owner);
        memset(owner->ras, 0, sizeof(owner->ras));
        owner->ras_top = 0U;
    }
    /* A node frees once every registered ctx synced past its generation
     * (post-scrub marks); overflow falls back to the drain path. */
    min_reclaim = __atomic_load_n(&s_reclaim_gen, __ATOMIC_ACQUIRE);
    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        if (s_reg_ctx[i] != NULL && s_reg_reclaim[i] < min_reclaim) {
            min_reclaim = s_reg_reclaim[i];
        }
    }
    while (*pp != NULL) {
        retired_node_t *n = *pp;
        bool freeable = drain;

        if (!drain && quiet && n->reclaim_gen < min_reclaim) {
            freeable = true;
        }
        if (freeable) {
            *pp = n->next;
            block_free_now(n->blk);
            free(n);
            s_retired_count--;
        } else {
            pp = &n->next;
        }
    }
}

uint32_t *ppc32_cache_epoch_ptr(void)
{
    return &g_cache_epoch;
}

/* Bitmap base baked into emitted guards; cleared in place on flush. */
const uint64_t *ppc32_code_pages_base(void)
{
    return ppc32_edge_code_pages_base();
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
        bool dead = s->entry != NULL &&
            ((const ppc32_block_t *)s->entry)->keyepoch == 0ULL;

        if (dead || (s->key >= start && s->key < end)) {
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

/* M3: thread-local staged guest snapshot (copyin_safe, outside the
 * lock); install publishes it before s_table[idx] = e, or discards it. */
static _Thread_local bool s_staged_valid = false;
static _Thread_local uint32_t s_staged_start = 0U;
static _Thread_local uint32_t s_staged_end = 0U;
static _Thread_local uint8_t *s_staged_snap = NULL;

static void staged_discard(void)
{
    free(s_staged_snap);
    s_staged_snap = NULL;
    s_staged_valid = false;
}

void ppc32_cache_stage_guest(ppc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint64_t len = (uint64_t)end - (uint64_t)start;

    free(s_staged_snap);
    s_staged_snap = NULL;
    s_staged_valid = true;
    s_staged_start = start;
    s_staged_end = end;
    if (ctx != NULL && ctx->vm_ready && end > start && len <= 4096ULL) {
        s_staged_snap = (uint8_t *)malloc((size_t)len);
        if (s_staged_snap != NULL && ppc32_vm_copyin_safe(ctx, start,
            s_staged_snap, (size_t)len) != 0) {
            free(s_staged_snap);
            s_staged_snap = NULL;
        }
    }
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
                    if (ctx != NULL) {
                        reg_ctx_locked(ctx, cache_epoch_load());
                    }
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
            if (ctx != NULL) {
                reg_ctx_locked(ctx, cache_epoch_load());
            }
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
        staged_discard();
        return NULL;
    }
    if (nslots > 8U) {
        nslots = 8U;
    }
    e = (ppc32_block_t *)calloc(1, sizeof(*e));
    if (e == NULL) {
        staged_discard();
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
        staged_discard();
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
        staged_discard();
        return NULL;
    }
    memcpy(code, words, nwords * sizeof(uint32_t));
    /* W^X flip: drop WRITE, add EXEC, flush I-cache. */
    if (mprotect(code, span, PROT_READ | PROT_EXEC) != 0) {
        (void)munmap(code, span);
        free(e);
        staged_discard();
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
            ppc32_edge_sever_target_locked(old_pc);
            s_table[idx] = NULL;
            ppc32_edge_drop_block_locked(old);
            retire_block_locked(old, __atomic_load_n(&s_reclaim_gen,
                __ATOMIC_ACQUIRE));
            /* old is retired above: only old_pc below, never old. */
            ibtc_drop_key_locked(ctx, old_pc);
            sever_ctx_range(ctx, old_pc, old_pc + 4U);
            ppc32_edge_note_evict(cache_epoch_load());
        }
        cur = cache_epoch_load();
        if (ctx != NULL) {
            reg_ctx_locked(ctx, cur);
        }
        reclaim_retired_locked(cur, ctx);
        /* Reclaim bumps only the reclamation generation now, so the
         * semantic epoch (and the stamp below) cannot shift here. */
        cur = cache_epoch_load();
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
        /* M3: publish the staged guest range + snapshot BEFORE the
         * entry becomes visible so peers never resolve bare pad0. */
        if (s_staged_valid) {
            ppc32_edge_code_mark(s_staged_start, s_staged_end);
            e->pad0[1] = (uint64_t)s_staged_start;
            e->pad0[2] = (uint64_t)s_staged_end;
            e->pad0[3] = (uint64_t)(uintptr_t)s_staged_snap;
            s_staged_valid = false;
            s_staged_snap = NULL;
        }
        s_table[idx] = e;
        /* P32-R13-6: register edges, backfill only the pc bucket. */
        for (s = 0U; s < nslots && s < 8U; s++) {
            ppc32_edge_add_locked(e, e->slot_pc[s], s);
        }
        if (is_call) {
            ppc32_edge_add_locked(e, ret_pc, 8U);
        }
        ppc32_edge_backfill_locked(e, s_page_ver);
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
    uint32_t cur;

    if (start >= end) {
        return;
    }
    /* No translated byte in [start, end): nothing to evict, sever, or
     * bump (the store hit data only, e.g. FPR spills sharing the signal
     * trampoline's stack page on a different 64-byte line). */
    if (!ppc32_edge_has_overlap_locked(s_table, start, end, skip,
        cache_epoch_load())) {
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
    cache_epoch_bump();
    cur = cache_epoch_load();
    /* Pages stay marked (stale marks only cost extra sweeps). */
    for (uint32_t i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        ppc32_block_t *e = s_table[i];

        if (e == NULL || !e->occupied) {
            continue;
        }
        /* A store may land mid-block (past the entry word), so match
         * the recorded translated range as well as the block start. */
        bool hit = (e->guest_pc >= start && e->guest_pc < end) ||
            (e->pad0[2] > e->pad0[1] && (uint32_t)e->pad0[1] < end &&
                (uint32_t)e->pad0[2] > start);

        if (hit) {
            if (e == skip) {
                continue; /* executing entry: severed only, never unmapped */
            }
            ppc32_edge_sever_target_locked(e->guest_pc);
            ppc32_edge_drop_block_locked(e);
            s_table[i] = NULL;
            retire_block_locked(e, __atomic_load_n(&s_reclaim_gen,
                __ATOMIC_ACQUIRE));
        } else if (e->pagever == s_page_ver[e->guest_pc >> 12U]) {
            __atomic_store_n(&e->keyepoch,
                (uint64_t)e->guest_pc | ((uint64_t)cur << 32U),
                __ATOMIC_RELEASE);
        }
    }
    if (skip != NULL && (uint32_t)skip->pad0[1] < end &&
        (uint32_t)skip->pad0[2] > start) {
        ppc32_edge_sever_target_locked(skip->guest_pc);
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
    /* No registry or reclamation touch here: ctx may be mid-block,
     * so the flush waits for the next quiescent dispatch sync. */
    sever_ctx_range(ctx, start, end);
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

/* Flush this ctx's IBTC/RAS when its entries predate the current
 * generation; sync the reclamation generation the same way. The
 * dispatch loop calls this before every lookup. */
void ppc32_cache_sync_ctx(ppc32_ctx_t *ctx)
{
    uint32_t cur;
    uint32_t rgen;

    if (ctx == NULL) {
        return;
    }
    cur = cache_epoch_load();
    rgen = __atomic_load_n(&s_reclaim_gen, __ATOMIC_ACQUIRE);
    if (ctx->ibtc_synced_epoch == cur && ctx->reclaim_synced_gen == rgen) {
        return;
    }
    (void)pthread_mutex_lock(&s_cache_lock);
    cur = cache_epoch_load();
    reg_ctx_locked(ctx, cur);
    reclaim_retired_locked(cur, ctx);
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* H1 SMC post-store hook (called from JIT code after a natively-emitted
 * guest store): evict and sever every overlapping translation; the
 * executing entry is only link-severed, never unmapped mid-execution. */
static void invalidate_all_locked(ppc32_ctx_t *ctx)
{
    uint32_t i;

    /* Retire everything without unmapping live code; the epoch bump
     * retires every emitted check at once, peers flush lazily. No
     * reclamation here: ctx may be mid-block, so quiescent dispatch
     * entry owns reclaim. */
    cache_epoch_bump();
    for (i = 0U; i < PPC32_DBT_HT_SIZE; i++) {
        if (s_table[i] != NULL) {
            ppc32_edge_drop_block_locked(s_table[i]);
            retire_block_locked(s_table[i], __atomic_load_n(&s_reclaim_gen,
                __ATOMIC_ACQUIRE));
            s_table[i] = NULL;
        }
    }
    ppc32_edge_clear_all_locked();
    /* No live block survives: clear the occupancy maps with it. */
    ppc32_edge_code_clear_all();
    if (ctx != NULL) {
        memset(ctx->ibtc, 0, sizeof(ctx->ibtc));
        memset(ctx->ras, 0, sizeof(ctx->ras));
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
    /* Fast path: no translated code on these pages, so the sweeps below
     * would evict nothing. Checked under lock against concurrent clear. */
    (void)pthread_mutex_lock(&s_cache_lock);
    has_code = ppc32_edge_code_any(ea, (uint32_t)end);
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

/* Fork protocol: prepare holds s_cache_lock across the snapshot; the
 * child drops peer registrations, whose owners are gone. */
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
    uint32_t next;

    for (i = 0U; i < PPC32_CACHE_MAX_REG; i++) {
        s_reg_ctx[i] = NULL;
        s_reg_epoch[i] = 0U;
        s_reg_reclaim[i] = 0U;
    }
    s_reg_overflow = false;
    /* Drop every registration: bump the reclamation generation so the
     * surviving child ctx observes reclaim_synced_gen != rgen and
     * re-inserts itself instead of taking the synced fast path. */
    next = __atomic_load_n(&s_reclaim_gen, __ATOMIC_ACQUIRE) + 1U;
    if (next == 0U) {
        next = 1U;
    }
    __atomic_store_n(&s_reclaim_gen, next, __ATOMIC_RELEASE);
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* Drop a worker ctx from the sync registry once its run loop has
 * exited. Freed slots are reused by reg_ctx_locked; a missed call only
 * delays freeing, never frees early. */
void ppc32_cache_unregister_ctx(ppc32_ctx_t *ctx)
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
            s_reg_reclaim[i] = 0U;
        }
    }
    ctx->reclaim_synced_gen = 0U;
    (void)pthread_mutex_unlock(&s_cache_lock);
}

/* Release one ctx slot before it is freed (same removal). */
void ppc32_cache_forget_ctx(const ppc32_ctx_t *ctx)
{
    ppc32_cache_unregister_ctx((ppc32_ctx_t *)(uintptr_t)ctx);
}
