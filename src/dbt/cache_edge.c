/*
 * src/dbt/cache_edge.c — Outgoing chain-edge table for the DBT cache
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * P32-R13-6: edges keyed by target pc (slot 8 = ret link), so sever
 * and backfill walk one bucket (O(1) avg). Every entry point runs
 * under cache.c's s_cache_lock.
 */

#include <stdlib.h>
#include <string.h>

#include "dbt/cache_edge.h"

/* One occupancy bit per guest 4 KiB page (SMC store fast path), moved
 * from cache.c so the translation cache stays under the line limit. */
#define PPC32_EDGE_NPAGES (0x100000000ULL / 4096ULL)
#define PPC32_EDGE_PAGE_WORDS (PPC32_EDGE_NPAGES / 64U)

static uint64_t s_edge_pages[PPC32_EDGE_PAGE_WORDS];
/* One bit per 64-byte line of every guest page (1 uint64 per page);
 * set alongside s_edge_pages, never cleared on bucket eviction. */
static uint64_t s_edge_lines[PPC32_EDGE_NPAGES];
/* Epoch of the most recent bucket eviction (0 = none yet). */
static uint32_t s_edge_evict_epoch = 0U;

#define EDGE_HT_BITS 16U
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
void ppc32_edge_add_locked(ppc32_block_t *src, uint32_t target,
    unsigned slot)
{
    edge_node_t *n;
    edge_node_t *c;

    if (src == NULL || slot > 8U) {
        return;
    }
    for (c = s_edge[edge_hash(target)]; c != NULL; c = c->next) {
        if (c->src == src && c->target == target && c->slot == slot) {
            return;
        }
    }
    n = (edge_node_t *)malloc(sizeof(*n));
    if (n == NULL) {
        return;
    }
    n->src = src;
    n->target = target;
    n->slot = (uint8_t)slot;
    n->next = s_edge[edge_hash(target)];
    s_edge[edge_hash(target)] = n;
}
void ppc32_edge_drop_locked(ppc32_block_t *src, uint32_t target,
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
void ppc32_edge_drop_block_locked(const ppc32_block_t *old)
{
    unsigned s;

    if (old == NULL) {
        return;
    }
    for (s = 0U; s < old->slot_count && s < 8U; s++) {
        ppc32_edge_drop_locked((ppc32_block_t *)old, old->slot_pc[s], s);
    }
    if (old->ret_pc != 0U) {
        ppc32_edge_drop_locked((ppc32_block_t *)old, old->ret_pc, 8U);
    }
}
/* Sever incoming links to `target`: only sources in its bucket. */
void ppc32_edge_sever_target_locked(uint32_t target)
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
void ppc32_edge_backfill_locked(ppc32_block_t *fresh,
    const uint32_t *page_ver)
{
    edge_node_t *n;

    if (fresh == NULL) {
        return;
    }
    n = s_edge[edge_hash(fresh->guest_pc)];
    while (n != NULL) {
        if (n->target == fresh->guest_pc && n->src != NULL &&
            n->src != fresh && n->src->occupied &&
            n->src->pagever == page_ver[n->src->guest_pc >> 12U]) {
            if (n->slot < 8U) {
                if (n->src->slot_pc[n->slot] == fresh->guest_pc) {
                    __atomic_store_n(&n->src->slot_entry[n->slot],
                        (void *)fresh, __ATOMIC_RELEASE);
                }
            } else if (n->src->ret_pc == fresh->guest_pc &&
                n->src->ret_entry == NULL) {
                __atomic_store_n(&n->src->ret_entry, (void *)fresh,
                    __ATOMIC_RELEASE);
            }
        }
        n = n->next;
    }
}
/* Free every edge node (invalidate_all: no live block survives). */
void ppc32_edge_clear_all_locked(void)
{
    uint32_t i;

    for (i = 0U; i < EDGE_HT_SIZE; i++) {
        edge_node_t *n = s_edge[i];

        while (n != NULL) {
            edge_node_t *nx = n->next;

            free(n);
            n = nx;
        }
        s_edge[i] = NULL;
    }
}

void ppc32_edge_code_mark(uint32_t start, uint32_t end)
{
    uint32_t pg;
    uint32_t lo;
    uint32_t hi;
    uint32_t ln;

    if (end <= start) {
        return;
    }
    for (pg = start >> 12U; ; pg++) {
        s_edge_pages[pg >> 6U] |= 1ULL << (pg & 63U);
        if (pg == ((end - 1U) >> 12U) || pg == 0xFFFFFU) {
            break;
        }
    }
    lo = start >> 6U;
    hi = (end - 1U) >> 6U;
    for (ln = lo; ; ln++) {
        s_edge_lines[ln >> 6U] |= 1ULL << (ln & 63U);
        if (ln == hi) {
            break;
        }
    }
}

bool ppc32_edge_code_any(uint32_t start, uint32_t end)
{
    uint32_t pg;

    if (end <= start) {
        return false;
    }
    for (pg = start >> 12U; ; pg++) {
        if ((s_edge_pages[pg >> 6U] & (1ULL << (pg & 63U))) != 0ULL) {
            return true;
        }
        if (pg == ((end - 1U) >> 12U) || pg == 0xFFFFFU) {
            break;
        }
    }
    return false;
}

bool ppc32_edge_lines_any(uint32_t start, uint32_t end)
{
    uint32_t lo;
    uint32_t hi;
    uint32_t ln;

    if (end <= start) {
        return false;
    }
    lo = start >> 6U;
    hi = (end - 1U) >> 6U;
    for (ln = lo; ; ln++) {
        if ((s_edge_lines[ln >> 6U] & (1ULL << (ln & 63U))) != 0ULL) {
            return true;
        }
        if (ln == hi) {
            break;
        }
    }
    return false;
}

void ppc32_edge_code_clear_all(void)
{
    memset(s_edge_pages, 0, sizeof s_edge_pages);
    memset(s_edge_lines, 0, sizeof s_edge_lines);
}

const uint64_t *ppc32_edge_code_pages_base(void)
{
    return s_edge_pages;
}

void ppc32_edge_note_evict(uint32_t cur)
{
    s_edge_evict_epoch = cur;
}

/* True when `e` could cover a byte of [start, end): by block start or
 * by the recorded translated range (never crossing a 4 KiB page). */
static bool edge_block_hits(const ppc32_block_t *e, uint32_t start,
    uint32_t end)
{
    uint32_t gs;
    uint32_t ge;

    if (e == NULL || !e->occupied) {
        return false;
    }
    if (e->guest_pc >= start && e->guest_pc < end) {
        return true;
    }
    gs = (uint32_t)e->pad0[1];
    ge = (uint32_t)e->pad0[2];
    return ge > gs && gs < end && ge > start;
}

bool ppc32_edge_has_overlap_locked(ppc32_block_t *const *table,
    uint32_t start, uint32_t end, const ppc32_block_t *skip,
    uint32_t cur_epoch)
{
    uint64_t span;
    uint32_t scan_lo;
    uint32_t pc;

    if (end <= start) {
        return false;
    }
    /* No translated line here since the last full flush: no block,
     * live or bucket-evicted, ever covered [start, end). The line map
     * survives bucket eviction, so this stays sound when the table no
     * longer holds every block. */
    if (!ppc32_edge_lines_any(start, end)) {
        return false;
    }
    span = (uint64_t)end - (uint64_t)start;
    if (span > 65536ULL || s_edge_evict_epoch == cur_epoch) {
        return true;
    }
    /* Every block is at most BLOCK_BUDGET words long, so an overlap
     * starts at most that far below `start`. Probing each candidate
     * start finds every live block that could cover [start, end). */
    if (edge_block_hits(skip, start, end)) {
        return true;
    }
    scan_lo = (start > (PPC32_DBT_BLOCK_BUDGET * 4U)) ?
        ((start - (PPC32_DBT_BLOCK_BUDGET * 4U)) & ~3U) : 0U;
    for (pc = scan_lo; pc < end; ) {
        uint32_t idx = (pc >> 2U) & (PPC32_DBT_HT_SIZE - 1U);

        if (edge_block_hits(table[idx], start, end)) {
            return true;
        }
        if (pc >= 0xFFFFFFFCU) {
            break;
        }
        pc += 4U;
    }
    return false;
}
