/*
 * src/dbt/cache_edge.h — Outgoing chain-edge table for the DBT cache
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private to src/dbt/cache.c. Callers hold s_cache_lock.
 */

#ifndef PPC32RT_DBT_CACHE_EDGE_H
#define PPC32RT_DBT_CACHE_EDGE_H

#include <stdbool.h>
#include <stdint.h>

#include "dbt/dbt.h"

/* Record that `src` exits to `target` through `slot` (8 = ret link). */
void ppc32_edge_add_locked(ppc32_block_t *src, uint32_t target,
    unsigned slot);
/* Forget one edge node. */
void ppc32_edge_drop_locked(ppc32_block_t *src, uint32_t target,
    unsigned slot);
/* Drop every outgoing edge node owned by `old`. */
void ppc32_edge_drop_block_locked(const ppc32_block_t *old);
/* NULL every slot/ret link into `target`. */
void ppc32_edge_sever_target_locked(uint32_t target);
/* Link live sources (pagever still current in `page_ver`) to `fresh`. */
void ppc32_edge_backfill_locked(ppc32_block_t *fresh,
    const uint32_t *page_ver);
/* Free every edge node. */
void ppc32_edge_clear_all_locked(void);

/* Code occupancy bitmaps (SMC store fast path). Callers hold the cache
 * lock. `mark` records every 4 KiB page and every 64-byte line touched
 * by [start, end); `clear_all` drops both maps (no live block survives
 * a full flush); `pages_base` exposes the page bitmap baked into the
 * emitted guards. */
void ppc32_edge_code_mark(uint32_t start, uint32_t end);
bool ppc32_edge_code_any(uint32_t start, uint32_t end);
bool ppc32_edge_lines_any(uint32_t start, uint32_t end);
void ppc32_edge_code_clear_all(void);
const uint64_t *ppc32_edge_code_pages_base(void);
/* Record a bucket eviction performed while the cache epoch is `cur`. */
void ppc32_edge_note_evict(uint32_t cur);
/* O(1) exact range-overlap precheck for `invalidate_range_skip_locked`.
 * Returns false only when no live or retired block ever translated
 * [start, end): no 64-byte line of the range ever held code (the line
 * map is never cleared on bucket eviction), or the range is at most
 * 64 KiB with no eviction in `cur_epoch` and a direct probe of every
 * candidate block start finds no overlap. Conservative true on page
 * wraps, unmapped ranges, and large spans. `table` is the direct-mapped
 * block table; `skip` is the executing entry (never unmapped). */
bool ppc32_edge_has_overlap_locked(ppc32_block_t *const *table,
    uint32_t start, uint32_t end, const ppc32_block_t *skip,
    uint32_t cur_epoch);

#endif /* PPC32RT_DBT_CACHE_EDGE_H */
