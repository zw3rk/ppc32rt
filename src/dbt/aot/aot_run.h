/*
 * src/dbt/aot/aot_run.h — Persistent AOT block-cache run wiring.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cold/warm persistence for --cache/--aot-cache (Wave C2): every block
 * the DBT seals is appended to the cache file (guest_pc_base + code,
 * no site table yet — execution-from-cache is U6 work); a warm run
 * validates the header (magic/version/profile, fail-closed) and
 * consults each record before appending. Execution always uses the
 * freshly translated in-memory block, so a corrupt or stale cache can
 * never change guest behavior — only the append/lookup path is
 * exercised. The suite verifies cold-emit -> warm-reload output
 * identity plus stable file size (hits append nothing).
 */

#ifndef PPC32RT_DBT_AOT_RUN_H
#define PPC32RT_DBT_AOT_RUN_H

#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"

/* Record one sealed block (called after ppc32_cache_install). No-op
 * when ctx->cache_dir is NULL. Lazy-opens/validates the file once. */
void ppc32_aot_note_block(ppc32_ctx_t *ctx, uint32_t guest_pc,
    const void *code, uint32_t code_len);

#endif /* PPC32RT_DBT_AOT_RUN_H */
