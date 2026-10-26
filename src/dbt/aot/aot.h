/*
 * src/dbt/aot/aot.h — Persistent AOT block cache format (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 sections 4.3.3 and 7 (Wave U6 preview,
 * carried by the U3 ppc32 lane): translated blocks persist across runs
 * under --cache-dir with their purely-relative 24-byte
 * vm32_mem_site_t[] recovery tables serialized into the block payload,
 * so warm-cache signal rewinding, preemption PC lookup, and fault
 * recovery work identically cold or warm without pointer fixups.
 *
 * Layout (little-endian header, all offsets relative):
 *   file magic "PPC32AOT1" (8 bytes, no NUL)
 *   aot_file_hdr_t (version, block count, guest profile)
 *   per block: aot_block_hdr_t + code bytes + vm32_mem_site_t[nsites]
 *
 * Position independence rule: no absolute host or guest addresses are
 * stored except guest_pc_base deltas (guest_pc_delta inside each site);
 * the loader rebases code at mmap time and recomputes cont targets
 * from (rx_base + cont_insn_offset).
 */

#ifndef PPC32RT_DBT_AOT_H
#define PPC32RT_DBT_AOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vm/vm32.h"

#define PPC32_AOT_MAGIC "PPC32AOT1"
#define PPC32_AOT_MAGIC_LEN 8U
#define PPC32_AOT_VERSION 1U

typedef struct {
    char magic[PPC32_AOT_MAGIC_LEN];
    uint32_t version;
    uint32_t block_count;
    uint32_t profile;
    uint32_t reserved;
} ppc32_aot_hdr_t;

_Static_assert(sizeof(ppc32_aot_hdr_t) == 24,
    "ppc32_aot_hdr_t must be 24 bytes");

typedef struct {
    uint32_t guest_pc_base;
    uint32_t code_len;
    uint32_t site_count;
    uint32_t flags;
} ppc32_aot_block_hdr_t;

_Static_assert(sizeof(ppc32_aot_block_hdr_t) == 16,
    "ppc32_aot_block_hdr_t must be 16 bytes");

/* Append one translated block (code + its relative site table) to an
 * open cache file descriptor. Returns 0 on success. */
int ppc32_aot_append(int cache_fd, uint32_t guest_pc_base,
    const void *code, uint32_t code_len, const vm32_mem_site_t *sites,
    uint32_t site_count);

/* Scan a cache file for guest_pc_base; on hit, copy out code and sites
 * into caller buffers (cap-checked). Returns 1 on hit, 0 on miss,
 * negative errno on I/O or format failure (mutation rejection: bad
 * magic or version fails closed, never executes partial bytes). */
int ppc32_aot_lookup(int cache_fd, uint32_t guest_pc_base, void *code_out,
    uint32_t code_cap, vm32_mem_site_t *sites_out, uint32_t site_cap,
    uint32_t *code_len_out, uint32_t *site_count_out);

/* Validate a cache file header without loading blocks. */
bool ppc32_aot_header_ok(const ppc32_aot_hdr_t *hdr);

#endif /* PPC32RT_DBT_AOT_H */
