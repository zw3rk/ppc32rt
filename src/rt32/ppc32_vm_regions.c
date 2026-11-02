/*
 * src/rt32/ppc32_vm_regions.c — Guest VMA region bookkeeping for the 4 GiB window
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from ppc32_vm.c (Phase 0, file-size discipline): sorted region
 * list with coalescing, gap finding, and mapped-range checks. All entry
 * points take the VM lock in ppc32_vm.c; the `*_locked` helpers here assume
 * the caller holds it (D19 CLONE_VM table-locking semantics carried over
 * from the i686rt substrate).
 */

#define _GNU_SOURCE
#include "ppc32_vm_priv.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

void vm_sync_from_ctx(ppc32_ctx_t *ctx)
{
    if (ctx->brk_base != 0U && g_vm_brk_base != ctx->brk_base) {
        g_vm_brk_base = ctx->brk_base;
        g_vm_brk_curr = ctx->brk_curr;
    }
}

void vm_sync_brk_to_ctx(ppc32_ctx_t *ctx)
{
    if (g_vm_brk_base != 0U) {
        ctx->brk_base = g_vm_brk_base;
        ctx->brk_curr = g_vm_brk_curr;
        if (g_vm_root_ctx != NULL && g_vm_root_ctx != ctx) {
            g_vm_root_ctx->brk_base = g_vm_brk_base;
            g_vm_root_ctx->brk_curr = g_vm_brk_curr;
        }
    }
}

void vm_copy_state_to_ctx(ppc32_ctx_t *dst)
{
    if (g_vm_brk_base != 0U) {
        dst->brk_base = g_vm_brk_base;
        dst->brk_curr = g_vm_brk_curr;
    }
    size_t count = (g_vm_region_count <= PPC32_MAX_REGIONS) ? g_vm_region_count : PPC32_MAX_REGIONS;
    dst->mmap_cursor  = g_vm_mmap_cursor;
    dst->region_count = count;
    if (count > 0U) {
        memcpy(dst->regions, g_vm_regions, count * sizeof(ppc32_region_t));
    }
}

void vm_sync_to_ctx(ppc32_ctx_t *ctx)
{
    vm_copy_state_to_ctx(ctx);
    if (g_vm_root_ctx != NULL && g_vm_root_ctx != ctx) {
        vm_copy_state_to_ctx(g_vm_root_ctx);
    }
}

void vm_remove_region_at(size_t idx)
{
    if (idx >= g_vm_region_count) {
        return;
    }
    if (idx + 1U < g_vm_region_count) {
        memmove(&g_vm_regions[idx], &g_vm_regions[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(ppc32_region_t));
    }
    g_vm_region_count--;
}

int vm_insert_region_raw_ex(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, int fd,
                            uint64_t offset, const char *name)
{
    if (start >= end || g_vm_region_count >= PPC32_MAX_REGIONS) {
        return -1;
    }
    size_t pos = 0U;
    while (pos < g_vm_region_count && g_vm_regions[pos].start < start) {
        pos++;
    }
    if (pos < g_vm_region_count) {
        memmove(&g_vm_regions[pos + 1U], &g_vm_regions[pos],
                (g_vm_region_count - pos) * sizeof(ppc32_region_t));
    }
    g_vm_region_count++;
    ppc32_region_t *r = &g_vm_regions[pos];
    r->start  = start;
    r->end    = end;
    r->prot   = prot;
    r->flags  = flags;
    r->fd     = fd;
    r->offset = (fd >= 0) ? offset : 0ULL;
    if (name) {
        snprintf(r->name, sizeof(r->name), "%s", name);
    } else {
        r->name[0] = '\0';
    }
    return 0;
}

int vm_insert_region_raw(uint32_t start, uint32_t end,
                         uint32_t prot, uint32_t flags, const char *name)
{
    return vm_insert_region_raw_ex(start, end, prot, flags, -1, 0ULL, name);
}

void vm_coalesce_regions_locked(void)
{
    if (g_vm_region_count < 2U) {
        return;
    }
    size_t dst = 0U;
    for (size_t src = 1U; src < g_vm_region_count; src++) {
        ppc32_region_t *prev = &g_vm_regions[dst];
        const ppc32_region_t *curr = &g_vm_regions[src];
        bool off_ok = (prev->fd < 0) ||
            (prev->offset + (uint64_t)(prev->end - prev->start) == curr->offset);
        if (prev->end == curr->start && prev->prot == curr->prot &&
            prev->flags == curr->flags && prev->fd == curr->fd &&
            off_ok && strcmp(prev->name, curr->name) == 0) {
            prev->end = curr->end;
        } else {
            dst++;
            if (dst != src) {
                g_vm_regions[dst] = *curr;
            }
        }
    }
    g_vm_region_count = dst + 1U;
}

void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end)
{
    size_t i = 0U;
    while (i < g_vm_region_count) {
        ppc32_region_t *r = &g_vm_regions[i];
        if (r->end <= unmap_start || r->start >= unmap_end) {
            i++;
            continue;
        }
        if (r->start >= unmap_start && r->end <= unmap_end) {
            vm_remove_region_at(i);
            continue;
        }
        if (r->start < unmap_start && r->end > unmap_end) {
            if (g_vm_region_count + 1U >= PPC32_MAX_REGIONS) {
                size_t before = g_vm_region_count;
                vm_coalesce_regions_locked();
                if (g_vm_region_count != before) {
                    i = 0U;
                    continue;
                }
            }
            ppc32_region_t orig = *r;
            uint64_t right_off = (orig.fd >= 0) ?
                (orig.offset + (uint64_t)(unmap_end - orig.start)) : 0ULL;
            if (vm_insert_region_raw_ex(unmap_end, orig.end,
                                        orig.prot, orig.flags, orig.fd,
                                        right_off, orig.name) == 0) {
                g_vm_regions[i].end = unmap_start;
                i += 2U;
            } else {
                i++;
            }
            continue;
        }
        if (r->start < unmap_start) {
            r->end = unmap_start;
        } else {
            if (r->fd >= 0) {
                r->offset += (uint64_t)(unmap_end - r->start);
            }
            r->start = unmap_end;
        }
        i++;
    }
}

int vm_record_region_ex_locked(uint32_t start, uint32_t end,
                               uint32_t prot, uint32_t flags, int fd,
                               uint64_t offset, const char *name)
{
    if (start >= end) {
        return -1;
    }
    char name_copy[64];
    if (name) {
        snprintf(name_copy, sizeof(name_copy), "%s", name);
    } else {
        name_copy[0] = '\0';
    }
    uint32_t clean_flags = flags & ~(PPC32_MAP_FIXED | PPC32_MAP_FIXED_NOREPLACE);
    vm_unmap_regions_locked(start, end);
    int rc = vm_insert_region_raw_ex(start, end, prot, clean_flags, fd, offset, name_copy);
    if (rc < 0) {
        vm_coalesce_regions_locked();
        rc = vm_insert_region_raw_ex(start, end, prot, clean_flags, fd, offset, name_copy);
    }
    vm_coalesce_regions_locked();
    return rc;
}

int vm_record_region_locked(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, const char *name)
{
    return vm_record_region_ex_locked(start, end, prot, flags, -1, 0ULL, name);
}

void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot)
{
    size_t i = 0U;
    while (i < g_vm_region_count) {
        ppc32_region_t *r = &g_vm_regions[i];
        if (r->end <= mp_start || r->start >= mp_end) {
            i++;
            continue;
        }
        if (r->start >= mp_start && r->end <= mp_end) {
            r->prot = prot;
            i++;
            continue;
        }
        ppc32_region_t orig = *r;
        if (orig.start < mp_start && orig.end > mp_end) {
            if (g_vm_region_count + 2U <= PPC32_MAX_REGIONS) {
                uint64_t mid_off = (orig.fd >= 0) ?
                    (orig.offset + (uint64_t)(mp_start - orig.start)) : 0ULL;
                uint64_t right_off = (orig.fd >= 0) ?
                    (orig.offset + (uint64_t)(mp_end - orig.start)) : 0ULL;
                r->end = mp_start;
                (void)vm_insert_region_raw_ex(mp_start, mp_end, prot, orig.flags,
                                              orig.fd, mid_off, orig.name);
                (void)vm_insert_region_raw_ex(mp_end, orig.end, orig.prot, orig.flags,
                                              orig.fd, right_off, orig.name);
                i += 3U;
            } else {
                r->prot = prot;
                i++;
            }
        } else if (orig.start < mp_start) {
            uint64_t right_off = (orig.fd >= 0) ?
                (orig.offset + (uint64_t)(mp_start - orig.start)) : 0ULL;
            if (vm_insert_region_raw_ex(mp_start, orig.end, prot, orig.flags,
                                        orig.fd, right_off, orig.name) == 0) {
                g_vm_regions[i].end = mp_start;
                i += 2U;
            } else {
                r->prot = prot;
                i++;
            }
        } else {
            r->start = mp_end;
            if (orig.fd >= 0) {
                r->offset = orig.offset + (uint64_t)(mp_end - orig.start);
            }
            if (vm_insert_region_raw_ex(orig.start, mp_end, prot, orig.flags,
                                        orig.fd, orig.offset, orig.name) == 0) {
                i += 2U;
            } else {
                r->start  = orig.start;
                r->offset = orig.offset;
                r->prot   = prot;
                i++;
            }
        }
    }
    vm_coalesce_regions_locked();
}

bool vm_range_overlaps_locked(uint32_t start, uint32_t end)
{
    for (size_t i = 0U; i < g_vm_region_count && g_vm_regions[i].start < end; i++) {
        if (g_vm_regions[i].end > start) {
            return true;
        }
    }
    return false;
}

bool vm_check_mapped_range_ex_locked(uint32_t start, uint32_t end,
                                     uint32_t *out_prot, uint32_t *out_flags,
                                     int *out_fd, uint64_t *out_offset,
                                     char *out_name, size_t name_sz)
{
    if (start >= end) {
        return false;
    }
    uint32_t cur = start;
    bool     first = true;
    uint32_t first_prot  = 0U;
    uint32_t first_flags = 0U;
    int      first_fd    = -1;
    uint64_t base_off    = 0ULL;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const ppc32_region_t *r = &g_vm_regions[i];
        if (r->end <= cur) {
            continue;
        }
        if (r->start > cur) {
            return false;
        }
        if (first) {
            first_prot  = r->prot;
            first_flags = r->flags & 0x23U;
            first_fd    = r->fd;
            base_off    = (r->fd >= 0) ?
                (r->offset + (uint64_t)(start - r->start)) : 0ULL;
            if (out_prot) {
                *out_prot = r->prot;
            }
            if (out_flags) {
                *out_flags = r->flags;
            }
            if (out_fd) {
                *out_fd = r->fd;
            }
            if (out_offset) {
                *out_offset = base_off;
            }
            if (out_name && name_sz > 0U) {
                snprintf(out_name, name_sz, "%s", r->name);
            }
            first = false;
        } else {
            bool fd_mismatch = (out_fd != NULL) && (r->fd != first_fd ||
                (first_fd >= 0 && r->offset != base_off + (uint64_t)(r->start - start)));
            if ((out_prot != NULL && r->prot != first_prot) ||
                (out_flags != NULL && (r->flags & 0x23U) != first_flags) ||
                fd_mismatch) {
                return false;
            }
        }
        if (r->end >= end) {
            return true;
        }
        cur = r->end;
    }
    return false;
}

bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz)
{
    return vm_check_mapped_range_ex_locked(start, end, out_prot, out_flags,
                                           NULL, NULL, out_name, name_sz);
}

int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(PPC32_MMAP_TOP_32 - PPC32_MMAP_BASE_32)) {
        return -1;
    }

    uint64_t cursor_cand = page_align_up((uint64_t)g_vm_mmap_cursor);
    if (cursor_cand < (uint64_t)PPC32_MMAP_BASE_32) {
        cursor_cand = (uint64_t)PPC32_MMAP_BASE_32;
    }
    if (cursor_cand + aligned_len <= (uint64_t)PPC32_MMAP_TOP_32 &&
        !vm_range_overlaps_locked((uint32_t)cursor_cand, (uint32_t)(cursor_cand + aligned_len))) {
        *out_va = (uint32_t)cursor_cand;
        return 0;
    }

    uint64_t cand = (uint64_t)PPC32_MMAP_BASE_32;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        uint64_t r_start = (uint64_t)g_vm_regions[i].start;
        uint64_t r_end   = page_align_up((uint64_t)g_vm_regions[i].end);
        if (r_end <= cand) {
            continue;
        }
        if (cand + aligned_len <= r_start) {
            break;
        }
        cand = r_end;
    }

    if (cand + aligned_len > (uint64_t)PPC32_MMAP_TOP_32) {
        return -1;
    }

    *out_va = (uint32_t)cand;
    return 0;
}
