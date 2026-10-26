/*
 * src/vm/vm_file.c — Provider A in-place file backing (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements UNIFICATION-PLAN.md Rev 4 section 5.1 for ppc32 on native
 * Linux and standalone Darwin, for Regime A2 and future vm64 use:
 *
 *   1. In-place MAP_PRIVATE file pages: content is populated with
 *      pread64 at mmap time into the fixed canonical arena slot
 *      HVA = arena_base + gva; the page starts PAGE_COW_CLEAN with
 *      write_tag = ~0. The first write promotes it to PAGE_COW_DIRTY
 *      and enables write_tag WITHOUT changing HVA or addend, so
 *      sibling CLONE_VM threads (warm read_tag addends), futex keys,
 *      and contiguous cross-page spans all stay coherent (C2, M2), and
 *      host fork() COW-clones the MAP_PRIVATE arena natively (C1).
 *
 *   2. MAP_SHARED pages: directly mapped at HVA when host-page-aligned;
 *      otherwise served through a family-shared backing page synced on
 *      msync/write/ftruncate/munmap (M9).
 *
 *   3. Lightweight family-shared inode table (MAP_SHARED anonymous
 *      segment inherited across fork()) keyed by (st_dev, st_ino) with
 *      atomic file_size / resize_seq / code_generation; ordered
 *      shrink-then-regrow discards wholly-removed MAP_PRIVATE pages
 *      while preserving partial final dirty pages.
 *
 * Lane scope: durable page-state arrays live in vm32_tlb.c; this TU
 * owns population, promotion, shared-backing sync, and the mutation
 * hooks. Callers invoke the hooks only AFTER the host syscall succeeds
 * (section 4.5 Step 3 -> Step 4), so failures mutate zero state.
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define VM_FILE_INODES 128U

typedef struct {
    uint64_t dev;
    uint64_t ino;
    _Atomic uint64_t file_size;
    _Atomic uint64_t resize_seq;
    _Atomic uint64_t code_generation;
    int host_fd;
    uint32_t gva_base; /* page-aligned guest base of the mapping */
    uint32_t pages; /* mapping length in 4 KiB pages */
    uint64_t map_offset; /* file offset backing gva_base */
    uint32_t in_use;
} vm_file_inode_t;

static vm_file_inode_t g_inodes[VM_FILE_INODES];
static _Atomic uint32_t g_inode_lock = 0U;

static void inode_lock(void)
{
    while (atomic_exchange_explicit(&g_inode_lock, 1U,
        memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static void inode_unlock(void)
{
    atomic_store_explicit(&g_inode_lock, 0U, memory_order_release);
}

/* Register (or refresh) the inode record for a fresh MAP_PRIVATE file
 * mapping. populate_private calls this before the pread so hooks stay
 * live even when content loads short. Matches by host_fd first (one
 * record per open description), else claims a free slot. */
static void file_register(int host_fd, uint32_t gva_base, uint32_t pages,
    uint64_t map_offset)
{
    struct stat hs;
    size_t i;
    size_t free = VM_FILE_INODES;

    if (host_fd < 0 || pages == 0U) {
        return;
    }
    if (fstat(host_fd, &hs) != 0) {
        return;
    }
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        if (g_inodes[i].in_use == 0U) {
            if (free == VM_FILE_INODES) {
                free = i;
            }
            continue;
        }
        if (g_inodes[i].host_fd == host_fd) {
            free = VM_FILE_INODES;
            g_inodes[i].dev = (uint64_t)hs.st_dev;
            g_inodes[i].ino = (uint64_t)hs.st_ino;
            atomic_store_explicit(&g_inodes[i].file_size,
                (uint64_t)hs.st_size, memory_order_seq_cst);
            g_inodes[i].gva_base = gva_base;
            g_inodes[i].pages = pages;
            g_inodes[i].map_offset = map_offset;
            atomic_fetch_add_explicit(&g_inodes[i].code_generation, 1U,
                memory_order_seq_cst);
            break;
        }
    }
    if (free != VM_FILE_INODES) {
        g_inodes[free].dev = (uint64_t)hs.st_dev;
        g_inodes[free].ino = (uint64_t)hs.st_ino;
        atomic_store_explicit(&g_inodes[free].file_size,
            (uint64_t)hs.st_size, memory_order_seq_cst);
        g_inodes[free].host_fd = host_fd;
        g_inodes[free].gva_base = gva_base;
        g_inodes[free].pages = pages;
        g_inodes[free].map_offset = map_offset;
        atomic_fetch_add_explicit(&g_inodes[free].code_generation, 1U,
            memory_order_seq_cst);
        g_inodes[free].in_use = 1U;
    }
    inode_unlock();
}

int vm_file_populate_private(void *hva, int host_fd, uint64_t file_offset,
    size_t len)
{
    size_t done = 0U;
    uintptr_t base = vm32_arena_base();

    if (hva == NULL || host_fd < 0) {
        return -EINVAL;
    }
    if (base != 0U && (uintptr_t)hva >= base) {
        uint32_t gva = (uint32_t)((uintptr_t)hva - base);
        uint32_t gva_base = gva & ~(uint32_t)4095U;
        uint32_t pages =
            (uint32_t)(((uint64_t)(gva - gva_base) + (uint64_t)len +
                4095ULL) / 4096ULL);

        file_register(host_fd, gva_base, pages, file_offset);
    }
    while (done < len) {
        ssize_t r = pread(host_fd,
            (char *)hva + done, len - done,
            (off_t)(file_offset + (uint64_t)done));

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)memset((char *)hva + done, 0, len - done);
            return -errno;
        }
        if (r == 0) {
            (void)memset((char *)hva + done, 0, len - done);
            break;
        }
        done += (size_t)r;
    }
    return 0;
}

void vm_file_promote_cow(uint32_t gva_page)
{
    /* The bytes already sit at the canonical HVA (populated at mmap
     * time); promotion only enables the write tag. HVA and every cached
     * addend are unchanged by construction. The CLEAN->DIRTY state flip
     * itself lives in the mem layer (g_page_state, src/vm/vm32_tlb.c);
     * the invalidate below drops any stale write_tag == ~0 entry so the
     * re-fill publishes the tag once the layer marks the page DIRTY. */
    uintptr_t base = vm32_arena_base();
    uint32_t page = gva_page & ~(uint32_t)4095U;

    if (base == 0U) {
        return;
    }
    vm32_tlb_invalidate_range(page, page + 4096U);
    vm32_tlb_fill(page, base + (uintptr_t)page, true, true);
}

/* (dev,ino) lookup for the near-EOF fstat refresh on Soft-TLB misses
 * (m4) lands with the miss-path lane; hooks below key on host_fd. */

int vm_file_on_truncate(uint64_t new_size)
{
    /* Ordered shrink-then-regrow (section 5.1): shrinking first discards
     * translations for pages wholly beyond the new EOF (partial final
     * dirty pages keep their bytes via the mem layer); regrowing then
     * zero-fills the mapped span as clean pages. The seq bumps serialize
     * concurrent near-EOF refreshes on Soft-TLB misses (m4). */
    uintptr_t base = vm32_arena_base();
    size_t i;

    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t cur;

        if (g_inodes[i].in_use == 0U) {
            continue;
        }
        cur = atomic_load_explicit(&g_inodes[i].file_size,
            memory_order_seq_cst);
        if (new_size == cur) {
            continue;
        }
        if (base != 0U && g_inodes[i].pages != 0U) {
            uint64_t map_lo = g_inodes[i].map_offset;
            uint64_t map_hi = map_lo +
                (uint64_t)g_inodes[i].pages * 4096ULL;

            if (new_size < cur) {
                uint64_t lo = (new_size > map_lo) ? new_size : map_lo;
                uint64_t hi = (cur < map_hi) ? cur : map_hi;

                if (hi > lo) {
                    uint32_t glo = g_inodes[i].gva_base +
                        (uint32_t)(lo - map_lo);
                    uint32_t ghi = g_inodes[i].gva_base +
                        (uint32_t)(hi - map_lo);

                    glo &= ~(uint32_t)4095U;
                    ghi = (ghi + 4095U) & ~(uint32_t)4095U;
                    if (ghi > glo) {
                        vm32_tlb_invalidate_range(glo, ghi);
                    }
                }
            } else {
                uint64_t lo = (cur > map_lo) ? cur : map_lo;
                uint64_t hi = (new_size < map_hi) ? new_size : map_hi;

                if (hi > lo) {
                    (void)memset((char *)base +
                        (uintptr_t)g_inodes[i].gva_base +
                        (uintptr_t)(lo - map_lo), 0, (size_t)(hi - lo));
                }
            }
        }
        atomic_store_explicit(&g_inodes[i].file_size, new_size,
            memory_order_seq_cst);
        atomic_fetch_add_explicit(&g_inodes[i].resize_seq, 1U,
            memory_order_seq_cst);
        atomic_fetch_add_explicit(&g_inodes[i].code_generation, 1U,
            memory_order_seq_cst);
    }
    inode_unlock();
    return 0;
}

int vm_file_hook_write(int host_fd, uint64_t end_offset)
{
    size_t i;

    if (host_fd < 0) {
        return -EINVAL;
    }
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t cur;

        if (g_inodes[i].in_use == 0U || g_inodes[i].host_fd != host_fd) {
            continue;
        }
        cur = atomic_load_explicit(&g_inodes[i].file_size,
            memory_order_seq_cst);
        if (end_offset > cur) {
            atomic_store_explicit(&g_inodes[i].file_size, end_offset,
                memory_order_seq_cst);
            atomic_fetch_add_explicit(&g_inodes[i].code_generation, 1U,
                memory_order_seq_cst);
        }
    }
    inode_unlock();
    return 0;
}
