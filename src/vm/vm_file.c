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
#include <stdbool.h>
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

/* Register-only variant for mappings the host kernel already filled
 * (non-A2 direct mmap): same inode record as populate_private, but no
 * userspace pread/memset, which would fault on read-only mappings and
 * on pages past EOF. */
void vm_file_note_private(int host_fd, uint32_t gva_base, uint32_t pages,
    uint64_t map_offset)
{
    file_register(host_fd, gva_base, pages, map_offset);
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

        file_register(host_fd, gva_base, pages,
            file_offset - (uint64_t)(gva - gva_base));
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

/* True when the 4 KiB page belongs to a registered file mapping. */
static bool page_is_file_backed(uint32_t page)
{
    size_t i;
    bool hit = false;

    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t span;

        if (g_inodes[i].in_use == 0U || g_inodes[i].pages == 0U) {
            continue;
        }
        span = (uint64_t)g_inodes[i].pages * 4096ULL;
        if ((uint64_t)page >= (uint64_t)g_inodes[i].gva_base &&
            (uint64_t)page < (uint64_t)g_inodes[i].gva_base + span) {
            hit = true;
            break;
        }
    }
    inode_unlock();
    return hit;
}

void vm_file_promote_cow(uint32_t gva_page)
{
    /* The bytes already sit at the canonical HVA (populated at mmap
     * time); promotion flips PAGE_COW_CLEAN to PAGE_COW_DIRTY. HVA and
     * every cached addend are unchanged by construction. The state flip
     * itself lives in the mem layer (g_page_state, src/vm/vm32_tlb.c);
     * the invalidate below drops any stale write_tag == ~0 entry, the
     * re-fill publishes the write tag once the layer marks the page
     * DIRTY, and the generation bump drops DBT code compiled under
     * CLEAN assumptions. Pages outside any registered file mapping are
     * left alone: filling a translation for them would arm a tag the
     * mem layer never backing-marked. */
    uintptr_t base = vm32_arena_base();
    uint32_t page = gva_page & ~(uint32_t)4095U;
    size_t i;

    if (base == 0U || !page_is_file_backed(page)) {
        return;
    }
    vm32_note_cow_dirty(page);
    vm32_tlb_fill(page, base + (uintptr_t)page, true, true);
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t span;

        if (g_inodes[i].in_use == 0U || g_inodes[i].pages == 0U) {
            continue;
        }
        span = (uint64_t)g_inodes[i].pages * 4096ULL;
        if ((uint64_t)page >= (uint64_t)g_inodes[i].gva_base &&
            (uint64_t)page < (uint64_t)g_inodes[i].gva_base + span) {
            atomic_fetch_add_explicit(&g_inodes[i].code_generation, 1U,
                memory_order_seq_cst);
        }
    }
    inode_unlock();
}

/* (dev,ino) lookup for the near-EOF fstat refresh on Soft-TLB misses
 * (m4) lands with the miss-path lane; hooks below key on host_fd. */

static uint64_t clamp_u64(uint64_t v, uint64_t lo, uint64_t hi)
{
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

/* Apply one EOF change to inode slot i (caller holds inode_lock).
 * Zeroes the resized span inside the mapping (the partial tail on
 * shrink, the regrown span on grow) and drops translations for pages
 * wholly beyond the new EOF so accesses there trap (PAGE_EOF_TRAP),
 * then publishes size/seq/generation. Direct A1 readers see zeroes
 * instead of stale bytes; A2 readers miss into -EACCES. The seq bumps
 * serialize concurrent near-EOF refreshes on Soft-TLB misses (m4). */
static void file_apply_truncate(size_t i, uint64_t new_size)
{
    uintptr_t base = vm32_arena_base();
    uint64_t cur = atomic_load_explicit(&g_inodes[i].file_size,
        memory_order_seq_cst);

    if (new_size == cur) {
        return;
    }
    if (base != 0U && g_inodes[i].pages != 0U) {
        uint64_t map_lo = g_inodes[i].map_offset;
        uint64_t map_hi = map_lo +
            (uint64_t)g_inodes[i].pages * 4096ULL;
        uint64_t lo = clamp_u64(new_size < cur ? new_size : cur, map_lo,
            map_hi);
        uint64_t hi = clamp_u64(new_size < cur ? cur : new_size, map_lo,
            map_hi);
        uint32_t gva_base = g_inodes[i].gva_base;

        if (hi > lo) {
            (void)memset((char *)base + (uintptr_t)gva_base +
                (uintptr_t)(lo - map_lo), 0, (size_t)(hi - lo));
        }
        {
            uint64_t eof = clamp_u64((new_size + 4095ULL) & ~4095ULL,
                map_lo, map_hi);

            if (map_hi > eof) {
                uint32_t glo =
                    (uint32_t)((uint64_t)gva_base + (eof - map_lo));
                uint32_t ghi =
                    (uint32_t)((uint64_t)gva_base + (map_hi - map_lo));

                vm32_tlb_invalidate_range(glo, ghi);
                /* Beyond-EOF pages trap (SIGBUS) until regrow. */
                vm32_mark_eof_trap(glo, ghi);
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

int vm_file_on_truncate(uint64_t new_size)
{
    /* Broadcast form (section 5.1): every registered mapping moves.
     * Prefer vm_file_on_truncate_fd, which matches one identity. */
    size_t i;

    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        if (g_inodes[i].in_use == 0U) {
            continue;
        }
        file_apply_truncate(i, new_size);
    }
    inode_unlock();
    return 0;
}

/* Identity truncate (RC-U3-r2 #4): only the mapping whose host_fd,
 * st_dev, and st_ino match the truncated description moves. A stale
 * record left behind by a closed fd reused for another file can no
 * longer corrupt an unrelated mapping. */
int vm_file_on_truncate_fd(int host_fd, uint64_t new_size)
{
    struct stat hs;
    size_t i;

    if (host_fd < 0) {
        return -EINVAL;
    }
    if (fstat(host_fd, &hs) != 0) {
        return -errno;
    }
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        if (g_inodes[i].in_use == 0U || g_inodes[i].host_fd != host_fd ||
            g_inodes[i].dev != (uint64_t)hs.st_dev ||
            g_inodes[i].ino != (uint64_t)hs.st_ino) {
            continue;
        }
        file_apply_truncate(i, new_size);
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
