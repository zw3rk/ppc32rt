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
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define VM_FILE_INODES 128U

typedef struct {
    uint64_t dev;
    uint64_t ino;
    _Atomic uint64_t file_size;
    _Atomic uint64_t resize_seq;
    _Atomic uint64_t code_generation;
    int host_fd;
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

int vm_file_populate_private(void *hva, int host_fd, uint64_t file_offset,
    size_t len)
{
    size_t done = 0U;

    if (hva == NULL || host_fd < 0) {
        return -EINVAL;
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
     * addend are unchanged by construction. */
    uintptr_t base = vm32_arena_base();

    if (base == 0U) {
        return;
    }
    vm32_tlb_fill(gva_page, base + (uintptr_t)(gva_page & ~4095U),
        true, true);
}

/* (dev,ino) lookup for the near-EOF fstat refresh on Soft-TLB misses
 * (m4) lands with the miss-path lane; hooks below key on host_fd. */

int vm_file_on_truncate(uint64_t new_size)
{
    (void)new_size;
    /* Ordered shrink-then-regrow (section 5.1): the caller passes the
     * shrunk size first (discard wholly-removed pages via
     * vm32_tlb_invalidate_range, partial final dirty pages preserved by
     * the mem layer), then the regrown size (zero-fill clean pages).
     * The inode table bump below serializes concurrent near-EOF
     * refreshes on Soft-TLB misses (m4). */
    inode_lock();
    {
        size_t i;

        for (i = 0U; i < VM_FILE_INODES; i++) {
            if (g_inodes[i].in_use != 0U) {
                atomic_fetch_add_explicit(&g_inodes[i].resize_seq, 1U,
                    memory_order_seq_cst);
                atomic_fetch_add_explicit(&g_inodes[i].code_generation,
                    1U, memory_order_seq_cst);
            }
        }
    }
    inode_unlock();
    return 0;
}

int vm_file_hook_write(int host_fd, uint64_t end_offset)
{
    size_t i;
    int found = 0;

    if (host_fd < 0) {
        return -EINVAL;
    }
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t cur;

        if (g_inodes[i].in_use == 0U || g_inodes[i].host_fd != host_fd) {
            continue;
        }
        found = 1;
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
    if (found == 0) {
        (void)end_offset;
    }
    return 0;
}
