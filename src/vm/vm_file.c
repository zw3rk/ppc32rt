/*
 * src/vm/vm_file.c — Provider A in-place file backing (Wave U3 lane U3-ppc32)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 5.1 for ppc32 (Regime A2 and future
 * vm64 use):
 *
 *   1. In-place MAP_PRIVATE file pages: content is populated with
 *      pread64 at mmap time into the fixed canonical arena slot
 *      HVA = arena_base + gva; the page starts PAGE_COW_CLEAN with
 *      write_tag = ~0. The first write promotes it to PAGE_COW_DIRTY
 *      and enables write_tag WITHOUT changing HVA or addend, so
 *      sibling CLONE_VM threads, futex keys, and contiguous cross-page
 *      spans all stay coherent, and host fork() COW-clones the
 *      MAP_PRIVATE arena natively.
 *
 *   2. MAP_SHARED pages: directly mapped at HVA when host-page-aligned;
 *      otherwise served through family-shared staging objects in
 *      vm_file_stage.c, coherent across overlapping aliases by inode.
 *
 *   3. Lightweight family-shared inode table (MAP_SHARED anonymous
 *      segment inherited across fork()) keyed by (st_dev, st_ino) with
 *      atomic file_size / resize_seq / code_generation; ordered
 *      shrink-then-regrow discards wholly-removed MAP_PRIVATE pages
 *      while preserving partial final dirty pages.
 *
 * Lane scope: durable page-state arrays live in vm32_tlb.c; this TU
 * owns population, promotion, EOF trapping, and the mutation hooks.
 * Callers invoke the hooks only AFTER the host syscall succeeds, so
 * failures mutate zero state. Every mapping range gets its own inode
 * slot (P32-R4-10); mutation hooks match by (st_dev, st_ino), never by
 * reusable fd numbers.
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"
#include "rt32/ppc32_vm_priv.h"
#include "vm/vm_file_int.h"

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
    uint32_t gva_base;
    uint32_t pages;
    uint64_t map_offset;
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

/* Register the inode record for a fresh file mapping. Every
 * (fd, gva_base) range owns its own slot (P32-R4-10): re-registering
 * the identical range refreshes it, any other range claims a free
 * slot, so a second mapping from the same fd never discards the
 * first. populate_private calls this before the pread so hooks stay
 * live even when content loads short. */
static void file_register(int host_fd, uint32_t gva_base, uint32_t pages,
    uint64_t map_offset)
{
    uint64_t dev;
    uint64_t ino;
    uint64_t fsz;
    size_t i;
    size_t free = VM_FILE_INODES;

    if (host_fd < 0 || pages == 0U) {
        return;
    }
    if (vm_file_fd_identity(host_fd, &dev, &ino, &fsz, NULL) != 0) {
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
        if (g_inodes[i].host_fd == host_fd &&
            g_inodes[i].gva_base == gva_base &&
            g_inodes[i].pages == pages &&
            g_inodes[i].map_offset == map_offset) {
            g_inodes[i].dev = dev;
            g_inodes[i].ino = ino;
            atomic_store_explicit(&g_inodes[i].file_size, fsz,
                memory_order_seq_cst);
            atomic_fetch_add_explicit(&g_inodes[i].code_generation, 1U,
                memory_order_seq_cst);
            inode_unlock();
            return;
        }
    }
    if (free != VM_FILE_INODES) {
        g_inodes[free].dev = dev;
        g_inodes[free].ino = ino;
        atomic_store_explicit(&g_inodes[free].file_size, fsz,
            memory_order_seq_cst);
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

/* Drop (or trim) inode records overlapping [start_gva, end_gva): the
 * range is being unmapped or replaced, so hooks must no longer treat
 * it as file-backed. Fully covered records are reclaimed for reuse;
 * edge overlaps shrink the record; an interior hole splits it when a
 * free slot exists, otherwise the record is conservatively dropped. */
void vm_file_untrack_range(uint32_t start_gva, uint32_t end_gva)
{
    size_t i;

    if (end_gva <= start_gva) {
        return;
    }
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t lo;
        uint64_t hi;

        if (g_inodes[i].in_use == 0U || g_inodes[i].pages == 0U) {
            continue;
        }
        lo = (uint64_t)g_inodes[i].gva_base;
        hi = lo + (uint64_t)g_inodes[i].pages * 4096ULL;
        if (hi <= (uint64_t)start_gva || lo >= (uint64_t)end_gva) {
            continue;
        }
        if ((uint64_t)start_gva <= lo && (uint64_t)end_gva >= hi) {
            g_inodes[i].in_use = 0U;
            g_inodes[i].pages = 0U;
            continue;
        }
        if ((uint64_t)start_gva <= lo) {
            uint32_t cut = (uint32_t)((uint64_t)end_gva - lo);

            cut &= ~(uint32_t)4095U;
            g_inodes[i].map_offset += (uint64_t)cut;
            g_inodes[i].gva_base += cut;
            g_inodes[i].pages -= cut / 4096U;
            continue;
        }
        if ((uint64_t)end_gva >= hi) {
            g_inodes[i].pages =
                (uint32_t)(((uint64_t)start_gva - lo) / 4096ULL);
            continue;
        }
        {
            uint32_t left_pages =
                (uint32_t)(((uint64_t)start_gva - lo) / 4096ULL);
            uint32_t right_gva = (uint32_t)(((uint64_t)end_gva + 4095ULL) &
                ~4095ULL);
            uint32_t right_pages =
                (uint32_t)((hi - (uint64_t)right_gva) / 4096ULL);
            uint64_t right_off = g_inodes[i].map_offset +
                ((uint64_t)right_gva - lo);
            size_t j;
            size_t free = VM_FILE_INODES;

            for (j = 0U; j < VM_FILE_INODES; j++) {
                if (g_inodes[j].in_use == 0U) {
                    free = j;
                    break;
                }
            }
            if (free == VM_FILE_INODES || right_pages == 0U) {
                g_inodes[i].pages = left_pages;
                if (free == VM_FILE_INODES) {
                    g_inodes[i].in_use = 0U;
                    g_inodes[i].pages = 0U;
                }
                continue;
            }
            g_inodes[i].pages = left_pages;
            g_inodes[free].dev = g_inodes[i].dev;
            g_inodes[free].ino = g_inodes[i].ino;
            atomic_store_explicit(&g_inodes[free].file_size,
                atomic_load_explicit(&g_inodes[i].file_size,
                    memory_order_seq_cst),
                memory_order_seq_cst);
            atomic_store_explicit(&g_inodes[free].resize_seq,
                atomic_load_explicit(&g_inodes[i].resize_seq,
                    memory_order_seq_cst),
                memory_order_seq_cst);
            atomic_store_explicit(&g_inodes[free].code_generation,
                atomic_load_explicit(&g_inodes[i].code_generation,
                    memory_order_seq_cst),
                memory_order_seq_cst);
            g_inodes[free].host_fd = g_inodes[i].host_fd;
            g_inodes[free].gva_base = right_gva;
            g_inodes[free].pages = right_pages;
            g_inodes[free].map_offset = right_off;
            g_inodes[free].in_use = 1U;
        }
    }
    inode_unlock();
}

/* Mark guest pages wholly beyond EOF as trap pages (SIGBUS on access):
 * staged MAP_SHARED mappings have no host page fault to supply it, and
 * A2 private in-place mappings are pread-filled with accessible zeroes
 * that Linux would SIGBUS instead. Only whole pages past the
 * rounded-up EOF move; the partial tail page keeps its zero-filled
 * bytes. An empty file traps the whole mapping, as does a mapping
 * starting at or past the rounded EOF (P32-R4-7). */
void vm_file_trap_beyond_eof(int host_fd, uint32_t gva_base,
    uint64_t map_offset, size_t len)
{
    uint64_t fsz;
    uint64_t eof_page;
    uint64_t map_end;
    uint64_t first_off;
    uint32_t first;
    uint32_t last;

    if (host_fd < 0 || len == 0U) {
        return;
    }
    if (vm_file_fd_identity(host_fd, NULL, NULL, &fsz, NULL) != 0) {
        return;
    }
    eof_page = (fsz + 4095ULL) & ~4095ULL;
    map_end = map_offset + (uint64_t)len;
    if (map_end <= eof_page) {
        return;
    }
    first_off = (eof_page > map_offset) ? eof_page : map_offset;
    first = gva_base + (uint32_t)(first_off - map_offset);
    last = gva_base + (uint32_t)len;
    if (last <= first) {
        return;
    }
    vm32_mark_eof_trap(first, last);
}

/* Fork coordination: the parent holds the inode lock across fork so no
 * registration is half-written at the snapshot; the child drops the
 * inherited locked value (its owner is gone). Records are inherited
 * through the MAP_PRIVATE arena COW like the pages they describe. */
void vm_file_fork_prepare(void)
{
    inode_lock();
}

void vm_file_fork_parent(void)
{
    inode_unlock();
}

void vm_file_fork_child(void)
{
    atomic_store_explicit(&g_inode_lock, 0U, memory_order_release);
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
     * mem layer never backing-marked. Runs after the TLB miss path
     * released its lock, so taking the inode lock here nests
     * TLB -> inode, matching the global order (P32-R4-8). */
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

/* Zero an in-place private file span without faulting on read-only
 * host pages (P32-R4-9): widen the covering host pages writable,
 * memset, then restore the per-sub-page union (never PROT_EXEC).
 * Best-effort: an mprotect failure skips the zeroing. A2-only; on A1
 * the kernel owns private file pages and handles truncation itself. */
static void file_zero_private_span(uint32_t lo, uint32_t hi)
{
    uintptr_t base;
    size_t h;
    uintptr_t hlo;
    uintptr_t hhi;

    if (hi <= lo || !vm32_is_a2()) {
        return;
    }
    base = vm32_arena_base();
    if (base == 0U) {
        return;
    }
    h = vm32_host_page_size();
    if (h < VM32_GUEST_PAGE_SIZE) {
        h = VM32_GUEST_PAGE_SIZE;
    }
    hlo = (base + (uint64_t)lo) & ~(h - 1U);
    hhi = ((base + (uint64_t)hi) + h - 1U) & ~(h - 1U);
    if (hhi <= hlo) {
        return;
    }
    if (mprotect((void *)hlo, (size_t)(hhi - hlo),
            PROT_READ | PROT_WRITE) != 0) {
        return;
    }
    (void)memset((void *)(base + (uint64_t)lo), 0, (size_t)(hi - lo));
    (void)vm32_sync_host_range(lo, hi);
}

/* Truncate in two phases (P32-R4-8/R4-9). Phase 1 runs under the inode
 * lock and only publishes size/seq/generation for every slot of the
 * (dev, ino) identity — no guest access, no TLB calls — so it never
 * nests inode -> TLB against fork's TLB -> inode order. Phase 2 runs
 * under the VM lock with the inode lock released: per-region guest
 * updates (safe staged pwrite zeros, temp-writable private zeroing on
 * A2, kernel-owned direct mappings untouched), TLB invalidation, and
 * EOF trap marking. A stale record left behind by a closed fd reused
 * for another file cannot match: identity is (dev, ino) (P32-R4-10). */
static void file_truncate_phase1(uint64_t dev, uint64_t ino,
    uint64_t new_size, uint64_t *old_out)
{
    size_t i;
    bool known = false;
    uint64_t old = new_size;

    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t cur;

        if (g_inodes[i].in_use == 0U || g_inodes[i].dev != dev ||
            g_inodes[i].ino != ino) {
            continue;
        }
        cur = atomic_load_explicit(&g_inodes[i].file_size,
            memory_order_seq_cst);
        if (!known || cur > old) {
            old = cur;
            known = true;
        }
        if (new_size == cur) {
            continue;
        }
        atomic_store_explicit(&g_inodes[i].file_size, new_size,
            memory_order_seq_cst);
        atomic_fetch_add_explicit(&g_inodes[i].resize_seq, 1U,
            memory_order_seq_cst);
        atomic_fetch_add_explicit(&g_inodes[i].code_generation, 1U,
            memory_order_seq_cst);
    }
    inode_unlock();
    if (old_out != NULL) {
        *old_out = known ? old : new_size;
    }
}

/* Re-record a regrown file span [glo, ghi) as accessible mapping state
 * (P32-R4-9 grow path): pages trapped by an earlier shrink become
 * readable zeros again once the file covers them. */
static void file_truncate_rerecord(uint32_t glo, uint32_t ghi,
    uint8_t prot, bool is_shared)
{
    uint8_t state;

    if (ghi <= glo) {
        return;
    }
    state = is_shared ? (uint8_t)VM32_PAGE_SHARED :
        (uint8_t)VM32_PAGE_COW_CLEAN;
    vm32_record_map(glo, ghi, (uint8_t)(prot & 0x7U), state);
    (void)vm32_sync_host_range(glo, ghi);
    vm32_tlb_invalidate_range(glo, ghi);
}

static void file_truncate_phase2(uint64_t dev, uint64_t ino,
    uint64_t old_size, uint64_t new_size)
{
    uint64_t new_eof = (new_size + 4095ULL) & ~4095ULL;
    uint64_t zlo = (old_size < new_size) ? old_size : new_size;
    uint64_t zhi = (old_size < new_size) ? new_size : old_size;
    bool grew = new_size > old_size;
    size_t i;
    bool held = vm_lock_held_by_self();

    if (!held) {
        vm_lock_acquire();
    }
    for (i = 0U; i < g_vm_region_count; i++) {
        const ppc32_region_t *r = &g_vm_regions[i];
        uint64_t rlo;
        uint64_t rhi;
        uint64_t tlo;
        uint64_t zrlo;
        uint64_t zrhi;
        uint64_t rdev;
        uint64_t rino;
        bool is_shared;

        if (r->fd < 0 || (r->flags & PPC32_MAP_ANONYMOUS) != 0U) {
            continue;
        }
        if (vm_file_fd_identity(r->fd, &rdev, &rino, NULL, NULL) != 0 ||
            rdev != dev || rino != ino) {
            continue;
        }
        if (r->end <= r->start) {
            continue;
        }
        rlo = r->offset;
        rhi = rlo + (uint64_t)(r->end - r->start);
        is_shared = (r->flags & 0x01U) != 0U;
        /* Zero the resized span inside staged backing and in-place
         * private pages; direct kernel-backed mappings are left for
         * the kernel (P32-R4-9). */
        zrlo = (rlo > zlo) ? rlo : zlo;
        zrhi = (rhi < zhi) ? rhi : zhi;
        if (zrhi > zrlo) {
            vm_file_shared_truncate_range(r->fd, zrlo, zrhi);
            if (!is_shared) {
                file_zero_private_span(
                    (uint32_t)((uint64_t)r->start + (zrlo - rlo)),
                    (uint32_t)((uint64_t)r->start + (zrhi - rlo)));
            }
        }
        /* Pages wholly beyond the new EOF trap (SIGBUS) in every
         * mapping kind; regrown spans become accessible again. */
        tlo = (rlo > new_eof) ? rlo : new_eof;
        if (rhi > tlo) {
            uint32_t glo_trap =
                (uint32_t)((uint64_t)r->start + (tlo - rlo));
            uint32_t ghi_trap = r->end;

            vm32_tlb_invalidate_range(glo_trap, ghi_trap);
            vm32_mark_eof_trap(glo_trap, ghi_trap);
        }
        if (grew) {
            uint64_t old_eof = (old_size + 4095ULL) & ~4095ULL;
            uint64_t urlo = (rlo > old_eof) ? rlo : old_eof;
            uint64_t urhi = (rhi < new_size) ? rhi : new_size;

            if (urhi > urlo) {
                file_truncate_rerecord(
                    (uint32_t)((uint64_t)r->start + (urlo - rlo)),
                    (uint32_t)((uint64_t)r->start + (urhi - rlo)),
                    (uint8_t)(r->prot & 0x7U), is_shared);
            }
        }
    }
    if (!held) {
        vm_lock_release();
    }
}

/* Identity truncate: only mappings of the truncated file move. The
 * file is already resized by the host ftruncate; this publishes the
 * new size and reconciles guest state. Self-serializes through the
 * outer VM lock (phase 2) after a lock-free inode update (phase 1),
 * honoring the canonical VM -> TLB -> inode order (P32-R4-8). */
int vm_file_on_truncate_fd(int host_fd, uint64_t new_size)
{
    uint64_t dev;
    uint64_t ino;
    uint64_t old_size;

    if (host_fd < 0) {
        return -EINVAL;
    }
    if (vm_file_fd_identity(host_fd, &dev, &ino, NULL, NULL) != 0) {
        return -errno;
    }
    file_truncate_phase1(dev, ino, new_size, &old_size);
    file_truncate_phase2(dev, ino, old_size, new_size);
    return 0;
}

int vm_file_hook_write(int host_fd, uint64_t end_offset)
{
    uint64_t dev;
    uint64_t ino;
    size_t i;
    bool held;

    if (host_fd < 0) {
        return -EINVAL;
    }
    if (vm_file_fd_identity(host_fd, &dev, &ino, NULL, NULL) != 0) {
        return -errno;
    }
    /* Canonical order: VM outer, inode inner (P32-R4-8). */
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    inode_lock();
    for (i = 0U; i < VM_FILE_INODES; i++) {
        uint64_t cur;

        if (g_inodes[i].in_use == 0U || g_inodes[i].dev != dev ||
            g_inodes[i].ino != ino) {
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
    if (!held) {
        vm_lock_release();
    }
    return 0;
}
