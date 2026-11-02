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
#include "rt32/ppc32_vm_priv.h"

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
 * staged MAP_SHARED mappings have no host page fault to supply it.
 * Only whole pages past the rounded-up EOF move; the partial tail
 * page keeps its zero-filled bytes. Private mappings keep zero-filled
 * reads (correct Linux behavior), so callers gate on MAP_SHARED. */
void vm_file_trap_beyond_eof(int host_fd, uint32_t gva_base,
    uint64_t map_offset, size_t len)
{
    struct stat hs;
    uint64_t fsz;
    uint64_t eof_page;
    uint64_t map_end;
    uint32_t first;
    uint32_t last;

    if (host_fd < 0 || len == 0U) {
        return;
    }
    if (fstat(host_fd, &hs) != 0 || hs.st_size <= 0) {
        return;
    }
    fsz = (uint64_t)hs.st_size;
    eof_page = (fsz + 4095ULL) & ~4095ULL;
    map_end = map_offset + (uint64_t)len;
    if (eof_page < map_offset || map_end <= eof_page) {
        return;
    }
    first = gva_base + (uint32_t)(eof_page - map_offset);
    last = gva_base + (uint32_t)len;
    if (last <= first) {
        return;
    }
    vm32_mark_eof_trap(first, last);
}

/* ---- A2 sub-page MAP_SHARED staging (P32-R3-3) ----
 *
 * On hosts with H > 4096 a guest MAP_SHARED mapping whose file offset is
 * 4 KiB-aligned but not host-aligned cannot be mmap'd MAP_SHARED from the
 * file directly (host offsets need H alignment). Staging a private copy
 * would silently break alias and fork sharing, so each distinct
 * (st_dev, st_ino, file_offset) family shares one memfd-backed staging
 * object sized to the host-rounded mapping length: every alias mmaps the
 * SAME object MAP_SHARED at its own GVA, so stores through one alias (or
 * across fork, which keeps MAP_SHARED shared) are visible through all of
 * them. Fill comes from the file at map time; short reads (EOF) zero-fill
 * and pages wholly beyond the rounded-up EOF still trap via
 * vm_file_trap_beyond_eof. Write-back to the file is best-effort on
 * munmap (EOF-clamped, errors ignored); no guest msync handler exists to
 * drive it earlier. Partially overlapping (non-identical) ranges stage as
 * separate objects and cohere only within identical ranges.
 *
 * All entry points run under the VM lock (the mmap/munmap/mremap paths
 * hold it), which also serializes them against the fork snapshot, so no
 * extra lock is needed. Slots are dropped by the region-side GC once no
 * live region references their (dev, ino, offset) key. */

#define VM_FILE_STAGED_GROUPS 32U

typedef struct {
    uint32_t in_use;
    uint64_t dev;
    uint64_t ino;
    uint64_t file_offset;
    size_t staged_len;
    int stage_fd;
    int src_fd;
    uint64_t file_size;
    int64_t mtime;
} vm_file_staged_t;

static vm_file_staged_t g_staged[VM_FILE_STAGED_GROUPS];

static size_t stage_round_host(size_t len)
{
    size_t h = vm32_host_page_size();

    if (h < VM32_GUEST_PAGE_SIZE) {
        h = VM32_GUEST_PAGE_SIZE;
    }
    return (len + h - 1U) & ~(h - 1U);
}

static int stage_pwrite_all(int fd, const void *buf, size_t len,
    uint64_t off)
{
    size_t done = 0U;

    while (done < len) {
        ssize_t w = pwrite(fd, (const char *)buf + done, len - done,
            (off_t)(off + (uint64_t)done));

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (w == 0) {
            return -EIO;
        }
        done += (size_t)w;
    }
    return 0;
}

/* Fill [stage_off, stage_off + len) of the staging object from the file
 * at file_off; short reads (EOF) zero-fill the remainder. */
static int stage_fill(int stage_fd, int src_fd, uint64_t file_off,
    size_t stage_off, size_t len)
{
    char buf[8192];
    size_t done = 0U;

    while (done < len) {
        size_t want = (len - done < sizeof buf) ? len - done : sizeof buf;
        ssize_t r = pread(src_fd, buf, want,
            (off_t)(file_off + (uint64_t)done));

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (r == 0) {
            size_t z = done;

            (void)memset(buf, 0, sizeof buf);
            while (z < len) {
                size_t w = (len - z < sizeof buf) ? len - z : sizeof buf;
                int rc = stage_pwrite_all(stage_fd, buf, w,
                    (uint64_t)stage_off + (uint64_t)z);

                if (rc != 0) {
                    return rc;
                }
                z += w;
            }
            return 0;
        }
        {
            int rc = stage_pwrite_all(stage_fd, buf, (size_t)r,
                (uint64_t)stage_off + (uint64_t)done);

            if (rc != 0) {
                return rc;
            }
        }
        done += (size_t)r;
    }
    return 0;
}

/* Copy one group's staged bytes back into the file over [wlo, whi),
 * clamped to the current file size so zero-filled EOF tails never extend
 * the file. Best-effort: read/write errors stop the copy silently. */
static void stage_drain_locked(size_t idx, uint64_t wlo, uint64_t whi)
{
    char buf[8192];
    struct stat hs;
    uint64_t fsz;
    uint64_t off;

    if (idx >= VM_FILE_STAGED_GROUPS || g_staged[idx].in_use == 0U) {
        return;
    }
    if (fstat(g_staged[idx].src_fd, &hs) != 0 || hs.st_size <= 0) {
        return;
    }
    fsz = (uint64_t)hs.st_size;
    if (whi > fsz) {
        whi = fsz;
    }
    if (whi <= wlo) {
        return;
    }
    off = wlo;
    while (off < whi) {
        size_t want = ((uint64_t)sizeof buf < whi - off) ?
            sizeof buf : (size_t)(whi - off);
        ssize_t r = pread(g_staged[idx].stage_fd, buf, want,
            (off_t)(off - g_staged[idx].file_offset));

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        if (stage_pwrite_all(g_staged[idx].src_fd, buf, (size_t)r,
                off) != 0) {
            break;
        }
        off += (uint64_t)r;
    }
    g_staged[idx].file_size = fsz;
    g_staged[idx].mtime = (int64_t)hs.st_mtime;
}

int vm_file_shared_acquire(int src_fd, uint64_t file_offset, size_t len,
    int *out_stage_fd)
{
    struct stat hs;
    uint64_t fsz;
    size_t need;
    size_t i;
    size_t free = VM_FILE_STAGED_GROUPS;

    if (src_fd < 0 || len == 0U || out_stage_fd == NULL) {
        return -EINVAL;
    }
    if (fstat(src_fd, &hs) != 0) {
        return -errno;
    }
    need = stage_round_host(len);
    if (need == 0U) {
        return -ENOMEM;
    }
    fsz = (hs.st_size > 0) ? (uint64_t)hs.st_size : 0ULL;
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        int rc;

        if (g_staged[i].in_use == 0U) {
            if (free == VM_FILE_STAGED_GROUPS) {
                free = i;
            }
            continue;
        }
        if (g_staged[i].dev != (uint64_t)hs.st_dev ||
            g_staged[i].ino != (uint64_t)hs.st_ino ||
            g_staged[i].file_offset != file_offset) {
            continue;
        }
        if (g_staged[i].file_size != fsz ||
            g_staged[i].mtime != (int64_t)hs.st_mtime) {
            /* P32-R3-3: write back live alias stores before the refill. */
            stage_drain_locked(i, file_offset,
                file_offset + (uint64_t)g_staged[i].staged_len);
            if (g_staged[i].staged_len < need &&
                ftruncate(g_staged[i].stage_fd, (off_t)need) != 0) {
                return -errno;
            }
            g_staged[i].staged_len =
                (g_staged[i].staged_len < need) ? need : g_staged[i].staged_len;
            rc = stage_fill(g_staged[i].stage_fd, src_fd, file_offset,
                0U, g_staged[i].staged_len);
            if (rc != 0) {
                return rc;
            }
        } else if (g_staged[i].staged_len < need) {
            size_t old = g_staged[i].staged_len;

            if (ftruncate(g_staged[i].stage_fd, (off_t)need) != 0) {
                return -errno;
            }
            g_staged[i].staged_len = need;
            rc = stage_fill(g_staged[i].stage_fd, src_fd, file_offset,
                old, need - old);
            if (rc != 0) {
                return rc;
            }
        }
        g_staged[i].file_size = fsz;
        g_staged[i].mtime = (int64_t)hs.st_mtime;
        *out_stage_fd = g_staged[i].stage_fd;
        return 0;
    }
    if (free == VM_FILE_STAGED_GROUPS) {
        return -ENOMEM;
    }
    {
        int sfd = vm_create_shared_anon_fd((uint64_t)need);
        int dfd;
        int rc;

        if (sfd < 0) {
            return sfd;
        }
        dfd = vm_dup_fd(src_fd);
        if (dfd < 0) {
            (void)close(sfd);
            return -errno;
        }
        rc = stage_fill(sfd, src_fd, file_offset, 0U, need);
        if (rc != 0) {
            (void)close(sfd);
            (void)close(dfd);
            return rc;
        }
        g_staged[free].dev = (uint64_t)hs.st_dev;
        g_staged[free].ino = (uint64_t)hs.st_ino;
        g_staged[free].file_offset = file_offset;
        g_staged[free].staged_len = need;
        g_staged[free].stage_fd = sfd;
        g_staged[free].src_fd = dfd;
        g_staged[free].file_size = fsz;
        g_staged[free].mtime = (int64_t)hs.st_mtime;
        g_staged[free].in_use = 1U;
        *out_stage_fd = sfd;
        return 0;
    }
}

void vm_file_shared_writeback_file_range(int fd, uint64_t lo, uint64_t hi)
{
    struct stat hs;
    size_t i;

    if (fd < 0 || hi <= lo) {
        return;
    }
    if (fstat(fd, &hs) != 0) {
        return;
    }
    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        uint64_t glo;
        uint64_t ghi;

        if (g_staged[i].in_use == 0U ||
            g_staged[i].dev != (uint64_t)hs.st_dev ||
            g_staged[i].ino != (uint64_t)hs.st_ino) {
            continue;
        }
        glo = g_staged[i].file_offset;
        ghi = glo + (uint64_t)g_staged[i].staged_len;
        if (ghi <= lo || glo >= hi) {
            continue;
        }
        stage_drain_locked(i, (glo > lo) ? glo : lo,
            (ghi < hi) ? ghi : hi);
    }
}

size_t vm_file_shared_group_count(void)
{
    return VM_FILE_STAGED_GROUPS;
}

bool vm_file_shared_group_key(size_t idx, uint64_t *dev_out,
    uint64_t *ino_out, uint64_t *off_out)
{
    if (idx >= VM_FILE_STAGED_GROUPS || g_staged[idx].in_use == 0U ||
        dev_out == NULL || ino_out == NULL || off_out == NULL) {
        return false;
    }
    *dev_out = g_staged[idx].dev;
    *ino_out = g_staged[idx].ino;
    *off_out = g_staged[idx].file_offset;
    return true;
}

/* Map one staged sub-page MAP_SHARED file range at its (host-aligned)
 * guest address: acquire (or reuse) the family staging object and mmap it
 * MAP_SHARED over the arena slice, then publish guest permissions. The
 * region record (caller's file identity) stays owned by the caller.
 * Returns 0 or a negative errno. Runs under the VM lock. */
int vm_file_shared_map_at(void *host_target, size_t map_len, int use_fd,
    uint64_t host_off, uint32_t target_va, uint32_t map_end, uint8_t prot,
    uint8_t state)
{
    int stage_fd = -1;
    int rc = vm_file_shared_acquire(use_fd, host_off, map_len, &stage_fd);
    void *res;

    if (rc != 0) {
        return rc;
    }
    res = mmap(host_target, map_len, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED, stage_fd, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    vm32_record_map(target_va, map_end, prot, state);
    (void)vm32_sync_host_range(target_va, map_end);
    return 0;
}

void vm_file_shared_drop_group(uint64_t dev, uint64_t ino, uint64_t off)
{
    size_t i;

    for (i = 0U; i < VM_FILE_STAGED_GROUPS; i++) {
        if (g_staged[i].in_use == 0U || g_staged[i].dev != dev ||
            g_staged[i].ino != ino || g_staged[i].file_offset != off) {
            continue;
        }
        stage_drain_locked(i, g_staged[i].file_offset,
            g_staged[i].file_offset + (uint64_t)g_staged[i].staged_len);
        (void)close(g_staged[i].stage_fd);
        (void)close(g_staged[i].src_fd);
        g_staged[i].in_use = 0U;
        g_staged[i].staged_len = 0U;
        return;
    }
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
