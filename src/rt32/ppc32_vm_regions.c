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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vm/vm32.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static _Thread_local int g_vm_lock_held = 0;

void vm_lock_acquire(void)
{
    ppc32_spin_lock(&g_vm_lock);
    g_vm_lock_held = 1;
}

void vm_lock_release(void)
{
    g_vm_lock_held = 0;
    ppc32_spin_unlock(&g_vm_lock);
}

void ppc32_vm_lock(void)
{
    vm_lock_acquire();
}

void ppc32_vm_unlock(void)
{
    vm_lock_release();
}

void ppc32_vm_unlock_if_held_by_self(void)
{
    if (g_vm_lock_held != 0) {
        g_vm_lock_held = 0;
        ppc32_spin_unlock(&g_vm_lock);
    }
}

/* Fork coordination (P32-R3-4): the parent holds the VM lock across
 * the snapshot (ppc32_vm_lock); the child drops the inherited locked
 * value and clears the copied thread-local held flag. */
void ppc32_vm_fork_child(void)
{
    g_vm_lock_held = 0;
    atomic_store_explicit(&g_vm_lock, 0U, memory_order_release);
}

uint64_t page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

int vm_dup_fd(int fd)
{
    if (fd < 0) {
        return -1;
    }
#ifdef F_DUPFD_CLOEXEC
    int dfd = fcntl(fd, F_DUPFD_CLOEXEC, 512);
    if (dfd >= 0) {
        return dfd;
    }
    dfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (dfd >= 0) {
        return dfd;
    }
#endif
    int fallback = dup(fd);
    if (fallback >= 0) {
        int fl = fcntl(fallback, F_GETFD);
        if (fl >= 0) {
            (void)fcntl(fallback, F_SETFD, fl | FD_CLOEXEC);
        }
    }
    return fallback;
}

bool vm_same_backing_fd(int fd_a, int fd_b)
{
    if (fd_a < 0 && fd_b < 0) {
        return true;
    }
    if (fd_a < 0 || fd_b < 0) {
        return false;
    }
    if (fd_a == fd_b) {
        return true;
    }
    struct stat sa;
    struct stat sb;
    if (fstat(fd_a, &sa) != 0 || fstat(fd_b, &sb) != 0) {
        return false;
    }
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

int vm_create_shared_anon_fd(uint64_t size)
{
#ifdef __linux__
    /* Prefer memfd (no /tmp ENOSPC/unwritable failure, no disk-backed
     * shared memory); fall through to the mkstemp file on failure. */
    {
        int memfd = memfd_create("ppc32rt-shm", MFD_CLOEXEC);

        if (memfd >= 0) {
            if (ftruncate(memfd, (off_t)size) != 0) {
                int err = -errno;

                (void)close(memfd);
                return err;
            }
            return memfd;
        }
    }
#endif
    char tmpl[] = "/tmp/.ppc32rt-shm-XXXXXX";
    int sh_fd = mkstemp(tmpl);
    if (sh_fd < 0) {
        return -errno;
    }
    (void)unlink(tmpl);
    int fl = fcntl(sh_fd, F_GETFD);
    if (fl >= 0) {
        (void)fcntl(sh_fd, F_SETFD, fl | FD_CLOEXEC);
    }
    if (ftruncate(sh_fd, (off_t)size) != 0) {
        int err = -errno;
        (void)close(sh_fd);
        return err;
    }
    return sh_fd;
}

/* Grow a shared-anonymous backing file to req_sz without ever shrinking
 * it: after a split, sibling fragments share the file, so an unconditional
 * ftruncate would drop their tail pages beyond EOF (later SIGBUS). */
int vm_grow_shared_anon_fd(int fd, uint64_t req_sz)
{
    struct stat st;
    uint64_t cur_sz;

    if (fd < 0) {
        return -EBADF;
    }
    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    cur_sz = (st.st_size > 0) ? (uint64_t)st.st_size : 0ULL;
    if (req_sz > cur_sz && ftruncate(fd, (off_t)req_sz) != 0) {
        return -errno;
    }
    return 0;
}

bool vm_can_modify_range_locked(uint32_t start, uint32_t end, bool insert_mid)
{
    if (start >= end) {
        return false;
    }
    vm_coalesce_regions_locked();
    size_t extra = insert_mid ? 1U : 0U;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const ppc32_region_t *r = &g_vm_regions[i];
        if (r->end <= start || r->start >= end) {
            continue;
        }
        if (r->start < start && r->end > end) {
            extra += insert_mid ? 2U : 1U;
        } else if (insert_mid && (r->start < start || r->end > end)) {
            extra += 1U;
        }
    }
    return g_vm_region_count + extra <= PPC32_MAX_REGIONS;
}

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
}

void vm_remove_region_at(size_t idx)
{
    if (idx >= g_vm_region_count) {
        return;
    }
    if (g_vm_regions[idx].fd >= 0) {
        (void)close(g_vm_regions[idx].fd);
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
    int owned_fd = -1;
    if (fd >= 0) {
        owned_fd = vm_dup_fd(fd);
        if (owned_fd < 0) {
            return -1;
        }
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
    r->fd     = owned_fd;
    r->offset = (owned_fd >= 0) ? offset : 0ULL;
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
            prev->flags == curr->flags && vm_same_backing_fd(prev->fd, curr->fd) &&
            off_ok && strcmp(prev->name, curr->name) == 0) {
            if (curr->fd >= 0 && curr->fd != prev->fd) {
                (void)close(curr->fd);
            }
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
    int tmp_fd = -1;
    if (fd >= 0) {
        tmp_fd = vm_dup_fd(fd);
        if (tmp_fd < 0) {
            return -1;
        }
    }
    char name_copy[64];
    if (name) {
        snprintf(name_copy, sizeof(name_copy), "%s", name);
    } else {
        name_copy[0] = '\0';
    }
    uint32_t clean_flags = flags & ~(PPC32_MAP_FIXED | PPC32_MAP_FIXED_NOREPLACE);
    vm_unmap_regions_locked(start, end);
    int rc = vm_insert_region_raw_ex(start, end, prot, clean_flags, tmp_fd, offset, name_copy);
    if (rc < 0) {
        vm_coalesce_regions_locked();
        rc = vm_insert_region_raw_ex(start, end, prot, clean_flags, tmp_fd, offset, name_copy);
    }
    if (tmp_fd >= 0) {
        (void)close(tmp_fd);
    }
    vm_coalesce_regions_locked();
    return rc;
}

int vm_record_region_locked(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, const char *name)
{
    return vm_record_region_ex_locked(start, end, prot, flags, -1, 0ULL, name);
}

int vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot)
{
    if (!vm_can_modify_range_locked(mp_start, mp_end, true)) {
        return -ENOMEM;
    }
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
            uint64_t mid_off = (orig.fd >= 0) ?
                (orig.offset + (uint64_t)(mp_start - orig.start)) : 0ULL;
            uint64_t right_off = (orig.fd >= 0) ?
                (orig.offset + (uint64_t)(mp_end - orig.start)) : 0ULL;
            if (vm_insert_region_raw_ex(mp_start, mp_end, prot, orig.flags,
                                        orig.fd, mid_off, orig.name) != 0) {
                return -ENOMEM;
            }
            if (vm_insert_region_raw_ex(mp_end, orig.end, orig.prot, orig.flags,
                                        orig.fd, right_off, orig.name) != 0) {
                vm_remove_region_at(i + 1U);
                return -ENOMEM;
            }
            g_vm_regions[i].end = mp_start;
            i += 3U;
        } else if (orig.start < mp_start) {
            uint64_t right_off = (orig.fd >= 0) ?
                (orig.offset + (uint64_t)(mp_start - orig.start)) : 0ULL;
            if (vm_insert_region_raw_ex(mp_start, orig.end, prot, orig.flags,
                                        orig.fd, right_off, orig.name) != 0) {
                return -ENOMEM;
            }
            g_vm_regions[i].end = mp_start;
            i += 2U;
        } else {
            r->start = mp_end;
            if (orig.fd >= 0) {
                r->offset = orig.offset + (uint64_t)(mp_end - orig.start);
            }
            if (vm_insert_region_raw_ex(orig.start, mp_end, prot, orig.flags,
                                        orig.fd, orig.offset, orig.name) != 0) {
                r->start  = orig.start;
                r->offset = orig.offset;
                return -ENOMEM;
            }
            i += 2U;
        }
    }
    vm_coalesce_regions_locked();
    return 0;
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
            bool fd_mismatch = (out_fd != NULL) && (!vm_same_backing_fd(r->fd, first_fd) ||
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

static bool vm_range_prot_ok_locked(const ppc32_ctx_t *ctx, uint32_t va,
                                    uint32_t end, uint32_t need_prot)
{
    const ppc32_region_t *regs = NULL;
    size_t count = 0U;

    if (ctx->vm_ready) {
        regs  = g_vm_regions;
        count = g_vm_region_count;
    } else if (ctx->region_count > 0U) {
        regs  = ctx->regions;
        count = (ctx->region_count <= PPC32_MAX_REGIONS) ?
            ctx->region_count : PPC32_MAX_REGIONS;
    } else {
        return true;
    }

    uint32_t cur = va;
    for (size_t i = 0U; i < count && cur < end; i++) {
        const ppc32_region_t *r = &regs[i];
        if (r->end <= cur) {
            continue;
        }
        if (r->start > cur || (r->prot & need_prot) != need_prot) {
            return false;
        }
        cur = (r->end < end) ? r->end : end;
    }
    return cur >= end;
}

bool ppc32_vm_range_prot_ok(const ppc32_ctx_t *ctx, uint32_t va,
                            size_t len, uint32_t need_prot)
{
    if (!ctx) {
        return false;
    }
    if (len == 0U) {
        return true;
    }
    if (len > PPC32_TASK_SIZE_TOP || va < PPC32_LOW_GUARD_SIZE) {
        return false;
    }
    uint64_t end = (uint64_t)va + (uint64_t)len;
    if (end > (uint64_t)PPC32_TASK_SIZE_TOP || end < (uint64_t)va) {
        return false;
    }
    vm_lock_acquire();
    bool ok = vm_range_prot_ok_locked(ctx, va, (uint32_t)end, need_prot);
    vm_lock_release();
    return ok;
}

int ppc32_vm_copyin_safe(const ppc32_ctx_t *ctx, uint32_t va,
                         void *dst, size_t len)
{
    if (!ctx || (!dst && len > 0U)) {
        return -EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    if (len > PPC32_TASK_SIZE_TOP || va < PPC32_LOW_GUARD_SIZE) {
        return -EFAULT;
    }
    uint64_t end = (uint64_t)va + (uint64_t)len;
    if (end > (uint64_t)PPC32_TASK_SIZE_TOP || end < (uint64_t)va) {
        return -EFAULT;
    }
    vm_lock_acquire();
    if (!vm_range_prot_ok_locked(ctx, va, (uint32_t)end, 1U)) {
        vm_lock_release();
        return -EFAULT;
    }
    memcpy(dst, ppc32_guest_ptr(ctx, va), len);
    vm_lock_release();
    return 0;
}

int ppc32_vm_copyout_safe(const ppc32_ctx_t *ctx, uint32_t va,
                          const void *src, size_t len)
{
    if (!ctx || (!src && len > 0U)) {
        return -EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    if (len > PPC32_TASK_SIZE_TOP || va < PPC32_LOW_GUARD_SIZE) {
        return -EFAULT;
    }
    uint64_t end = (uint64_t)va + (uint64_t)len;
    if (end > (uint64_t)PPC32_TASK_SIZE_TOP || end < (uint64_t)va) {
        return -EFAULT;
    }
    vm_lock_acquire();
    if (!vm_range_prot_ok_locked(ctx, va, (uint32_t)end, 2U)) {
        vm_lock_release();
        return -EFAULT;
    }
    memcpy(ppc32_guest_ptr(ctx, va), src, len);
    vm_lock_release();
    return 0;
}

int vm_find_free_gap_aligned_locked(uint64_t aligned_len, uint64_t align,
                                    uint32_t *out_va)
{
    if (align < (uint64_t)PPC32_PAGE_SIZE) {
        align = (uint64_t)PPC32_PAGE_SIZE;
    }
    uint64_t mask = align - 1ULL;
    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(PPC32_MMAP_TOP_32 - PPC32_MMAP_BASE_32)) {
        return -1;
    }

    uint64_t cursor_cand = ((uint64_t)g_vm_mmap_cursor + mask) & ~mask;
    if (cursor_cand < (uint64_t)PPC32_MMAP_BASE_32) {
        cursor_cand = ((uint64_t)PPC32_MMAP_BASE_32 + mask) & ~mask;
    }
    if (cursor_cand + aligned_len <= (uint64_t)PPC32_MMAP_TOP_32 &&
        !vm_range_overlaps_locked((uint32_t)cursor_cand, (uint32_t)(cursor_cand + aligned_len))) {
        *out_va = (uint32_t)cursor_cand;
        return 0;
    }

    uint64_t cand = ((uint64_t)PPC32_MMAP_BASE_32 + mask) & ~mask;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        uint64_t r_start = (uint64_t)g_vm_regions[i].start;
        uint64_t r_end   = ((uint64_t)g_vm_regions[i].end + mask) & ~mask;
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

int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    return vm_find_free_gap_aligned_locked(aligned_len, (uint64_t)PPC32_PAGE_SIZE, out_va);
}

int ppc32_vm_record_region(ppc32_ctx_t *ctx, uint32_t start, uint32_t end,
                           uint32_t prot, uint32_t flags, const char *name)
{
    if (!ctx || start >= end) {
        return -1;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_record_region_locked(start, end, prot, flags, name);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return rc;
}

void ppc32_vm_sync_ctx(ppc32_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
}

/* Reserve host PROT_NONE over [start, start+len) for the legacy (non-A2)
 * unmap path. Moved from ppc32_vm.c (Phase 0 file-size discipline). */
int vm_reserve_prot_none(ppc32_ctx_t *ctx, uint32_t start, uint32_t len)
{
    void *res = mmap(ppc32_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (res == MAP_FAILED) {
        return -errno;
    }
    return 0;
}

/* True teardown (munmap/mremap-source removal): the range stops being
 * file-backed, so its inode records go too. Moved from ppc32_vm.c
 * (Phase 0 file-size discipline). */

/* A staged MAP_SHARED group stays alive while any live region references
 * its (dev, ino, offset) key; regions keep the caller's file fd/offset,
 * so identity is compared through fstat. */
static bool staged_group_referenced_locked(uint64_t dev, uint64_t ino,
    uint64_t off)
{
    size_t i;

    for (i = 0U; i < g_vm_region_count; i++) {
        struct stat st;

        if (g_vm_regions[i].fd < 0 || g_vm_regions[i].offset != off) {
            continue;
        }
        if (fstat(g_vm_regions[i].fd, &st) != 0) {
            continue;
        }
        if ((uint64_t)st.st_dev == dev && (uint64_t)st.st_ino == ino) {
            return true;
        }
    }
    return false;
}

/* Drop staged groups no live region references (P32-R3-3): the drop
 * itself writes back and closes both fds. Runs after every region-list
 * mutation on the unmap path. */
static void vm_file_shared_gc_locked(void)
{
    size_t n = vm_file_shared_group_count();
    size_t i;

    for (i = 0U; i < n; i++) {
        uint64_t dev;
        uint64_t ino;
        uint64_t off;

        if (!vm_file_shared_group_key(i, &dev, &ino, &off)) {
            continue;
        }
        if (!staged_group_referenced_locked(dev, ino, off)) {
            vm_file_shared_drop_group(dev, ino, off);
        }
    }
}

/* Best-effort write-back of staged groups intersecting a torn-down or
 * replaced range, resolved through the still-live regions. */
static void vm_file_shared_writeback_overlap_locked(uint32_t start,
    uint32_t end)
{
    size_t i;

    if (end <= start) {
        return;
    }
    for (i = 0U; i < g_vm_region_count; i++) {
        uint32_t lo;
        uint32_t hi;

        if (g_vm_regions[i].fd < 0 ||
            (g_vm_regions[i].flags & 0x01U) == 0U) {
            continue;
        }
        if (g_vm_regions[i].end <= start || g_vm_regions[i].start >= end) {
            continue;
        }
        lo = (g_vm_regions[i].start > start) ? g_vm_regions[i].start : start;
        hi = (g_vm_regions[i].end < end) ? g_vm_regions[i].end : end;
        vm_file_shared_writeback_file_range(g_vm_regions[i].fd,
            g_vm_regions[i].offset + (uint64_t)(lo - g_vm_regions[i].start),
            g_vm_regions[i].offset + (uint64_t)(hi - g_vm_regions[i].start));
    }
}

int vm_munmap_locked(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx || (addr & (PPC32_PAGE_SIZE - 1U)) != 0U || len == 0U) {
        return -EINVAL;
    }
    uint64_t aligned_len = page_align_up((uint64_t)len);
    if (addr < PPC32_LOW_GUARD_SIZE ||
        (uint64_t)addr + aligned_len > (uint64_t)PPC32_TASK_SIZE_TOP) {
        return -EINVAL;
    }

    uint32_t start = ppc32_page_down(addr);
    uint32_t end = (uint32_t)((uint64_t)start + aligned_len);
    if (!vm_can_modify_range_locked(start, end, false)) {
        return -ENOMEM;
    }

    /* Same VM>inode order as the mmap path. */
    vm_file_untrack_range(start, end);
    vm_file_shared_writeback_overlap_locked(start, end);

    if (vm32_is_a2()) {
        int urc = vm32_unmap_union(start, (uint32_t)aligned_len);
        if (urc != 0) {
            return urc;
        }
    } else {
        int rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
        if (rc != 0) {
            return rc;
        }
        vm32_record_unmap(start, end);
    }

    vm_unmap_regions_locked(start, end);
    vm_file_shared_gc_locked();
    vm32_tlb_invalidate_range(start, end);
    vm32_ll_note_remap();
    if (g_vm_mmap_cursor == end && start >= PPC32_MMAP_BASE_32) {
        g_vm_mmap_cursor = start;
    }
    return 0;
}

