/*
 * src/rt32/ppc32_vm.c — Guest 4 GiB window [G, G+4GiB) reservation and guest VMA manager
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from i686rt/src/rt32/rt32_vm.c (itself vendored
 * from a32rt/src/vm.c @ d84feb3, SPEC D13): mechanical renames
 * i686_/rt32_→ppc32_, I686_/RT32_→PPC32_, retyped on ppc32_ctx_t; guest
 * VA ceiling PPC32_TASK_SIZE_TOP (0xC0000000, SPEC 1.1); mmap search
 * range [0x30000000, 0xB0000000) below the PPC32 guest stack. Carries the
 * D18 signal-window race-free commit point and D19 CLONE_VM page-table
 * mutex locking semantics from the source. Region bookkeeping lives in
 * ppc32_vm_regions.c (shared via ppc32_vm_priv.h).
 */

#define _GNU_SOURCE
#include "ppc32_vm_priv.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

_Atomic uint32_t g_vm_lock = 0U;
ppc32_ctx_t    *g_vm_root_ctx = NULL;
uint32_t        g_vm_brk_base = 0U;
uint32_t        g_vm_brk_curr = 0U;
uint32_t        g_vm_mmap_cursor = PPC32_MMAP_BASE_32;
ppc32_region_t  g_vm_regions[PPC32_MAX_REGIONS];
size_t          g_vm_region_count = 0U;

void vm_lock_acquire(void)
{
    ppc32_spin_lock(&g_vm_lock);
}

void vm_lock_release(void)
{
    ppc32_spin_unlock(&g_vm_lock);
}

uint64_t page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

static int vm_reserve_prot_none(ppc32_ctx_t *ctx, uint32_t start, uint32_t len)
{
    void *res = mmap(ppc32_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    return 0;
}

/* Translation-cache invalidation on guest mm ops (D11 SMC): real since
 * Phase H H1; the interpreter has no code cache (the call is cheap). */
#ifdef PPC32RT_NO_DBT
static inline void vm_invalidate_jit(ppc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    (void)ctx; (void)start; (void)end;
}
#else
extern void ppc32_dbt_invalidate_range(ppc32_ctx_t *ctx, uint32_t start,
                                      uint32_t end);
static inline void vm_invalidate_jit(ppc32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    ppc32_dbt_invalidate_range(ctx, start, end);
}
#endif


static int try_reserve_window(uint64_t base)
{
    if ((base & (PPC32_PAGE_SIZE - 1ULL)) != 0ULL || base > UINT64_MAX - PPC32_WINDOW_SIZE) {
        return -1;
    }

    uint64_t map_start = (base == 0ULL) ? (uint64_t)PPC32_LOW_GUARD_SIZE : base;
    uint64_t map_len   = (base == 0ULL) ? (PPC32_WINDOW_SIZE - (uint64_t)PPC32_LOW_GUARD_SIZE)
                                        : PPC32_WINDOW_SIZE;

    void *res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (res == MAP_FAILED && (errno == EINVAL || errno == EOPNOTSUPP)) {
        res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (res == MAP_FAILED) {
        return -1;
    }
    if ((uint64_t)(uintptr_t)res != map_start) {
        munmap(res, (size_t)map_len);
        return -1;
    }
    return 0;
}

int ppc32_vm_init(ppc32_ctx_t *ctx, uint64_t requested_window)
{
    if (!ctx) {
        return -1;
    }

    uint64_t base = requested_window;
    bool     has_explicit = (requested_window != UINT64_MAX);

    if (!has_explicit) {
        const char *env_win = getenv("PPC32RT_WINDOW");
        if (env_win && env_win[0] != '\0') {
            char *endp = NULL;
            errno = 0;
            unsigned long long val = strtoull(env_win, &endp, 0);
            if (strchr(env_win, '-') != NULL || errno == ERANGE || !endp ||
                endp == env_win || *endp != '\0' || (uint64_t)val == UINT64_MAX) {
                fprintf(stderr, "ppc32rt: invalid PPC32RT_WINDOW '%s'\n", env_win);
                return -1;
            }
            base = (uint64_t)val;
            has_explicit = true;
        }
    }

    if (has_explicit) {
        if (try_reserve_window(base) != 0) {
            fprintf(stderr, "ppc32rt: failed to reserve guest window at 0x%llx\n",
                    (unsigned long long)base);
            return -1;
        }
        ctx->guest_base = base;
    } else if (ctx->has_host_info && ctx->host_info.window_hint != 0ULL &&
               try_reserve_window(ctx->host_info.window_hint) == 0) {
        ctx->guest_base = ctx->host_info.window_hint;
    } else {
        /* Try G = 0 first; if occupied, scan 4 GiB-aligned windows [4G, 64G). */
        if (try_reserve_window(0ULL) == 0) {
            ctx->guest_base = 0ULL;
        } else {
            bool found = false;
            for (uint64_t cand = 0x100000000ULL; cand < 0x1000000000ULL; cand += 0x100000000ULL) {
                if (try_reserve_window(cand) == 0) {
                    ctx->guest_base = cand;
                    found = true;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "ppc32rt: unable to find free 4 GiB guest window\n");
                return -1;
            }
        }
    }

    vm_lock_acquire();
    g_vm_root_ctx     = ctx;
    g_vm_brk_base     = 0U;
    g_vm_brk_curr     = 0U;
    g_vm_mmap_cursor  = PPC32_MMAP_BASE_32;
    g_vm_region_count = 0U;
    ctx->mmap_cursor  = PPC32_MMAP_BASE_32;
    ctx->region_count = 0U;
    ctx->vm_ready     = true;
    vm_lock_release();
    return 0;
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


/* Exec teardown: drop every region except the vdso from the AUTHORITATIVE
 * global list (ctx->regions is a mirror; vm_sync_from_ctx never copies it
 * back, so a ctx-only clear is undone by the next vm_sync_to_ctx). */
void ppc32_vm_reset_for_exec(ppc32_ctx_t *ctx)
{
    vm_lock_acquire();
    size_t w = 0U;
    for (size_t r = 0U; r < g_vm_region_count; r++) {
        if (strcmp(g_vm_regions[r].name, "[vdso]") == 0) {
            g_vm_regions[w] = g_vm_regions[r];
            w++;
        }
    }
    g_vm_region_count = w;
    g_vm_brk_base  = 0U;
    g_vm_brk_curr  = 0U;
    g_vm_mmap_cursor = PPC32_MMAP_BASE_32;
    vm_lock_release();

    /* Kernel exec semantics (RC7b T4b): execve destroys ALL old address
     * space.  Only the region bookkeeping was cleared above, so the
     * stale host mappings of the previous image (in a posix_spawn fork
     * child: the wineserver's whole COW-inherited address space) stayed
     * resident in the window — later ld.so/NTDLL allocations then
     * collided with foreign leftover data (foreign TCBs, foreign code),
     * which killed the boot with NULL-call threads and "could not load
     * kernel32.dll".  Tear the window down; the next stack setup re-maps
     * the vDSO and the stack, and the new image loads fresh pages. */
    (void)munmap((void *)(uintptr_t)PPC32_LOW_GUARD_SIZE,
                 (size_t)(PPC32_WINDOW_SIZE - (uint64_t)PPC32_LOW_GUARD_SIZE));

    /* Mirror the cleared state into the caller's ctx.  vdso_base must
     * clear too: ppc32_vdso_map is idempotent on it, and a fork child
     * would otherwise skip the re-map and run without the vDSO page. */
    ctx->brk_base    = 0U;
    ctx->brk_curr    = 0U;
    ctx->mmap_cursor = PPC32_MMAP_BASE_32;
    ctx->vdso_base   = 0U;
    ctx->vm_ready    = false;
    ctx->region_count = (w <= PPC32_MAX_REGIONS) ? w : PPC32_MAX_REGIONS;
    if (ctx->region_count > 0U) {
        memcpy(ctx->regions, g_vm_regions, ctx->region_count * sizeof(ppc32_region_t));
    }
}

uint32_t ppc32_vm_brk(ppc32_ctx_t *ctx, uint32_t new_brk)
{
    if (!ctx) {
        return 0U;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    uint32_t brk_limit = (g_vm_brk_base < PPC32_MMAP_BASE_32) ? PPC32_MMAP_BASE_32 : PPC32_MMAP_TOP_32;
    if (new_brk == 0U || new_brk < g_vm_brk_base || new_brk > brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    uint64_t old_page64 = page_align_up((uint64_t)g_vm_brk_curr);
    uint64_t new_page64 = page_align_up((uint64_t)new_brk);
    if (new_page64 > (uint64_t)brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    uint32_t old_page = (uint32_t)old_page64;
    uint32_t new_page = (uint32_t)new_page64;

    if (new_page > old_page) {
        if (vm_range_overlaps_locked(old_page, new_page)) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        uint32_t len = new_page - old_page;
        void *host_addr = ppc32_guest_ptr(ctx, old_page);
        void *res = mmap(host_addr, len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (res == MAP_FAILED) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        (void)vm_record_region_locked(old_page, new_page,
                                      (uint32_t)(PROT_READ | PROT_WRITE), 0x22U, "[heap]");
    } else if (new_page < old_page) {
        uint32_t len = old_page - new_page;
        /* Re-reserve shrunk brk pages with PROT_NONE inside the guest window */
        (void)vm_reserve_prot_none(ctx, new_page, len);
        vm_unmap_regions_locked(new_page, old_page);
    }

    g_vm_brk_curr = new_brk;
    if (new_page != old_page) {
        vm_sync_to_ctx(ctx);
    } else {
        vm_sync_brk_to_ctx(ctx);
    }
    vm_lock_release();

    if (new_page < old_page) {
        vm_invalidate_jit(ctx, new_page, old_page);
    }
    return new_brk;
}

static uint32_t vm_mmap2_locked(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx || len == 0U || (flags & 0x03U) == 0U || (flags & 0x03U) == 0x03U) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t aligned_len = page_align_up((uint64_t)len);
    if (aligned_len == 0ULL || aligned_len > (uint64_t)PPC32_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    int host_flags = 0;
    if (flags & 0x01U) {
        host_flags |= MAP_SHARED;
    }
    if (flags & 0x02U) {
        host_flags |= MAP_PRIVATE;
    }
    if (flags & PPC32_MAP_ANONYMOUS) {
        host_flags |= MAP_ANONYMOUS;
    }

    uint32_t target_va     = 0U;
    bool     update_cursor = false;
    if ((flags & (PPC32_MAP_FIXED | PPC32_MAP_FIXED_NOREPLACE)) != 0U) {
        if ((addr & (PPC32_PAGE_SIZE - 1U)) != 0U || addr < PPC32_LOW_GUARD_SIZE) {
            return (uint32_t)(-EINVAL);
        }
        if ((uint64_t)addr + aligned_len > (uint64_t)PPC32_TASK_SIZE_TOP) {
            return (uint32_t)(-ENOMEM);
        }
        if ((flags & PPC32_MAP_FIXED_NOREPLACE) != 0U &&
            vm_range_overlaps_locked(addr, (uint32_t)((uint64_t)addr + aligned_len))) {
            return (uint32_t)(-EEXIST);
        }
        target_va = addr;
    } else {
        uint32_t hint_va = ppc32_page_down(addr);
        if (addr != 0U &&
            hint_va >= PPC32_MMAP_BASE_32 &&
            (uint64_t)hint_va + aligned_len <= (uint64_t)PPC32_MMAP_TOP_32 &&
            !vm_range_overlaps_locked(hint_va, (uint32_t)((uint64_t)hint_va + aligned_len))) {
            target_va = hint_va;
        } else if (vm_find_free_gap_locked(aligned_len, &target_va) != 0) {
            return (uint32_t)(-ENOMEM);
        } else {
            update_cursor = true;
        }
    }

    int   host_prot   = ppc32_host_prot(ctx, prot);
    void *host_target = ppc32_guest_ptr(ctx, target_va);
    off_t host_off    = (off_t)pgoffset * (off_t)PPC32_PAGE_SIZE;
    void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                     host_flags | MAP_FIXED, (host_flags & MAP_ANONYMOUS) ? -1 : fd,
                     (host_flags & MAP_ANONYMOUS) ? 0 : host_off);
    if (res == MAP_FAILED) {
        return (uint32_t)(-errno);
    }

    if (update_cursor) {
        g_vm_mmap_cursor = (uint32_t)((uint64_t)target_va + aligned_len);
    }
    (void)vm_record_region_locked(target_va, (uint32_t)((uint64_t)target_va + aligned_len),
                                  prot & 0x7U, flags, "[mmap]");
    return target_va;
}

uint32_t ppc32_vm_mmap2(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx) {
        return (uint32_t)(-EINVAL);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    uint32_t res = vm_mmap2_locked(ctx, addr, len, prot, flags, fd, pgoffset);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (res <= 0xFFFFF000U &&
        ((flags & (PPC32_MAP_FIXED | PPC32_MAP_FIXED_NOREPLACE)) != 0U ||
         (prot & (uint32_t)PROT_EXEC) != 0U)) {
        vm_invalidate_jit(ctx, res, (uint32_t)((uint64_t)res + page_align_up((uint64_t)len)));
    }

    /* a32rt's AOT cache preload (a32_aot_load_fd) was dropped: ppc32rt has no
     * AOT pre-translator (the DBT compiles lazily, Phase 3). */

    return res;
}

static int vm_mprotect_locked(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx || (addr & (PPC32_PAGE_SIZE - 1U)) != 0U || addr < 0x1000U || (prot & ~0x7U) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    uint64_t aligned_len = page_align_up((uint64_t)len);
    uint64_t end64       = (uint64_t)addr + aligned_len;
    if (addr < PPC32_LOW_GUARD_SIZE ||
        aligned_len == 0ULL ||
        end64 > (uint64_t)PPC32_TASK_SIZE_TOP ||
        !vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL, NULL, 0U)) {
        return -ENOMEM;
    }

    if (mprotect(ppc32_guest_ptr(ctx, addr), (size_t)aligned_len, ppc32_host_prot(ctx, prot)) != 0) {
        return -errno;
    }

    vm_mprotect_regions_locked(addr, (uint32_t)end64, prot & 0x7U);
    return 0;
}

int ppc32_vm_mprotect(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_mprotect_locked(ctx, addr, len, prot);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (rc == 0 && len > 0U) {
        vm_invalidate_jit(ctx, addr, (uint32_t)((uint64_t)addr + page_align_up((uint64_t)len)));
    }
    return rc;
}

static int vm_munmap_locked(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len)
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
    /* Keep the [G, G+4GiB) reservation intact by replacing unmapped pages with PROT_NONE */
    int rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
    if (rc != 0) {
        return rc;
    }

    uint32_t end = (uint32_t)((uint64_t)start + aligned_len);
    vm_unmap_regions_locked(start, end);
    if (g_vm_mmap_cursor == end && start >= PPC32_MMAP_BASE_32) {
        g_vm_mmap_cursor = start;
    }
    return 0;
}

int ppc32_vm_munmap(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_munmap_locked(ctx, addr, len);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (rc == 0) {
        vm_invalidate_jit(ctx, addr, (uint32_t)((uint64_t)addr + page_align_up((uint64_t)len)));
    }
    return rc;
}

uint32_t ppc32_vm_mremap(ppc32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                       uint32_t new_len, uint32_t flags, uint32_t new_addr)
{
    if (!ctx || (old_addr & (PPC32_PAGE_SIZE - 1U)) != 0U ||
        old_len == 0U || new_len == 0U) {
        return (uint32_t)(-EINVAL);
    }
    if ((flags & ~(PPC32_MREMAP_MAYMOVE | PPC32_MREMAP_FIXED)) != 0U ||
        ((flags & PPC32_MREMAP_FIXED) != 0U && (flags & PPC32_MREMAP_MAYMOVE) == 0U)) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t old_aligned = page_align_up((uint64_t)old_len);
    uint64_t new_aligned = page_align_up((uint64_t)new_len);
    if (old_addr < PPC32_LOW_GUARD_SIZE ||
        (uint64_t)old_addr + old_aligned > (uint64_t)PPC32_TASK_SIZE_TOP) {
        return (uint32_t)(-EINVAL);
    }
    if (new_aligned == 0ULL || new_aligned > (uint64_t)PPC32_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    uint32_t prot       = 0x3U;
    uint32_t orig_flags = 0x22U;
    char     orig_name[64];
    orig_name[0] = '\0';
    if (!vm_check_mapped_range_locked(old_addr, (uint32_t)((uint64_t)old_addr + old_aligned),
                                      &prot, &orig_flags, orig_name, sizeof(orig_name))) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return (uint32_t)(-EFAULT);
    }
    uint32_t    keep_flags  = orig_flags & 0x23U;
    uint32_t    map_flags   = (((keep_flags & 0x01U) != 0U) ? 0x01U : 0x02U) | PPC32_MAP_ANONYMOUS;
    const char *region_name = (orig_name[0] != '\0') ? orig_name : "[mmap]";

    if ((flags & PPC32_MREMAP_FIXED) == 0U) {
        if (new_aligned == old_aligned) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return old_addr;
        }
        if (new_aligned < old_aligned) {
            uint32_t unmap_addr = old_addr + (uint32_t)new_aligned;
            uint32_t unmap_len  = (uint32_t)(old_aligned - new_aligned);
            int rc = vm_munmap_locked(ctx, unmap_addr, unmap_len);
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            if (rc != 0) {
                return (uint32_t)rc;
            }
            vm_invalidate_jit(ctx, unmap_addr, unmap_addr + unmap_len);
            return old_addr;
        }

        uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
        uint64_t new_end = (uint64_t)old_addr + new_aligned;
        if (new_end <= (uint64_t)PPC32_TASK_SIZE_TOP &&
            !vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
            uint32_t ext = vm_mmap2_locked(ctx, old_end, (uint32_t)(new_aligned - old_aligned),
                                           prot, map_flags | PPC32_MAP_FIXED, -1, 0U);
            if (ext <= 0xFFFFF000U) {
                (void)vm_record_region_locked(old_end, (uint32_t)new_end,
                                              prot, keep_flags, region_name);
                uint32_t ext_end = (uint32_t)new_end;
                if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                    ext_end <= PPC32_MMAP_TOP_32) {
                    g_vm_mmap_cursor = ext_end;
                }
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                    vm_invalidate_jit(ctx, old_end, ext_end);
                }
                return old_addr;
            }
        }

        if ((flags & PPC32_MREMAP_MAYMOVE) == 0U) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-ENOMEM);
        }
    } else {
        if ((new_addr & (PPC32_PAGE_SIZE - 1U)) != 0U || new_addr < PPC32_LOW_GUARD_SIZE ||
            (uint64_t)new_addr + new_aligned > (uint64_t)PPC32_TASK_SIZE_TOP ||
            ((uint64_t)new_addr < (uint64_t)old_addr + old_aligned &&
             (uint64_t)old_addr < (uint64_t)new_addr + new_aligned)) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-EINVAL);
        }
    }

    bool     is_fixed = (flags & PPC32_MREMAP_FIXED) != 0U;
    uint32_t rw_prot  = (prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE);
    uint32_t new_va   = vm_mmap2_locked(ctx, is_fixed ? new_addr : 0U, (uint32_t)new_aligned,
                                        rw_prot, map_flags | (is_fixed ? PPC32_MAP_FIXED : 0U),
                                        -1, 0U);
    if (new_va > 0xFFFFF000U) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return new_va;
    }

    if ((prot & 0x1U) == 0U) {
        (void)mprotect(ppc32_guest_ptr(ctx, old_addr), (size_t)old_aligned, PROT_READ);
    }
    size_t copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
    memcpy(ppc32_guest_ptr(ctx, new_va), ppc32_guest_ptr(ctx, old_addr), copy_bytes);
    if (prot != 0x3U) {
        (void)vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
    }
    (void)vm_record_region_locked(new_va, (uint32_t)((uint64_t)new_va + new_aligned),
                                  prot, keep_flags, region_name);
    (void)vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    vm_invalidate_jit(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
    if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
        vm_invalidate_jit(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
    }
    return new_va;
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
