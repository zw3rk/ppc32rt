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
#include <sys/stat.h>
#include <unistd.h>

#include "vm/vm32.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

_Atomic uint32_t       g_vm_lock = 0U;
ppc32_ctx_t           *g_vm_root_ctx = NULL;
uint32_t               g_vm_brk_base = 0U;
uint32_t               g_vm_brk_curr = 0U;
uint32_t               g_vm_mmap_cursor = PPC32_MMAP_BASE_32;
ppc32_region_t         g_vm_regions[PPC32_MAX_REGIONS];
size_t                 g_vm_region_count = 0U;

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

/* Publish the two-regime state when the legacy probe owns the window:
 * regime from the live host page size, A2 TLB armed empty. */
static void vm32_attach_legacy(void)
{
    long host_page = sysconf(_SC_PAGESIZE);

    if (host_page > 0L) {
        (void)vm32_select_regime((size_t)host_page);
    }
    vm32_tlb_invalidate_all();
}

/* Reserve one window candidate (RC-U3-r2 #4): the two-regime vm32 layer
 * owns the [G, G+4GiB) reservation when the platform allows it (regime
 * select + arena publish + A2 TLB arm inside vm32_init); otherwise the
 * legacy PROT_NONE probe keeps the G=0 guard-hole layout and the regime
 * is published around it. Exactly one owner reserves per boot. */
static int reserve_window(ppc32_ctx_t *ctx, uint64_t base)
{
    if (base != 0ULL && vm32_init(ctx, base) == 0) {
        return 0;
    }
    if (try_reserve_window(base) != 0) {
        return -1;
    }
    ctx->guest_base = base;
    vm32_attach_legacy();
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
        if (reserve_window(ctx, base) != 0) {
            fprintf(stderr, "ppc32rt: failed to reserve guest window at 0x%llx\n",
                    (unsigned long long)base);
            return -1;
        }
    } else if (ctx->has_host_info && ctx->host_info.window_hint != 0ULL &&
               reserve_window(ctx, ctx->host_info.window_hint) == 0) {
        /* reserve_window published ctx->guest_base. */
    } else {
        /* Try G = 0 first; if occupied, scan 4 GiB-aligned windows [4G, 64G). */
        if (reserve_window(ctx, 0ULL) == 0) {
            /* reserve_window published ctx->guest_base. */
        } else {
            bool found = false;
            for (uint64_t cand = 0x100000000ULL; cand < 0x1000000000ULL; cand += 0x100000000ULL) {
                if (reserve_window(ctx, cand) == 0) {
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
    /* Publish the reserved window to the Regime A2 union layer (no
     * reservation: legacy init already owns [G, G+4GiB)). No-op data
     * on 4K hosts; selects the union regime on H > 4096. */
    vm32_shadow_window(ctx->guest_base);
    vm_lock_release();
    return 0;
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
        } else if (g_vm_regions[r].fd >= 0) {
            (void)close(g_vm_regions[r].fd);
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
    (void)munmap((void *)(uintptr_t)(ctx->guest_base + (uint64_t)PPC32_LOW_GUARD_SIZE),
                 (size_t)(PPC32_WINDOW_SIZE - (uint64_t)PPC32_LOW_GUARD_SIZE));
    /* The old address space is gone: translations and reservations die. */
    vm32_tlb_invalidate_all();
    vm32_ll_note_remap();

    /* The whole window is gone: no recorded prot/state or translation
     * may outlive the address space (A2 union layer included). */
    vm32_tlb_invalidate_all();

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
        if (vm_range_overlaps_locked(old_page, new_page) ||
            !vm_can_modify_range_locked(old_page, new_page, true)) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        uint32_t len = new_page - old_page;
        void *host_addr = ppc32_guest_ptr(ctx, old_page);
        if (vm32_is_a2()) {
            vm32_record_map(old_page, new_page,
                (uint8_t)(PROT_READ | PROT_WRITE),
                (uint8_t)VM32_PAGE_ANON);
            if (vm32_sync_host_range(old_page, new_page) != 0) {
                vm32_record_unmap(old_page, new_page);
                uint32_t curr = g_vm_brk_curr;
                vm_sync_brk_to_ctx(ctx);
                vm_lock_release();
                return curr;
            }
            memset(host_addr, 0, len);
        } else {
            void *res = mmap(host_addr, len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (res == MAP_FAILED) {
                uint32_t curr = g_vm_brk_curr;
                vm_sync_brk_to_ctx(ctx);
                vm_lock_release();
                return curr;
            }
            vm32_record_map(old_page, new_page,
                (uint8_t)(PROT_READ | PROT_WRITE),
                (uint8_t)VM32_PAGE_ANON);
        }
        (void)vm_record_region_locked(old_page, new_page,
                                      (uint32_t)(PROT_READ | PROT_WRITE), 0x22U, "[heap]");
    } else if (new_page < old_page) {
        if (!vm_can_modify_range_locked(new_page, old_page, false)) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        uint32_t len = old_page - new_page;
        if (vm32_is_a2()) {
            (void)vm32_unmap_union(new_page, len);
        } else {
            (void)vm_reserve_prot_none(ctx, new_page, len);
            vm32_record_unmap(new_page, old_page);
        }
        vm_unmap_regions_locked(new_page, old_page);
        vm32_tlb_invalidate_range(new_page, old_page);
        vm32_ll_note_remap();
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

    uint64_t hpsz        = (uint64_t)vm32_host_page_size();
    bool     is_shared   = (flags & 0x01U) != 0U;
    uint64_t gap_align   = (is_shared && hpsz > (uint64_t)PPC32_PAGE_SIZE) ?
                           hpsz : (uint64_t)PPC32_PAGE_SIZE;
    uint64_t host_map_len = (is_shared && hpsz > (uint64_t)PPC32_PAGE_SIZE) ?
                            ((aligned_len + hpsz - 1ULL) & ~(hpsz - 1ULL)) : aligned_len;

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
        uint32_t hint_va = (uint32_t)((uint64_t)addr & ~(gap_align - 1ULL));
        if (addr != 0U &&
            hint_va >= PPC32_MMAP_BASE_32 &&
            (uint64_t)hint_va + host_map_len <= (uint64_t)PPC32_MMAP_TOP_32 &&
            !vm_range_overlaps_locked(hint_va, (uint32_t)((uint64_t)hint_va + host_map_len))) {
            target_va = hint_va;
        } else if (vm_find_free_gap_aligned_locked(host_map_len, gap_align, &target_va) != 0) {
            return (uint32_t)(-ENOMEM);
        } else {
            update_cursor = true;
        }
    }

    uint32_t map_end = (uint32_t)((uint64_t)target_va + aligned_len);
    if (!vm_can_modify_range_locked(target_va, map_end, true)) {
        return (uint32_t)(-ENOMEM);
    }
    if ((host_flags & MAP_ANONYMOUS) == 0 && fd < 0) {
        return (uint32_t)(-EBADF);
    }

    int sh_fd = -1;
    if (is_shared && (flags & PPC32_MAP_ANONYMOUS) != 0U && fd < 0) {
        sh_fd = vm_create_shared_anon_fd(host_map_len);
        if (sh_fd < 0) {
            return (uint32_t)sh_fd;
        }
    }
    int      use_fd      = (sh_fd >= 0) ? sh_fd : (((host_flags & MAP_ANONYMOUS) != 0) ? -1 : fd);
    int      host_prot   = ppc32_host_prot(ctx, prot);
    void    *host_target = ppc32_guest_ptr(ctx, target_va);
    off_t    host_off    = (sh_fd >= 0) ? 0 : ((off_t)pgoffset * (off_t)PPC32_PAGE_SIZE);
    uint8_t  state       = (uint8_t)VM32_PAGE_ANON;
    if (is_shared) {
        state = (uint8_t)VM32_PAGE_SHARED;
    } else if ((host_flags & MAP_ANONYMOUS) == 0) {
        state = (uint8_t)VM32_PAGE_COW_CLEAN;
    }

    bool va_host_aligned = (((uint64_t)target_va & (hpsz - 1ULL)) == 0ULL);
    bool off_host_aligned = (((uint64_t)host_off & (hpsz - 1ULL)) == 0ULL);
    bool in_window =
        ((uint64_t)target_va + host_map_len <= (uint64_t)PPC32_TASK_SIZE_TOP);
    bool shared_direct = is_shared && use_fd >= 0 &&
                         va_host_aligned && off_host_aligned && in_window;
    /* A2 sub-page shared file staging (P32-R3-3): guest-4K-aligned file
     * offsets below host granularity cannot map MAP_SHARED from the file,
     * so they share a memfd-backed staging object with the same alias and
     * fork visibility as a direct mapping instead of failing. */
    bool shared_staged = !shared_direct && vm32_is_a2() && is_shared &&
                         use_fd >= 0 &&
                         (host_flags & MAP_ANONYMOUS) == 0 &&
                         va_host_aligned && in_window;
    /* Guest-visible extent stays map_end: host_map_len may round up to a
     * host page, but the padding is backing only — publishing guest perms
     * over it would grant accessible memory past the requested mapping. */
    if ((shared_direct || shared_staged) && host_map_len > aligned_len) {
        uint32_t host_end = (uint32_t)((uint64_t)target_va + host_map_len);
        bool tail_busy = vm_range_overlaps_locked(map_end, host_end);
        if (tail_busy || !vm_can_modify_range_locked(target_va, host_end, true)) {
            if (sh_fd >= 0) { (void)close(sh_fd); }
            if (tail_busy && (flags & PPC32_MAP_FIXED_NOREPLACE) != 0U) {
                return (uint32_t)(-EEXIST);
            }
            return (uint32_t)(-ENOMEM);
        }
    }
    if (shared_direct) {
        int mprot = vm32_is_a2() ? (PROT_READ | PROT_WRITE) : host_prot;
        void *res = mmap(host_target, (size_t)host_map_len, mprot,
                         MAP_SHARED | MAP_FIXED, use_fd, host_off);
        if (res == MAP_FAILED && vm32_is_a2() && mprot != host_prot) {
            res = mmap(host_target, (size_t)host_map_len, host_prot,
                       MAP_SHARED | MAP_FIXED, use_fd, host_off);
        }
        if (res == MAP_FAILED) {
            int err = -errno;
            if (sh_fd >= 0) {
                (void)close(sh_fd);
            }
            return (uint32_t)err;
        }
        vm32_record_map(target_va, map_end, (uint8_t)(prot & 0x7U), state);
        if (vm32_is_a2()) {
            (void)vm32_sync_host_range(target_va, map_end);
        }
    } else if (shared_staged) {
        /* Coherent sub-page sharing through the staged object (sh_fd is
         * always -1 here: staging is file-backed only). */
        int serr = vm_file_shared_map_at(host_target, (size_t)host_map_len,
            use_fd, (uint64_t)host_off, target_va, map_end,
            (uint8_t)(prot & 0x7U), state);

        if (serr != 0) {
            return (uint32_t)serr;
        }
    } else if (vm32_is_a2()) {
        /* Shared mappings that are neither host-eligible (direct) nor
         * file-staged (anonymous MAP_SHARED below host granularity, or a
         * host-rounded tail past the window) still have no coherent
         * backing here: fail instead of reporting MAP_SHARED semantics
         * that a private copy could not honor. */
        if (is_shared) {
            bool misaligned = !va_host_aligned || !off_host_aligned;

            if (sh_fd >= 0) {
                (void)close(sh_fd);
            }
            return (uint32_t)(misaligned ? -EINVAL : -ENOMEM);
        }
        vm32_record_map(target_va, map_end,
            (uint8_t)(PROT_READ | PROT_WRITE), state);
        if (vm32_sync_host_range(target_va, map_end) != 0) {
            vm32_record_unmap(target_va, map_end);
            if (sh_fd >= 0) {
                (void)close(sh_fd);
            }
            return (uint32_t)(-ENOMEM);
        }
        if (use_fd < 0) {
            memset(host_target, 0, (size_t)aligned_len);
        } else {
            int prc = vm_file_populate_private(host_target, use_fd,
                (uint64_t)host_off, (size_t)aligned_len);
            if (prc != 0) {
                vm32_record_unmap(target_va, map_end);
                (void)vm32_sync_host_range(target_va, map_end);
                return (uint32_t)prc;
            }
        }
        vm32_record_map(target_va, map_end, (uint8_t)(prot & 0x7U), state);
        (void)vm32_sync_host_range(target_va, map_end);
    } else {
        void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                         host_flags | MAP_FIXED, use_fd,
                         (use_fd < 0) ? 0 : host_off);
        if (res == MAP_FAILED) {
            int err = -errno;
            if (sh_fd >= 0) {
                (void)close(sh_fd);
            }
            return (uint32_t)err;
        }
        if ((host_flags & MAP_ANONYMOUS) == 0 && use_fd >= 0) {
            vm_file_note_private(use_fd, target_va,
                (uint32_t)(aligned_len / 4096ULL),
                (uint64_t)host_off);
        }
        vm32_record_map(target_va, map_end, (uint8_t)(prot & 0x7U), state);
    }

    uint64_t rec_off = (use_fd >= 0) ? (uint64_t)host_off : 0ULL;
    uint32_t rec_len = (uint32_t)((uint64_t)map_end - (uint64_t)target_va);
    int rrc = vm_record_region_ex_locked(target_va, map_end, prot & 0x7U, flags, use_fd, rec_off, "[mmap]");
    if (sh_fd >= 0) {
        (void)close(sh_fd);
    }
    if (rrc < 0) {
        if (vm32_is_a2()) {
            (void)vm32_unmap_union(target_va, rec_len);
        } else {
            (void)vm_reserve_prot_none(ctx, target_va, rec_len);
            vm32_record_unmap(target_va, map_end);
        }
        return (uint32_t)(-ENOMEM);
    }
    /* Region publication unmaps overlapping ranges first, which drops
     * their inode records — including the fresh one populated above.
     * Re-register file backing after the insert so the new mapping
     * keeps its identity and EOF tracking. */
    if (sh_fd < 0 && use_fd >= 0 && (host_flags & MAP_ANONYMOUS) == 0) {
        vm_file_note_private(use_fd, target_va,
            (uint32_t)(aligned_len / 4096ULL),
            (uint64_t)host_off);
        if (is_shared && vm32_is_a2()) {
            vm_file_trap_beyond_eof(use_fd, target_va,
                (uint64_t)host_off, (size_t)aligned_len);
        }
    }
    if (update_cursor) {
        g_vm_mmap_cursor = (uint32_t)((uint64_t)target_va + host_map_len);
    }
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
        !vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL, NULL, 0U) ||
        !vm_can_modify_range_locked(addr, (uint32_t)end64, true)) {
        return -ENOMEM;
    }

    if (vm32_is_a2()) {
        int urc = vm32_protect_union(addr, (uint32_t)aligned_len,
            (uint8_t)(prot & 0x7U));
        if (urc != 0) {
            return urc;
        }
    } else {
        if (mprotect(ppc32_guest_ptr(ctx, addr), (size_t)aligned_len, ppc32_host_prot(ctx, prot)) != 0) {
            return -errno;
        }
        vm32_record_protect(addr, (uint32_t)end64,
            (uint8_t)(prot & 0x7U));
    }

    int mrc = vm_mprotect_regions_locked(addr, (uint32_t)end64, prot & 0x7U);
    vm32_tlb_invalidate_range(addr, (uint32_t)end64);
    vm32_ll_note_remap();
    return mrc;
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

static void vm_restore_src_prot(ppc32_ctx_t *ctx, uint32_t addr, size_t len, uint32_t prot)
{
    if (vm32_is_a2()) {
        (void)vm32_protect_union(addr, (uint32_t)len, (uint8_t)(prot & 0x7U));
    } else {
        (void)mprotect(ppc32_guest_ptr(ctx, addr), len, ppc32_host_prot(ctx, prot));
    }
}

static uint32_t vm_mremap_unlock(ppc32_ctx_t *ctx, int mremap_fd, uint32_t ret)
{
    if (mremap_fd >= 0) {
        (void)close(mremap_fd);
    }
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return ret;
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

    uint32_t prot        = 0x3U;
    uint32_t orig_flags  = 0x22U;
    int      orig_fd     = -1;
    uint64_t orig_offset = 0ULL;
    char     orig_name[64];
    orig_name[0] = '\0';
    if (!vm_check_mapped_range_ex_locked(old_addr, (uint32_t)((uint64_t)old_addr + old_aligned),
                                         &prot, &orig_flags, &orig_fd, &orig_offset,
                                         orig_name, sizeof(orig_name))) {
        return vm_mremap_unlock(ctx, -1, (uint32_t)(-EFAULT));
    }
    int mremap_fd = -1;
    if (orig_fd >= 0) {
        mremap_fd = vm_dup_fd(orig_fd);
        if (mremap_fd < 0) {
            return vm_mremap_unlock(ctx, -1, (uint32_t)(-ENOMEM));
        }
    }
    uint32_t    keep_flags  = orig_flags & 0x23U;
    bool        is_shared   = (keep_flags & 0x01U) != 0U;
    bool        has_fd      = (mremap_fd >= 0);
    uint32_t    map_flags   = (is_shared ? 0x01U : 0x02U) |
                              (has_fd ? 0U : PPC32_MAP_ANONYMOUS);
    int         map_fd      = has_fd ? mremap_fd : -1;
    const char *region_name = (orig_name[0] != '\0') ? orig_name : "[mmap]";
    uint64_t    hpsz        = (uint64_t)vm32_host_page_size();

    if (is_shared && (keep_flags & PPC32_MAP_ANONYMOUS) != 0U && has_fd &&
        new_aligned > old_aligned) {
        uint64_t req_sz = orig_offset + new_aligned;
        int grc;
        if (hpsz > (uint64_t)PPC32_PAGE_SIZE) {
            req_sz = (req_sz + hpsz - 1ULL) & ~(hpsz - 1ULL);
        }
        grc = vm_grow_shared_anon_fd(mremap_fd, req_sz);
        if (grc != 0) {
            return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)grc);
        }
    }

    if ((flags & PPC32_MREMAP_FIXED) == 0U) {
        if (new_aligned == old_aligned) {
            return vm_mremap_unlock(ctx, mremap_fd, old_addr);
        }
        if (new_aligned < old_aligned) {
            uint32_t unmap_addr = old_addr + (uint32_t)new_aligned;
            uint32_t unmap_len  = (uint32_t)(old_aligned - new_aligned);
            int rc = vm_munmap_locked(ctx, unmap_addr, unmap_len);
            (void)vm_mremap_unlock(ctx, mremap_fd, 0U);
            if (rc != 0) {
                return (uint32_t)rc;
            }
            vm_invalidate_jit(ctx, unmap_addr, unmap_addr + unmap_len);
            return old_addr;
        }

        uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
        uint64_t new_end = (uint64_t)old_addr + new_aligned;
        bool can_ext_inplace = (!is_shared || !vm32_is_a2() ||
                                ((uint64_t)old_end & (hpsz - 1ULL)) == 0ULL);
        if (can_ext_inplace && new_end <= (uint64_t)PPC32_TASK_SIZE_TOP &&
            !vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
            uint64_t ext_off   = has_fd ? (orig_offset + old_aligned) : 0ULL;
            uint32_t ext_pgoff = (uint32_t)(ext_off / (uint64_t)PPC32_PAGE_SIZE);
            uint32_t ext = vm_mmap2_locked(ctx, old_end, (uint32_t)(new_aligned - old_aligned),
                                           prot, map_flags | PPC32_MAP_FIXED,
                                           map_fd, ext_pgoff);
            if (ext <= 0xFFFFF000U) {
                if (vm_record_region_ex_locked(old_end, (uint32_t)new_end,
                                               prot, keep_flags, map_fd, ext_off, region_name) < 0) {
                    (void)vm_munmap_locked(ctx, old_end, (uint32_t)(new_aligned - old_aligned));
                    return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)(-ENOMEM));
                }
                uint32_t ext_end = (uint32_t)new_end;
                if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                    ext_end <= PPC32_MMAP_TOP_32) {
                    g_vm_mmap_cursor = ext_end;
                }
                (void)vm_mremap_unlock(ctx, mremap_fd, 0U);
                if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                    vm_invalidate_jit(ctx, old_end, ext_end);
                }
                return old_addr;
            }
        }

        if ((flags & PPC32_MREMAP_MAYMOVE) == 0U) {
            return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)(-ENOMEM));
        }
    } else {
        if ((new_addr & (PPC32_PAGE_SIZE - 1U)) != 0U || new_addr < PPC32_LOW_GUARD_SIZE ||
            (uint64_t)new_addr + new_aligned > (uint64_t)PPC32_TASK_SIZE_TOP ||
            ((uint64_t)new_addr < (uint64_t)old_addr + old_aligned &&
              (uint64_t)old_addr < (uint64_t)new_addr + new_aligned)) {
            return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)(-EINVAL));
        }
    }

    bool is_fixed      = (flags & PPC32_MREMAP_FIXED) != 0U;
    bool fixed_va_ok   = !is_fixed ||
                         (((uint64_t)new_addr & (hpsz - 1ULL)) == 0ULL);
    bool direct_ok     = ((orig_offset & (hpsz - 1ULL)) == 0ULL);
    /* A2 file-backed sub-page sharing restages through the same shared
     * object (P32-R3-3), so it moves like a directly backed mapping. */
    bool staged_ok     = vm32_is_a2() &&
                         (keep_flags & PPC32_MAP_ANONYMOUS) == 0U;
    bool shared_backed = is_shared && has_fd && fixed_va_ok &&
                         (!vm32_is_a2() || direct_ok || staged_ok);
    if ((is_shared && !shared_backed) ||
        !vm_can_modify_range_locked(old_addr, (uint32_t)((uint64_t)old_addr + old_aligned), false)) {
        return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)(-ENOMEM));
    }

    uint32_t init_prot  = shared_backed ? prot :
                          ((prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE));
    uint32_t orig_pgoff = has_fd ? (uint32_t)(orig_offset / (uint64_t)PPC32_PAGE_SIZE) : 0U;
    uint32_t new_va     = vm_mmap2_locked(ctx, is_fixed ? new_addr : 0U, (uint32_t)new_aligned,
                                          init_prot, map_flags | (is_fixed ? PPC32_MAP_FIXED : 0U),
                                          map_fd, orig_pgoff);
    if (new_va > 0xFFFFF000U) {
        return vm_mremap_unlock(ctx, mremap_fd, new_va);
    }

    bool src_reprotected = false;
    size_t copy_bytes = 0U;
    if (!shared_backed) {
        copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
        if (has_fd && !vm32_is_a2()) {
            struct stat st;
            if (fstat(map_fd, &st) == 0) {
                uint64_t fsz   = (st.st_size > 0) ? (uint64_t)st.st_size : 0ULL;
                uint64_t avail = (fsz > orig_offset) ? page_align_up(fsz - orig_offset) : 0ULL;
                if ((uint64_t)copy_bytes > avail) {
                    copy_bytes = (size_t)avail;
                }
            }
        }
        if (copy_bytes > 0U) {
            if ((prot & 0x1U) == 0U) {
                int prc = vm32_is_a2() ?
                    vm32_protect_union(old_addr, (uint32_t)copy_bytes, (uint8_t)PROT_READ) :
                    ((mprotect(ppc32_guest_ptr(ctx, old_addr), copy_bytes, PROT_READ) == 0) ? 0 : -errno);
                if (prc != 0) {
                    (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
                    return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)prc);
                }
                src_reprotected = true;
            }
            memcpy(ppc32_guest_ptr(ctx, new_va), ppc32_guest_ptr(ctx, old_addr), copy_bytes);
        }
        if (prot != init_prot) {
            int mrc = vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
            if (mrc != 0) {
                if (src_reprotected) {
                    vm_restore_src_prot(ctx, old_addr, copy_bytes, prot);
                }
                (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
                return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)mrc);
            }
        }
    }
    if (vm_record_region_ex_locked(new_va, (uint32_t)((uint64_t)new_va + new_aligned),
                                   prot, keep_flags, map_fd,
                                   has_fd ? orig_offset : 0ULL, region_name) < 0) {
        if (src_reprotected) {
            vm_restore_src_prot(ctx, old_addr, copy_bytes, prot);
        }
        (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
        return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)(-ENOMEM));
    }
    int urc = vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
    if (urc != 0) {
        if (src_reprotected) {
            vm_restore_src_prot(ctx, old_addr, copy_bytes, prot);
        }
        (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
        return vm_mremap_unlock(ctx, mremap_fd, (uint32_t)urc);
    }
    (void)vm_mremap_unlock(ctx, mremap_fd, 0U);

    vm_invalidate_jit(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
    if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
        vm_invalidate_jit(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
    }
    return new_va;
}
