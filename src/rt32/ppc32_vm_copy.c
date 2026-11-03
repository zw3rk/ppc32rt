/*
 * src/rt32/ppc32_vm_copy.c — Permission-checked guest copy helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from ppc32_vm_regions.c (file-size discipline): the sub-page
 * permission check and the safe copyin/copyout used by the syscall,
 * signal, and thread layers. Every helper validates guest permissions
 * against the region table (P32-R4-11), so an accessible neighboring
 * sub-page on A2 can never launder access to a read-only or unmapped
 * target. Copyout additionally invalidates overlapping LL/SC
 * reservations on every store commit (P32-R4-12: a peer stwcx. must
 * fail even when the copyout writes the same value) and fans the bytes
 * out to overlapping staged shared-file aliases.
 *
 * All helpers acquire the VM lock only when the caller does not hold
 * it (P32-R4-8), so they stay callable from locked region paths and
 * unlocked syscall paths alike without nesting.
 */

#include "ppc32_vm_priv.h"

#include <errno.h>
#include <string.h>

#include "vm/vm32.h"

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
    bool ok;
    bool held;

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
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    ok = vm_range_prot_ok_locked(ctx, va, (uint32_t)end, need_prot);
    if (!held) {
        vm_lock_release();
    }
    return ok;
}

int ppc32_vm_copyin_safe(const ppc32_ctx_t *ctx, uint32_t va,
                         void *dst, size_t len)
{
    bool held;
    bool ok;

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
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    ok = vm_range_prot_ok_locked(ctx, va, (uint32_t)end, 1U);
    if (ok) {
        memcpy(dst, ppc32_guest_ptr(ctx, va), len);
    }
    if (!held) {
        vm_lock_release();
    }
    return ok ? 0 : -EFAULT;
}

int ppc32_vm_copyout_safe(const ppc32_ctx_t *ctx, uint32_t va,
                          const void *src, size_t len)
{
    bool held;
    bool ok;

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
    held = vm_lock_held_by_self();
    if (!held) {
        vm_lock_acquire();
    }
    ok = vm_range_prot_ok_locked(ctx, va, (uint32_t)end, 2U);
    if (ok) {
        memcpy(ppc32_guest_ptr(ctx, va), src, len);
        /* A committed guest store kills peer reservations even when
         * the value is unchanged (P32-R4-12), then fans out to staged
         * shared-file aliases (P32-R4-3). Both run under the VM lock
         * already held here; neither takes another lock. */
        vm32_store_invalidate_range(va, (uint32_t)len);
        vm_file_shared_cohere_store(ctx, va, (uint32_t)len);
    }
    if (!held) {
        vm_lock_release();
    }
    return ok ? 0 : -EFAULT;
}
