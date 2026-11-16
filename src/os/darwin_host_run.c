/*
 * src/os/darwin_host_run.c — G02 boot + run lifecycles (A32H 1.2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Window reservation, A32H_DARWIN_BOOT (with vmap retry + CommPage),
 * the real /dev/a32host lifecycle, the in-process mock lifecycle, and
 * the segment-isolated difftest lockstep runner. Trap handling itself
 * lives in darwin_host_bridge.c; VMA mirrors in darwin_host_vm.c.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/darwin_host_bridge.h"

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dbt/dbt.h"
#include "dbt/difftest.h"
#include "interp/interp.h"
#include "os/darwin_bridge_priv.h"
#include "os/hostfault.h"
#include "vm/vm32.h"

#define DARWIN_VMAP_STACK_CAP 64U
#define DARWIN_DIFFTEST_BOUND 100000ULL
/* Bounded worker quiesce at teardown: 200k yields (~seconds worst
 * case); stragglers are reaped by process exit, never hung on. */
#define DARWIN_QUIESCE_SPINS 200000U

/* Reserve the full 4 GiB window. want == 0 lets the kernel pick (mock
 * path); otherwise the exact address is required (real transport G)
 * and MAP_FIXED places it there. Never a short window: callers fail
 * instead of running with a truncated address space. */
static void *reserve_window_at(uint64_t want)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *at = (want == 0U) ? NULL : (void *)(uintptr_t)want;
    void *p;

    if (want != 0U) {
        flags |= MAP_FIXED;
    }
    p = mmap(at, 0x100000000ULL, PROT_READ | PROT_WRITE, flags, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

static void unreserve_window(void *base)
{
    if (base != NULL) {
        (void)munmap(base, 0x100000000ULL);
    }
}

static int do_boot(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, uint64_t want)
{
    a32h_darwin_boot_t boot;
    a32h_darwin_vmap_t stack_vmaps[DARWIN_VMAP_STACK_CAP];
    a32h_darwin_vmap_t *vmaps = stack_vmaps;
    bool heap_vmaps = false;
    void *base;
    size_t i;
    int rc = -EIO;

    memset(ctx, 0, sizeof *ctx);
    memset(&boot, 0, sizeof boot);
    memset(stack_vmaps, 0, sizeof stack_vmaps);
    bridge_lock();
    bridge_reset_workers();
    bridge_mirrors_reset();
    bridge_unlock();
    ppc32_hostfault_install();
    base = reserve_window_at(want);
    if (base == NULL) {
        return -ENOMEM;
    }
    ctx->guest_base = (uint64_t)(uintptr_t)base;
    vm32_shadow_window(ctx->guest_base);
    ctx->vm_ready = true;
    ctx->is_darwin = true;
    ctx->is_spe = 0U;
    ctx->profile = PPC32_PROFILE_CLASSIC;
    bridge_set_window(ctx->guest_base);
    bridge_mirror_add(ctx);
    boot.arch = (uint32_t)A32H_ARCH_PPC32;
    boot.abi_minor = (uint32_t)A32H_ABI_MINOR_DARWIN;
    boot.window_base = ctx->guest_base;
    boot.vmap_ptr = (uint64_t)(uintptr_t)vmaps;
    boot.vmap_cap = DARWIN_VMAP_STACK_CAP;
    if (bridge_trap(fn, opaque, (unsigned long)A32H_DARWIN_BOOT, &boot)
        != 0) {
        goto out;
    }
    if (boot.vmap_count > DARWIN_VMAP_STACK_CAP) {
        /* Dyld images exceed the stack cap: allocate exactly vmap_count
         * entries and re-issue BOOT so no VMA is dropped. */
        uint32_t want_n = boot.vmap_count;

        vmaps = calloc((size_t)want_n, sizeof *vmaps);
        if (vmaps == NULL) {
            rc = -ENOMEM;
            goto out;
        }
        heap_vmaps = true;
        memset(&boot, 0, sizeof boot);
        boot.arch = (uint32_t)A32H_ARCH_PPC32;
        boot.abi_minor = (uint32_t)A32H_ABI_MINOR_DARWIN;
        boot.window_base = ctx->guest_base;
        boot.vmap_ptr = (uint64_t)(uintptr_t)vmaps;
        boot.vmap_cap = want_n;
        if (bridge_trap(fn, opaque, (unsigned long)A32H_DARWIN_BOOT,
            &boot) != 0 || boot.vmap_count > want_n) {
            goto out;
        }
    }
    {
        /* Sort vmaps[] by ascending VA before sealing unmapped gaps
         * PROT_NONE so out-of-order segments (e.g. stack/heap appended
         * after CommPage) never leave an intermediate gap unsealed. */
        size_t hp = vm32_host_page_size();
        uint64_t mask = (hp == 0U) ? 0ULL : (uint64_t)(hp - 1U);
        uint64_t cursor = 0ULL;
        size_t j;

        for (i = 1U; i < boot.vmap_count; i++) {
            a32h_darwin_vmap_t cur = vmaps[i];

            j = i;
            while (j > 0U && vmaps[j - 1U].va > cur.va) {
                vmaps[j] = vmaps[j - 1U];
                j--;
            }
            vmaps[j] = cur;
        }
        for (i = 0U; i < boot.vmap_count; i++) {
            uint64_t vs = (uint64_t)vmaps[i].va;

            if (vs > cursor) {
                uint64_t s = cursor & ~mask;
                uint64_t e = (vs + mask) & ~mask;

                if (e > s) {
                    (void)mprotect(
                        (void *)(uintptr_t)(ctx->guest_base + s),
                        (size_t)(e - s), PROT_NONE);
                }
            }
            if (vs + (uint64_t)vmaps[i].len > cursor) {
                cursor = vs + (uint64_t)vmaps[i].len;
            }
        }
        if (cursor < 0x100000000ULL) {
            uint64_t s = cursor & ~mask;
            uint64_t e = 0x100000000ULL;

            if (e > s) {
                (void)mprotect(
                    (void *)(uintptr_t)(ctx->guest_base + s),
                    (size_t)(e - s), PROT_NONE);
            }
        }
    }
    for (i = 0U; i < boot.vmap_count; i++) {
        uint64_t end64 = (uint64_t)vmaps[i].va + (uint64_t)vmaps[i].len;
        uint32_t prot = vmaps[i].prot & 7U;

        if (vmaps[i].len == 0U) {
            continue;
        }
        if (end64 > 0x100000000ULL) {
            end64 = 0x100000000ULL;
        }
        if (end64 <= (uint64_t)vmaps[i].va) {
            continue;
        }
        bridge_register_vma(vmaps[i].va, (uint32_t)end64,
            (uint8_t)prot, ctx->guest_base);
    }
    if (boot.commpage_va != 0U && boot.commpage_size != 0U) {
        uint64_t cend = (uint64_t)boot.commpage_va +
            (uint64_t)boot.commpage_size;
        uint32_t cs = boot.commpage_va & ~0xFFFU;
        uint32_t ce;

        if (cend > 0x100000000ULL) {
            cend = 0x100000000ULL;
        }
        ce = (cend >= 0x100000000ULL) ? 0xFFFFFFFFU :
            (uint32_t)((cend + 0xFFFU) & ~0xFFFU);
        if (ce > cs) {
            /* CommPage data (timebase words): readable, RX so a
             * stray fetch faults cleanly instead of running data. */
            bridge_register_vma(cs, ce, 5U, ctx->guest_base);
        }
    }
    /* Fresh code image at reused VAs: drop all translated blocks from
     * previous runs in this process (dbt cache is pc-keyed). */
    ppc32_cache_invalidate_all(ctx);
    ctx->nip = boot.entry_pc;
    ctx->gpr[PPC32_REG_SP] = boot.entry_sp;
    ctx->gpr[3] = boot.entry_r0;
    ctx->darwin_tid = boot.initial_tid != 0U ? boot.initial_tid : 1U;
    /* Tag 0 is the Linux ELF personality: a zero hash from the host
     * must never alias it, so fall back to a fixed nonzero tag. */
    ctx->darwin_aot_hash = boot.aot_personality_hash != 0U ?
        boot.aot_personality_hash : 0xD4A71C0DEULL;
    ctx->exit_reason = PPC32_EXIT_NONE;
    rc = 0;
out:
    if (heap_vmaps) {
        free(vmaps);
    }
    if (rc != 0) {
        unreserve_window(base);
        bridge_set_window(0U);
        bridge_mirrors_reset();
    }
    return rc;
}

int ppc32_darwin_boot(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque)
{
    if (ctx == NULL || fn == NULL) {
        return -EINVAL;
    }
    return do_boot(ctx, fn, opaque, 0U);
}

/* Bounded worker quiesce + window teardown shared by both lifecycles. */
static void bridge_teardown(void)
{
    uint32_t spin = 0U;
    uint64_t base;

    while (bridge_live_workers() > 0U && spin++ < DARWIN_QUIESCE_SPINS) {
        sched_yield();
    }
    if (bridge_live_workers() == 0U) {
        base = bridge_take_window();
        unreserve_window((void *)(uintptr_t)base);
    }
    vm32_tlb_invalidate_all();
    ppc32_dbt_set_emitter(NULL);
    bridge_reset_emitter();
    bridge_lock();
    bridge_reset_workers();
    bridge_mirrors_reset();
    bridge_unlock();
    ppc32_tb_lockstep_on = false;
}

/* Segment-isolated lockstep difftest: the interp oracle (ref) and the
 * dbt DUT share one window, so the oracle's segment writes are
 * snapshotted away before the DUT runs each segment (working-set
 * shadow). vr/vscr/vrsave/fpr compare via difftest_check; the
 * timebase is frozen for 0 divergences. Unhandled exit reasons fail
 * cleanly (never spin). */
static int run_darwin_difftest(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque)
{
    ppc32_ctx_t *ref = calloc(1, sizeof *ref);
    ppc32_ctx_t *dut = calloc(1, sizeof *dut);
    ppc32_difftest_snap_t snap[PPC32_DIFFTEST_SNAP_CAP];
    size_t snap_n = 0U;
    bool incomplete = false;
    int mismatches = 0;
    int status = 0;
    uint64_t bound = DARWIN_DIFFTEST_BOUND;

    if (ref == NULL || dut == NULL) {
        free(ref);
        free(dut);
        return 1;
    }
    memcpy(ref, ctx, sizeof *ref);
    memcpy(dut, ctx, sizeof *dut);
    ref->engine = PPC32_ENGINE_INTERP;
    dut->engine = PPC32_ENGINE_DBT;
    bridge_mirror_add(ref);
    bridge_mirror_add(dut);
    snap_n = ppc32_difftest_snapshot(ctx, snap, PPC32_DIFFTEST_SNAP_CAP,
        &incomplete);
    if (incomplete) {
        ppc32_difftest_snap_free(snap, snap_n);
        free(ref);
        free(dut);
        return 1;
    }
    ppc32_tb_lockstep_on = true;
    for (;;) {
        int rc;

        if (bound-- == 0ULL) {
            status = 1;
            break;
        }
        bridge_run_stop(ref, PPC32_ENGINE_INTERP);
        ppc32_difftest_restore(ctx, snap, snap_n);
        bridge_run_stop(dut, PPC32_ENGINE_DBT);
        if (ref->exit_reason != dut->exit_reason) {
            mismatches++;
            status = 1;
            break;
        }
        difftest_check(ref, dut, ref->nip, &mismatches);
        if (mismatches != 0) {
            status = 1;
            break;
        }
        if (ref->exit_reason != PPC32_EXIT_SYSCALL &&
            ref->exit_reason != PPC32_EXIT_FAULT &&
            ref->exit_reason != PPC32_EXIT_TRAP &&
            ref->exit_reason != PPC32_EXIT_UNDEF) {
            status = 1;
            break;
        }
        memcpy(ctx, ref, sizeof *ctx);
        rc = bridge_handle_exit(ctx, fn, opaque, &status);
        memcpy(ref, ctx, sizeof *ref);
        ppc32_difftest_sync_dut(dut, ref);
        {
            int rfr = ppc32_difftest_refresh(ctx, snap, &snap_n);

            if (rfr != 0) {
                status = rfr;
                break;
            }
        }
        if (rc == 0 || rc == 1) {
            break;
        }
        if (rc == -2) {
            status = 1;
            break;
        }
    }
    ppc32_tb_lockstep_on = false;
    ppc32_difftest_snap_free(snap, snap_n);
    ppc32_cache_forget_ctx(ref);
    ppc32_cache_forget_ctx(dut);
    bridge_lock();
    bridge_mirror_remove(ref);
    bridge_mirror_remove(dut);
    bridge_unlock();
    if (mismatches != 0) {
        status = 1;
    }
    free(ref);
    free(dut);
    return status & 0xFF;
}

int ppc32_run_darwin_with_handler(a32h_darwin_handler_fn fn, void *opaque,
    int engine, bool difftest)
{
    ppc32_ctx_t *ctx = calloc(1, sizeof *ctx);
    int status;

    if (ctx == NULL || fn == NULL) {
        free(ctx);
        return 1;
    }
    if (engine != PPC32_ENGINE_INTERP && engine != PPC32_ENGINE_DBT) {
        engine = PPC32_ENGINE_INTERP;
    }
    if (do_boot(ctx, fn, opaque, 0U) != 0) {
        free(ctx);
        return 1;
    }
    if (!difftest) {
        status = ppc32_darwin_run_loop(ctx, fn, opaque, engine);
    } else {
        status = run_darwin_difftest(ctx, fn, opaque);
    }
    ppc32_cache_forget_ctx(ctx);
    bridge_teardown();
    free(ctx);
    return status & 0xFF;
}

int ppc32_run_darwin_host(const char *path, int engine, bool difftest)
{
    a32h_info_t info;
    ppc32_ctx_t *ctx;
    uint64_t want;
    int status;

    (void)path;
    memset(&info, 0, sizeof info);
    if (bridge_host_ioctl((unsigned long)A32H_GET_INFO, &info) != 0) {
        fputs("ppc32rt: /dev/a32host unavailable"
            " (hl hyper-linux provider required for darwin-host)\n",
            stderr);
        return 1;
    }
    if (info.abi_major != A32H_ABI_MAJOR) {
        fprintf(stderr,
            "ppc32rt: /dev/a32host ABI major %u != %u (frozen)\n",
            info.abi_major, A32H_ABI_MAJOR);
        return 1;
    }
    if ((info.caps & A32H_CAP_DARWIN_PERSONALITY) == 0ULL) {
        fputs("ppc32rt: /dev/a32host lacks A32H_CAP_DARWIN_PERSONALITY\n",
            stderr);
        return 1;
    }
    want = (info.window_hint != 0U) ? info.window_hint : 0x100000000ULL;
    if (engine != PPC32_ENGINE_INTERP && engine != PPC32_ENGINE_DBT) {
        engine = PPC32_ENGINE_INTERP;
    }
    ctx = calloc(1, sizeof *ctx);
    if (ctx == NULL) {
        return 1;
    }
    if (do_boot(ctx, NULL, NULL, want) != 0) {
        free(ctx);
        return 1;
    }
    if (!difftest) {
        status = ppc32_darwin_run_loop(ctx, NULL, NULL, engine);
    } else {
        status = run_darwin_difftest(ctx, NULL, NULL);
    }
    bridge_teardown();
    free(ctx);
    return status & 0xFF;
}
