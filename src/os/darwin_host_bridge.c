/*
 * src/os/darwin_host_bridge.c — G02 Darwin host bridge client (A32H 1.2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Narrow client of frozen include/a32host.h: reserves the 4 GiB window,
 * registers boot VMAs, runs interp/dbt/difftest, packs the GPR/FPR/VR
 * snapshot, and applies FLUSH_ICACHE / SYNC_VM_PROT / SPAWN_THREAD /
 * DELIVER_SIGNAL / EXIT_PROCESS. No Mach-O, dyld, BSD/Mach, libSystem,
 * or UI code lives here.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/darwin_host_bridge.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dbt/dbt.h"
#include "dbt/difftest.h"
#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"
#include "interp/interp.h"
#include "os/hostfault.h"
#include "vm/vm32.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0x1000
#endif
#endif

static char g_personality[64];
static bool g_darwin_boot;

void ppc32_darwin_set_cli(const char *personality, bool darwin_boot)
{
    if (personality != NULL) {
        size_t n = strlen(personality);
        if (n >= sizeof g_personality) {
            n = sizeof g_personality - 1U;
        }
        memcpy(g_personality, personality, n);
        g_personality[n] = '\0';
    }
    g_darwin_boot = darwin_boot;
}

bool ppc32_darwin_personality_active(void)
{
    const char *env = getenv("PPC32RT_PERSONALITY");
    if (g_darwin_boot) {
        return true;
    }
    if (g_personality[0] != '\0' &&
        strcmp(g_personality, "darwin-host") == 0) {
        return true;
    }
    return env != NULL && strcmp(env, "darwin-host") == 0;
}

uint64_t ppc32_darwin_cache_key(const ppc32_ctx_t *ctx)
{
    uint64_t h;
    if (ctx == NULL) {
        return 0U;
    }
    h = ctx->darwin_aot_hash ^ 0x9E3779B97F4A7C15ULL;
    h ^= (uint64_t)(uint32_t)ctx->profile + 0x9E3779B97F4A7C15ULL;
    h ^= h >> 30;
    h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27;
    h *= 0x94D049BB133111EBULL;
    return h ^ (h >> 31);
}

static ppc32_ctx_t *g_emit_owner;

static int bridge_emit(a64_buf_t *b, const ppc32_insn_t *insn, uint32_t pc)
{
    ppc32_emit_ctx_t e;
    int rc;
    ppc32_emit_begin(&e, g_emit_owner, b);
    rc = ppc32_emit_int(&e, insn, pc);
    if (rc == PPC32_EMIT_FALLBACK && !b->overflow) {
        rc = ppc32_emit_fp(&e, insn, pc);
    }
    return (rc == PPC32_EMIT_FALLBACK || b->overflow) ? 1 : 0;
}

static void bridge_stop_interp(ppc32_ctx_t *ctx)
{
    while (ctx->exit_reason == PPC32_EXIT_NONE) {
        interp_run(ctx);
    }
}

static void bridge_stop_dbt(ppc32_ctx_t *ctx)
{
    while (ctx->exit_reason == PPC32_EXIT_NONE) {
        (void)dbt_run(ctx);
    }
}

static void run_engine_stop(ppc32_ctx_t *ctx, int engine)
{
    if (engine == PPC32_ENGINE_DBT) {
        g_emit_owner = ctx;
        ppc32_dbt_set_emitter(bridge_emit);
        (void)ppc32_hostfault_run(ctx, bridge_stop_dbt);
    } else {
        (void)ppc32_hostfault_run(ctx, bridge_stop_interp);
    }
}

#define DARWIN_MAX_WORKERS 8U

typedef struct {
    bool live;
    uint32_t tid;
    pthread_t th;
    ppc32_ctx_t *ctx;
} darwin_worker_t;

static darwin_worker_t g_workers[DARWIN_MAX_WORKERS];
static uint64_t g_window_base;
static bool g_window_is_4g;

typedef struct {
    ppc32_ctx_t *ctx;
    a32h_darwin_handler_fn fn;
    void *opaque;
    int engine;
} worker_arg_t;

static void state_from_ctx(a32h_darwin_cpu_state_t *st, ppc32_ctx_t *ctx,
    uint32_t pc, uint32_t next_pc)
{
    size_t i;
    memset(st, 0, sizeof *st);
    for (i = 0U; i < 32U; i++) {
        st->gpr[i] = ctx->gpr[i];
        st->fpr[i] = ctx->fpr[i];
    }
    st->pc = pc;
    st->next_pc = next_pc;
    st->lr = ctx->lr;
    st->ctr = ctx->ctr;
    st->cpsr_or_cr = ctx->cr;
    st->xer = ctx->xer;
    st->fpscr = ctx->fpscr;
    st->vrsave = ctx->vrsave;
    st->vscr = ctx->vscr;
    st->tls_tp = (ctx->darwin_tls_tp != 0U) ? ctx->darwin_tls_tp :
        ctx->gpr[PPC32_REG_TP];
    st->state_flags = (uint32_t)(A32H_DSTATE_FP_VALID | A32H_DSTATE_VEC_VALID);
    memcpy(st->vr, ctx->vr, sizeof st->vr);
}

static void state_to_ctx(ppc32_ctx_t *ctx,
    const a32h_darwin_cpu_state_t *st)
{
    size_t i;
    for (i = 0U; i < 32U; i++) {
        ctx->gpr[i] = st->gpr[i];
    }
    ctx->nip = st->pc;
    ctx->lr = st->lr;
    ctx->ctr = st->ctr;
    ctx->cr = st->cpsr_or_cr;
    ctx->xer = st->xer;
    ctx->darwin_tls_tp = st->tls_tp;
    ctx->gpr[PPC32_REG_TP] = st->tls_tp;
    if ((st->state_flags & (uint32_t)A32H_DSTATE_FP_DIRTY) != 0U) {
        for (i = 0U; i < 32U; i++) {
            ctx->fpr[i] = st->fpr[i];
        }
        ctx->fpscr = st->fpscr;
    }
    if ((st->state_flags & (uint32_t)A32H_DSTATE_VEC_DIRTY) != 0U) {
        memcpy(ctx->vr, st->vr, sizeof ctx->vr);
        ctx->vscr = st->vscr;
        ctx->vrsave = st->vrsave;
    }
    ctx->exit_reason = PPC32_EXIT_NONE;
}

static bool va_is_prot(ppc32_ctx_t *ctx, uint32_t va, uint32_t kind)
{
    uint32_t need = (kind == (uint32_t)A32H_DFAULT_WRITE) ? 2U :
        (kind == (uint32_t)A32H_DFAULT_EXEC) ? 4U : 1U;
    size_t i;
    for (i = 0U; i < ctx->region_count; i++) {
        if (va >= ctx->regions[i].start && va < ctx->regions[i].end) {
            return (ctx->regions[i].prot & need) == 0U;
        }
    }
    return false;
}

static void apply_sync_prot(ppc32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t prot)
{
    uint32_t end = va + len;
    uint8_t p = (uint8_t)(prot & 7U);
    size_t i;
    if (len == 0U) {
        return;
    }
    if (ctx->guest_base != 0U) {
        /* mprotect only: preserves live bytes on upgrades and faults
         * fresh zeros on first touch of sealed gaps. */
        void *hva = (void *)(uintptr_t)(ctx->guest_base + (uint64_t)va);
        int hp = (p == 0U) ? PROT_NONE : (PROT_READ | PROT_WRITE);
        (void)mprotect(hva, len, hp);
    }
    vm32_record_protect(va, end, p);
    if ((p & 4U) != 0U) {
        vm32_mark_guest_exec(va, end);
    }
    vm32_tlb_invalidate_range(va, end);
    ppc32_dbt_invalidate_range(ctx, va, end);
    for (i = 0U; i < ctx->region_count; i++) {
        if (ctx->regions[i].start < end && va < ctx->regions[i].end) {
            ctx->regions[i].prot = prot & 7U;
        }
    }
}

static void forward_trap(a32h_darwin_handler_fn fn, void *opaque,
    a32h_darwin_trap_t *trap, a32h_darwin_cpu_state_t *st)
{
    trap->cpu_state_ptr = (uint64_t)(uintptr_t)st;
    (void)fn(opaque, (unsigned long)A32H_DARWIN_TRAP, trap);
}

/* Returns 0 on EXIT_PROCESS, 1 on worker EXIT_PROCESS, -1 to resume. */
static int handle_one_exit(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, bool is_worker, int *status_out)
{
    a32h_darwin_cpu_state_t st;
    a32h_darwin_trap_t trap;
    uint32_t reason = ctx->exit_reason;
    memset(&trap, 0, sizeof trap);
    trap.arch = (uint32_t)A32H_ARCH_PPC32;
    trap.tid = (ctx->darwin_tid != 0U) ? ctx->darwin_tid : 1U;
    if (reason == (uint32_t)PPC32_EXIT_SYSCALL) {
        trap.exit_reason = (uint32_t)A32H_DEXIT_SVC_TRAP;
        trap.trap_imm = ctx->gpr[0];
        state_from_ctx(&st, ctx, ctx->nip, ctx->nip + 4U);
        forward_trap(fn, opaque, &trap, &st);
    } else if (reason == (uint32_t)PPC32_EXIT_FAULT) {
        bool prot;
        uint32_t kind = (ctx->fault_addr == ctx->nip) ?
            (uint32_t)A32H_DFAULT_EXEC :
            (ctx->fault_is_store != 0U ? (uint32_t)A32H_DFAULT_WRITE :
            (uint32_t)A32H_DFAULT_READ);
        prot = va_is_prot(ctx, ctx->fault_addr, kind);
        trap.exit_reason = (uint32_t)A32H_DEXIT_FAULT;
        trap.fault_va = ctx->fault_addr;
        trap.fault_kind = kind;
        trap.fault_is_prot = prot ? 1U : 0U;
        trap.fault_syndrome = (ctx->fault_is_store != 0U ? 0x02000000U : 0U) |
            (prot ? 0x08000000U : 0U) |
            (kind == (uint32_t)A32H_DFAULT_EXEC ? 0x40000000U : 0U);
        state_from_ctx(&st, ctx, ctx->nip, ctx->nip + 4U);
        forward_trap(fn, opaque, &trap, &st);
    } else if (reason == (uint32_t)PPC32_EXIT_TRAP) {
        trap.exit_reason = (uint32_t)A32H_DEXIT_BKPT;
        state_from_ctx(&st, ctx, ctx->nip, ctx->nip + 4U);
        forward_trap(fn, opaque, &trap, &st);
    } else if (reason == (uint32_t)PPC32_EXIT_UNDEF) {
        trap.exit_reason = (uint32_t)A32H_DEXIT_ILLEGAL;
        state_from_ctx(&st, ctx, ctx->nip, ctx->nip + 4U);
        forward_trap(fn, opaque, &trap, &st);
    } else {
        return -1;
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_EXIT_PROCESS) != 0U) {
        if (status_out != NULL) {
            *status_out = trap.exit_status;
        }
        if (is_worker) {
            memset(&trap, 0, sizeof trap);
            trap.arch = (uint32_t)A32H_ARCH_PPC32;
            trap.tid = (ctx->darwin_tid != 0U) ? ctx->darwin_tid : 1U;
            trap.exit_reason = (uint32_t)A32H_DEXIT_THREAD_EXIT;
            state_from_ctx(&st, ctx, ctx->nip, ctx->nip + 4U);
            forward_trap(fn, opaque, &trap, &st);
            return 1;
        }
        return 0;
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_SYNC_VM_PROT) != 0U) {
        apply_sync_prot(ctx, trap.prot_va, trap.prot_len, trap.prot_flags);
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_FLUSH_ICACHE) != 0U &&
        trap.flush_len != 0U) {
        uint32_t end = trap.flush_va + trap.flush_len;
        vm32_tlb_invalidate_range(trap.flush_va, end);
        ppc32_dbt_invalidate_range(ctx, trap.flush_va, end);
        ctx->icache_flushes++;
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_SPAWN_THREAD) != 0U) {
        size_t k;
        for (k = 0U; k < DARWIN_MAX_WORKERS; k++) {
            if (!g_workers[k].live) {
                ppc32_ctx_t *child = calloc(1, sizeof *child);
                worker_arg_t *arg = calloc(1, sizeof *arg);
                pthread_t th;
                extern void *ppc32_darwin_worker_entry(void *a);
                if (child == NULL || arg == NULL) {
                    free(child);
                    free(arg);
                    break;
                }
                memcpy(child, ctx, sizeof *child);
                memset(child->ras, 0, sizeof child->ras);
                memset(child->ibtc, 0, sizeof child->ibtc);
                child->ras_top = 0U;
                child->ibtc_synced_epoch = 0U;
                child->exit_reason = PPC32_EXIT_NONE;
                child->nip = trap.spawn_pc;
                child->gpr[PPC32_REG_SP] = trap.spawn_sp;
                child->gpr[3] = trap.spawn_r0;
                child->darwin_tls_tp = trap.spawn_tls;
                child->gpr[PPC32_REG_TP] = trap.spawn_tls;
                child->darwin_tid = trap.spawn_tid;
                child->res_valid = 0U;
                arg->ctx = child;
                arg->fn = fn;
                arg->opaque = opaque;
                arg->engine = ctx->engine;
                if (pthread_create(&th, NULL, ppc32_darwin_worker_entry,
                    arg) != 0) {
                    free(arg);
                    free(child);
                    break;
                }
                g_workers[k].live = true;
                g_workers[k].tid = trap.spawn_tid;
                g_workers[k].th = th;
                g_workers[k].ctx = child;
                break;
            }
        }
    }
    state_to_ctx(ctx, &st);
    return -1;
}

void *ppc32_darwin_worker_entry(void *a)
{
    worker_arg_t *arg = (worker_arg_t *)a;
    int status = 0;
    if (arg == NULL) {
        return NULL;
    }
    for (;;) {
        int rc;
        run_engine_stop(arg->ctx, arg->engine);
        if (arg->ctx->exit_reason == PPC32_EXIT_NONE) {
            continue;
        }
        if (arg->ctx->nip == 0U) {
            a32h_darwin_cpu_state_t st;
            a32h_darwin_trap_t trap;
            memset(&trap, 0, sizeof trap);
            trap.arch = (uint32_t)A32H_ARCH_PPC32;
            trap.tid = arg->ctx->darwin_tid;
            trap.exit_reason = (uint32_t)A32H_DEXIT_THREAD_EXIT;
            state_from_ctx(&st, arg->ctx, 0U, 4U);
            forward_trap(arg->fn, arg->opaque, &trap, &st);
            break;
        }
        rc = handle_one_exit(arg->ctx, arg->fn, arg->opaque, true, &status);
        if (rc == 0 || rc == 1) {
            break;
        }
    }
    free(arg);
    return NULL;
}

int ppc32_darwin_run_loop(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, int engine)
{
    int status = 0;
    if (ctx == NULL || fn == NULL) {
        return 1;
    }
    ctx->engine = engine;
    for (;;) {
        int rc;
        run_engine_stop(ctx, engine);
        if (ctx->exit_reason == PPC32_EXIT_NONE) {
            continue;
        }
        rc = handle_one_exit(ctx, fn, opaque, false, &status);
        if (rc == 0) {
            return status & 0xFF;
        }
    }
}

int ppc32_darwin_boot(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque)
{
    a32h_darwin_boot_t boot;
    a32h_darwin_vmap_t vmaps[16];
    size_t i;
    uint64_t base = 0U;
    bool use_mmap = false;
    if (ctx == NULL || fn == NULL) {
        return -EINVAL;
    }
    memset(ctx, 0, sizeof *ctx);
    memset(&boot, 0, sizeof boot);
    memset(vmaps, 0, sizeof vmaps);
    memset(g_workers, 0, sizeof g_workers);
    {
        void *rw = mmap(NULL, 0x100000000ULL, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (rw != MAP_FAILED) {
            base = (uint64_t)(uintptr_t)rw;
            use_mmap = true;
        } else {
            void *mem = mmap(NULL, 16U * 1024U * 1024U, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem == MAP_FAILED) {
                return -ENOMEM;
            }
            base = (uint64_t)(uintptr_t)mem;
        }
    }
    ctx->guest_base = base;
    vm32_shadow_window(base);
    ctx->vm_ready = true;
    g_window_base = base;
    g_window_is_4g = use_mmap;
    boot.arch = (uint32_t)A32H_ARCH_PPC32;
    boot.abi_minor = (uint32_t)A32H_ABI_MINOR_DARWIN;
    boot.window_base = base;
    boot.vmap_ptr = (uint64_t)(uintptr_t)vmaps;
    boot.vmap_cap = 16U;
    if (fn(opaque, (unsigned long)A32H_DARWIN_BOOT, &boot) != 0) {
        return -EIO;
    }
    if (boot.vmap_count > 16U) {
        return -E2BIG;
    }
    if (use_mmap) {
        /* Seal unmapped gaps PROT_NONE, keeping handler-loaded bytes:
         * VMAs arrive sorted by the mock/hl loader; seal [0,first),
         * between consecutive VMAs, and [last,4GiB). */
        uint64_t cursor = 0ULL;
        for (i = 0U; i < boot.vmap_count; i++) {
            uint64_t vs = (uint64_t)vmaps[i].va;
            if (vs > cursor) {
                (void)mprotect((void *)(uintptr_t)(base + cursor),
                    (size_t)(vs - cursor), PROT_NONE);
            }
            if (vs + (uint64_t)vmaps[i].len > cursor) {
                cursor = vs + (uint64_t)vmaps[i].len;
            }
        }
        if (cursor < 0x100000000ULL) {
            (void)mprotect((void *)(uintptr_t)(base + cursor),
                (size_t)(0x100000000ULL - cursor), PROT_NONE);
        }
    }
    for (i = 0U; i < boot.vmap_count; i++) {
        uint32_t va = vmaps[i].va;
        uint32_t len = vmaps[i].len;
        uint32_t prot = vmaps[i].prot & 7U;
        uint32_t end = va + len;
        if (len == 0U) {
            continue;
        }
        if (use_mmap) {
            /* mprotect (not remap) so BOOT-loaded bytes survive. Host
             * stays RW so the loader/handler can patch code; guest
             * RO/NX is enforced by the vm32 Soft-TLB, not the host. */
            void *hva = (void *)(uintptr_t)(base + (uint64_t)va);
            int hp = (prot != 0U) ? (PROT_READ | PROT_WRITE) : PROT_NONE;
            (void)mprotect(hva, len, hp);
        }
        vm32_record_map(va, end, (uint8_t)prot, (uint8_t)VM32_PAGE_ANON);
        if ((prot & 4U) != 0U) {
            vm32_mark_guest_exec(va, end);
        }
        if (ctx->region_count < PPC32_MAX_REGIONS) {
            ppc32_region_t *r = &ctx->regions[ctx->region_count++];
            r->start = va;
            r->end = end;
            r->prot = prot;
            r->flags = 0U;
            r->fd = -1;
            r->offset = 0U;
            r->name[0] = '\0';
        }
    }
    /* Fresh code image at reused VAs: drop all translated blocks from
     * previous runs in this process (dbt cache is pc-keyed). */
    ppc32_cache_invalidate_all(ctx);
    ctx->nip = boot.entry_pc;
    ctx->gpr[PPC32_REG_SP] = boot.entry_sp;
    ctx->gpr[3] = boot.entry_r0;
    ctx->darwin_tid = boot.initial_tid != 0U ? boot.initial_tid : 1U;
    ctx->darwin_aot_hash = boot.aot_personality_hash;
    ctx->profile = PPC32_PROFILE_CLASSIC;
    ctx->exit_reason = PPC32_EXIT_NONE;
    return 0;
}

int ppc32_run_darwin_with_handler(a32h_darwin_handler_fn fn, void *opaque,
    int engine, bool difftest)
{
    ppc32_ctx_t *ctx = NULL;
    int status = 0;
    size_t k;
    if (fn == NULL) {
        return 1;
    }
    if (engine != PPC32_ENGINE_INTERP && engine != PPC32_ENGINE_DBT) {
        engine = PPC32_ENGINE_INTERP;
    }
    ctx = calloc(1, sizeof *ctx);
    if (ctx == NULL) {
        return 1;
    }
    if (ppc32_darwin_boot(ctx, fn, opaque) != 0) {
        free(ctx);
        return 1;
    }
    if (!difftest) {
        status = ppc32_darwin_run_loop(ctx, fn, opaque, engine);
    } else {
        ppc32_ctx_t *ref = calloc(1, sizeof *ref);
        ppc32_ctx_t *dut = calloc(1, sizeof *dut);
        int mismatches = 0;
        uint64_t bound = 100000ULL;
        if (ref == NULL || dut == NULL) {
            free(ref);
            free(dut);
            free(ctx);
            return 1;
        }
        memcpy(ref, ctx, sizeof *ref);
        memcpy(dut, ctx, sizeof *dut);
        for (;;) {
            uint32_t stop;
            int rc;
            if (bound-- == 0ULL) {
                status = 2;
                break;
            }
            run_engine_stop(ref, PPC32_ENGINE_INTERP);
            run_engine_stop(dut, PPC32_ENGINE_DBT);
            if (ref->exit_reason != dut->exit_reason) {
                mismatches++;
                break;
            }
            stop = ref->nip;
            difftest_check(ref, dut, stop, &mismatches);
            for (size_t vi = 0U; vi < 32U && mismatches == 0; vi++) {
                for (size_t vk = 0U; vk < 16U; vk++) {
                    if (ref->vr[vi][vk] != dut->vr[vi][vk]) {
                        mismatches++;
                        break;
                    }
                }
            }
            if (ref->vscr != dut->vscr || ref->vrsave != dut->vrsave) {
                mismatches++;
            }
            if (mismatches != 0) {
                break;
            }
            if (ref->exit_reason != PPC32_EXIT_SYSCALL &&
                ref->exit_reason != PPC32_EXIT_FAULT &&
                ref->exit_reason != PPC32_EXIT_TRAP &&
                ref->exit_reason != PPC32_EXIT_UNDEF) {
                break;
            }
            memcpy(ctx, ref, sizeof *ctx);
            rc = handle_one_exit(ctx, fn, opaque, false, &status);
            memcpy(ref, ctx, sizeof *ref);
            memcpy(dut, ctx, sizeof *dut);
            if (rc == 0) {
                break;
            }
        }
        if (mismatches != 0) {
            status = 1;
        }
        free(ref);
        free(dut);
    }
    for (k = 0U; k < DARWIN_MAX_WORKERS; k++) {
        if (g_workers[k].live) {
            (void)pthread_join(g_workers[k].th, NULL);
            free(g_workers[k].ctx);
            g_workers[k].live = false;
        }
    }
    free(ctx);
    if (g_window_base != 0U) {
        if (g_window_is_4g) {
            (void)munmap((void *)(uintptr_t)g_window_base, 0x100000000ULL);
        } else {
            (void)munmap((void *)(uintptr_t)g_window_base,
                16U * 1024U * 1024U);
        }
        g_window_base = 0U;
    }
    vm32_tlb_invalidate_all();
    ppc32_dbt_set_emitter(NULL);
    return status & 0xFF;
}
