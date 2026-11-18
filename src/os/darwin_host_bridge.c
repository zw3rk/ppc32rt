/*
 * src/os/darwin_host_bridge.c — G02 Darwin host bridge client (A32H 1.2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Narrow client of frozen include/a32host.h: reserves the 4 GiB window,
 * registers boot VMAs, runs interp/dbt/difftest, packs the GPR/FPR/VR
 * snapshot, and applies FLUSH_ICACHE / SYNC_VM_PROT / SPAWN_THREAD /
 * EXIT_THREAD / EXIT_PROCESS / DELIVER_SIGNAL. Two transports share one
 * core: the real /dev/a32host ioctl client (fn == NULL, hl provider)
 * and an in-process mock handler (host unit tests). No Mach-O, dyld,
 * BSD/Mach, libSystem, or UI code lives here.
 *
 * Threading model: guest segments and blocking host traps run unlocked
 * across main and worker threads. DBT cache lookup/install/invalidation
 * is serialized internally by cache.c (s_cache_lock + epoch-based
 * quiescent reclamation), and per-page VM/Soft-TLB state is serialized
 * by vm32's internal lock. g_bridge_mu serializes worker-slot/mirror
 * bookkeeping and SYNC_VM_PROT / FLUSH_ICACHE / SPAWN_THREAD replies.
 * The DBT emitter owner is _Thread_local, so translations on one thread
 * never run with another thread's emit context.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "os/darwin_host_bridge.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <unistd.h>

#include "dbt/dbt.h"
#include "dbt/difftest.h"
#include "dbt/emit_fp.h"
#include "dbt/emit_int.h"
#include "interp/interp.h"
#include "os/darwin_bridge_priv.h"
#include "os/hostfault.h"
#include "vm/vm32.h"

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

bool ppc32_darwin_is_bridge_personality(const char *p)
{
    return p != NULL && (strcmp(p, "darwin-host") == 0 ||
        strcmp(p, "hl-darwin") == 0);
}

bool ppc32_darwin_personality_known(const char *p)
{
    return ppc32_darwin_is_bridge_personality(p) ||
        (p != NULL && strcmp(p, "linux") == 0);
}

bool ppc32_darwin_personality_active(void)
{
    const char *env = getenv("PPC32RT_PERSONALITY");

    if (g_darwin_boot) {
        return true;
    }
    if (ppc32_darwin_is_bridge_personality(g_personality)) {
        return true;
    }
    return ppc32_darwin_is_bridge_personality(env);
}

/* Scan argv for bridge intent, stopping at "--" or the first positional
 * path (guest argv follows; nothing past it is an option). */
bool ppc32_darwin_cli_wants_bridge(int argc, char **argv,
    bool *out_darwin_boot)
{
    bool boot = false;
    bool want = false;
    int i;

    for (i = 1; i < argc; i++) {
        const char *s = argv[i];

        if (s == NULL || strcmp(s, "--") == 0 || s[0] != '-') {
            break;
        }
        if (strcmp(s, "--darwin-boot") == 0) {
            boot = true;
            want = true;
        } else if (strcmp(s, "--personality") == 0 && i + 1 < argc &&
            ppc32_darwin_is_bridge_personality(argv[i + 1])) {
            want = true;
        } else if (strncmp(s, "--personality=", 14) == 0 &&
            ppc32_darwin_is_bridge_personality(s + 14)) {
            want = true;
        }
    }
    if (ppc32_darwin_is_bridge_personality(getenv("PPC32RT_PERSONALITY"))) {
        want = true;
    }
    if (out_darwin_boot != NULL) {
        *out_darwin_boot = boot;
    }
    return want;
}

bool ppc32_darwin_is_macho_fd(int fd)
{
    uint8_t magic[4];
    uint32_t be;

    if (fd < 0 || pread(fd, magic, sizeof magic, 0) != 4) {
        return false;
    }
    be = ((uint32_t)magic[0] << 24) | ((uint32_t)magic[1] << 16) |
        ((uint32_t)magic[2] << 8) | magic[3];
    return be == 0xFEEDFACEU || be == 0xCEFAEDFEU ||
        be == 0xCAFEBABEU || be == 0xBEBAFECAU;
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

/* ---- real /dev/a32host transport (fd cached per process) ---- */

static pthread_mutex_t g_host_fd_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_host_fd = -1;

int bridge_host_ioctl(unsigned long req, void *arg)
{
    int fd;
    int rc;
    int e;

    pthread_mutex_lock(&g_host_fd_mu);
    if (g_host_fd < 0) {
        g_host_fd = open(A32H_DEV_PATH, O_RDWR | O_CLOEXEC);
        if (g_host_fd < 0) {
            pthread_mutex_unlock(&g_host_fd_mu);
            return -ENODEV;
        }
    }
    fd = g_host_fd;
    pthread_mutex_unlock(&g_host_fd_mu);
    for (;;) {
#if defined(__linux__)
        rc = (int)syscall(SYS_ioctl, fd, req, arg);
#else
        rc = ioctl(fd, req, arg);
#endif
        if (rc == 0) {
            return 0;
        }
        e = errno;
        if (e == EINTR) {
            continue;
        }
        if (e == EBADF) {
            pthread_mutex_lock(&g_host_fd_mu);
            if (g_host_fd == fd) {
                close(g_host_fd);
                g_host_fd = -1;
            }
            pthread_mutex_unlock(&g_host_fd_mu);
        }
        return (e != 0) ? -e : -EIO;
    }
}

int bridge_trap(a32h_darwin_handler_fn fn, void *opaque,
    unsigned long req, void *arg)
{
    return (fn != NULL) ? fn(opaque, req, arg) :
        bridge_host_ioctl(req, arg);
}

/* ---- bridge-wide serialization (engine segments and trap handling
 * on every thread) ---- */

static pthread_mutex_t g_bridge_mu = PTHREAD_MUTEX_INITIALIZER;

#define DARWIN_MAX_WORKERS 8U

void bridge_lock(void)
{
    pthread_mutex_lock(&g_bridge_mu);
}

void bridge_unlock(void)
{
    pthread_mutex_unlock(&g_bridge_mu);
}

/* ---- DBT emitter with thread-local owner ---- */

static _Thread_local ppc32_ctx_t *t_emit_owner;
static bool g_emitter_set;

void bridge_reset_emitter(void)
{
    pthread_mutex_lock(&g_bridge_mu);
    g_emitter_set = false;
    pthread_mutex_unlock(&g_bridge_mu);
}

static int bridge_emit(a64_buf_t *b, const ppc32_insn_t *insn, uint32_t pc)
{
    ppc32_emit_ctx_t e;
    int rc;

    ppc32_emit_begin(&e, t_emit_owner, b);
    rc = ppc32_emit_int(&e, insn, pc);
    if (rc == PPC32_EMIT_FALLBACK && !b->overflow) {
        rc = ppc32_emit_fp(&e, insn, pc);
    }
    return (rc == PPC32_EMIT_FALLBACK || b->overflow) ? 1 : 0;
}

static void bridge_stop_interp_body(ppc32_ctx_t *ctx)
{
    while (ctx->exit_reason == PPC32_EXIT_NONE) {
        interp_run(ctx);
    }
}

static void bridge_stop_dbt_body(ppc32_ctx_t *ctx)
{
    while (ctx->exit_reason == PPC32_EXIT_NONE) {
        (void)dbt_run(ctx);
    }
}

void bridge_run_stop(ppc32_ctx_t *ctx, int engine)
{
    if (engine == PPC32_ENGINE_DBT) {
        pthread_mutex_lock(&g_bridge_mu);
        if (!g_emitter_set) {
            ppc32_dbt_set_emitter(bridge_emit);
            g_emitter_set = true;
        }
        pthread_mutex_unlock(&g_bridge_mu);
        t_emit_owner = ctx;
        (void)ppc32_hostfault_run(ctx, bridge_stop_dbt_body);
    } else {
        (void)ppc32_hostfault_run(ctx, bridge_stop_interp_body);
    }
}

typedef struct {
    bool live;
    uint32_t tid;
    pthread_t th;
    ppc32_ctx_t *ctx;
} darwin_worker_t;

static darwin_worker_t g_workers[DARWIN_MAX_WORKERS];
static size_t g_live_workers;
static uint64_t g_window_base;

typedef struct {
    ppc32_ctx_t *ctx;
    a32h_darwin_handler_fn fn;
    void *opaque;
    int engine;
    uint32_t slot;
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
    /* The thread pointer lives in darwin_tls_tp (SPR 259). gpr[2] is
     * an ordinary ABI register on 32-bit Darwin PowerPC and is never
     * consulted here. */
    st->tls_tp = ctx->darwin_tls_tp;
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
    /* Never write gpr[PPC32_REG_TP]: r2 is a normal GPR here. */
    ctx->darwin_tls_tp = st->tls_tp;
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

static bool va_is_prot(uint32_t va, uint32_t kind)
{
    uint32_t need = (kind == (uint32_t)A32H_DFAULT_WRITE) ? 2U :
        (kind == (uint32_t)A32H_DFAULT_EXEC) ? 4U : 1U;
    uint8_t page_prot = 0U;

    return vm32_page_query(va, &page_prot) &&
        ((uint32_t)page_prot & need) == 0U;
}

static void forward_trap(a32h_darwin_handler_fn fn, void *opaque,
    a32h_darwin_trap_t *trap, a32h_darwin_cpu_state_t *st)
{
    trap->cpu_state_ptr = (uint64_t)(uintptr_t)st;
    (void)bridge_trap(fn, opaque, (unsigned long)A32H_DARWIN_TRAP, trap);
}

/* Forward one trap unlocked and apply its reply. Returns 0 on
 * EXIT_PROCESS (status set), 1 on EXIT_THREAD (worker rendezvous),
 * -1 to resume, -2 on fatal. Blocking host traps never hold g_bridge_mu. */
int bridge_handle_exit(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, int *status_out)
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

        prot = va_is_prot(ctx->fault_addr, kind);
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
        return -2;
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_EXIT_PROCESS) != 0U) {
        if (status_out != NULL) {
            *status_out = trap.exit_status;
        }
        return 0;
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_DELIVER_SIGNAL) != 0U) {
        /* The host rewrote cpu to the _sigtramp frame (r3..r5, r1);
         * apply the full FP/vector snapshot with it. */
        st.state_flags |= (uint32_t)(A32H_DSTATE_FP_DIRTY |
            A32H_DSTATE_VEC_DIRTY);
    }
    /* Publish post-reply CPU state to this thread's ctx before taking
     * g_bridge_mu for shared VM/cache/worker actions. */
    state_to_ctx(ctx, &st);
    if ((trap.reply_action & (uint32_t)(A32H_DACT_SYNC_VM_PROT |
        A32H_DACT_FLUSH_ICACHE | A32H_DACT_SPAWN_THREAD)) != 0U) {
        pthread_mutex_lock(&g_bridge_mu);
        if ((trap.reply_action & (uint32_t)A32H_DACT_SYNC_VM_PROT) != 0U) {
            bridge_apply_sync_prot(ctx, trap.prot_va, trap.prot_len,
                trap.prot_flags);
        }
        if ((trap.reply_action & (uint32_t)A32H_DACT_FLUSH_ICACHE) != 0U &&
            trap.flush_len != 0U) {
            uint64_t end64 = (uint64_t)trap.flush_va +
                (uint64_t)trap.flush_len;

            if (end64 > 0x100000000ULL) {
                end64 = 0x100000000ULL;
            }
            if (end64 > (uint64_t)trap.flush_va) {
                uint32_t end = (end64 >= 0x100000000ULL) ? 0xFFFFFFFFU :
                    (uint32_t)end64;

                vm32_tlb_invalidate_range(trap.flush_va, end);
                ppc32_dbt_invalidate_range(ctx, trap.flush_va, end);
                ctx->icache_flushes++;
            }
        }
        if ((trap.reply_action & (uint32_t)A32H_DACT_SPAWN_THREAD) != 0U) {
            size_t k;

            for (k = 0U; k < DARWIN_MAX_WORKERS; k++) {
                if (!g_workers[k].live) {
                    ppc32_ctx_t *child = calloc(1, sizeof *child);
                    worker_arg_t *arg = calloc(1, sizeof *arg);
                    pthread_t th;

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
                    child->reclaim_synced_gen = 0U;
                    child->exit_reason = PPC32_EXIT_NONE;
                    child->nip = trap.spawn_pc;
                    child->gpr[PPC32_REG_SP] = trap.spawn_sp;
                    child->gpr[3] = trap.spawn_r0;
                    child->lr = 0U;
                    child->darwin_tls_tp = trap.spawn_tls;
                    child->darwin_tid = trap.spawn_tid;
                    child->res_valid = 0U;
                    child->reservation_epoch++;
                    arg->ctx = child;
                    arg->fn = fn;
                    arg->opaque = opaque;
                    arg->engine = ctx->engine;
                    arg->slot = (uint32_t)k;
                    g_workers[k].live = true;
                    g_workers[k].tid = trap.spawn_tid;
                    g_workers[k].ctx = child;
                    g_live_workers++;
                    bridge_mirror_add(child);
                    if (pthread_create(&th, NULL, ppc32_darwin_worker_entry,
                        arg) != 0) {
                        bridge_mirror_remove(child);
                        g_workers[k].live = false;
                        g_workers[k].ctx = NULL;
                        g_live_workers--;
                        free(arg);
                        free(child);
                        break;
                    }
                    (void)pthread_detach(th);
                    g_workers[k].th = th;
                    break;
                }
            }
        }
        pthread_mutex_unlock(&g_bridge_mu);
    }
    if ((trap.reply_action & (uint32_t)A32H_DACT_EXIT_THREAD) != 0U) {
        if (status_out != NULL) {
            *status_out = trap.exit_status;
        }
        return 1;
    }
    return -1;
}

/* Whole-process exit from any thread: the worker path never returns.
 * In-process unit tests exercise this through a forked child. */
static void worker_exit_process(int status)
{
    _exit(status);
}

static void send_thread_exit(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque)
{
    a32h_darwin_cpu_state_t st;
    a32h_darwin_trap_t trap;

    memset(&trap, 0, sizeof trap);
    trap.arch = (uint32_t)A32H_ARCH_PPC32;
    trap.tid = (ctx->darwin_tid != 0U) ? ctx->darwin_tid : 1U;
    trap.exit_reason = (uint32_t)A32H_DEXIT_THREAD_EXIT;
    state_from_ctx(&st, ctx, ctx->nip, ctx->nip + 4U);
    forward_trap(fn, opaque, &trap, &st);
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

        bridge_run_stop(arg->ctx, arg->engine);
        if (arg->ctx->exit_reason == PPC32_EXIT_NONE) {
            continue;
        }
        rc = bridge_handle_exit(arg->ctx, arg->fn, arg->opaque, &status);
        if (rc == 0) {
            /* EXIT_PROCESS from any thread ends the process. */
            worker_exit_process(status);
        }
        if (rc == 1 || rc == -2) {
            break;
        }
    }
    /* EXIT_THREAD (or fatal): rendezvous unlocked, then reclaim slot. */
    send_thread_exit(arg->ctx, arg->fn, arg->opaque);
    ppc32_cache_forget_ctx(arg->ctx);
    pthread_mutex_lock(&g_bridge_mu);
    bridge_mirror_remove(arg->ctx);
    if (arg->slot < DARWIN_MAX_WORKERS && g_workers[arg->slot].live) {
        g_workers[arg->slot].live = false;
        g_workers[arg->slot].ctx = NULL;
        g_live_workers--;
    }
    pthread_mutex_unlock(&g_bridge_mu);
    free(arg->ctx);
    free(arg);
    return NULL;
}

int ppc32_darwin_run_loop(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, int engine)
{
    int status = 0;

    /* fn == NULL selects the real /dev/a32host transport (bridge_trap
     * routes through the cached ioctl fd). */
    if (ctx == NULL) {
        return 1;
    }
    ctx->engine = engine;
    for (;;) {
        int rc;

        bridge_run_stop(ctx, engine);
        if (ctx->exit_reason == PPC32_EXIT_NONE) {
            continue;
        }
        rc = bridge_handle_exit(ctx, fn, opaque, &status);
        if (rc == 0) {
            if (fn == NULL) {
                /* Real /dev/a32host transport: terminate the whole
                 * guest process immediately so parked workers never
                 * race teardown/unreserve. */
                _exit(status & 0xFF);
            }
            return status & 0xFF;
        }
        if (rc == 1) {
            return status & 0xFF;
        }
        if (rc == -2) {
            return 1;
        }
    }
}

void bridge_set_window(uint64_t base)
{
    g_window_base = base;
}

uint64_t bridge_take_window(void)
{
    uint64_t base = g_window_base;

    g_window_base = 0U;
    return base;
}

size_t bridge_live_workers(void)
{
    size_t n;

    pthread_mutex_lock(&g_bridge_mu);
    n = g_live_workers;
    pthread_mutex_unlock(&g_bridge_mu);
    return n;
}

/* The caller holds the bridge mutex (do_boot and bridge_teardown in
 * darwin_host_run.c both lock around reset + mirrors_reset): taking it
 * here too would self-deadlock a non-recursive mutex before BOOT. */
void bridge_reset_workers(void)
{
    size_t k;

    for (k = 0U; k < DARWIN_MAX_WORKERS; k++) {
        g_workers[k].live = false;
        g_workers[k].ctx = NULL;
    }
    g_live_workers = 0U;
}
