/*
 * tests/check_p32_darwin_tlsvm.c — G02 thread/VM/TLS + timebase coverage
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side tests driving ppc32_run_darwin_with_handler with
 * in-process mock handlers (no /dev/a32host):
 *   k) mfspr/mtspr rD, 259 (SPRG3 TLS, r2 never clobbered).
 *   l) EXIT_THREAD vs worker EXIT_PROCESS (forked child for the
 *      whole-process kill).
 *   m) SYNC_VM_PROT(0) unmap (stale zeros gone, prot-0 faults,
 *      fresh-zero re-maps).
 *   n) mftb/mftbu under --difftest (0 divergences, frozen timebase).
 *   o) CLI personality / Mach-O helpers (pure unit checks).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "a32host.h"
#include "os/darwin_host_bridge.h"
#include "ppc32rt.h"

long ppc32_run_guest_child(ppc32_ctx_t *child)
{
    (void)child;
    return 0L;
}

static int g_fails = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        g_fails++; \
    } \
} while (0)

#include "check_p32_darwin_g02_enc.h"

static uint32_t w_tw_always(void)
{
    return w_x31(31, 0, 0, 4, 0);
}

static uint32_t w_ori(uint32_t rt, uint32_t ra, uint32_t u)
{
    return w_dform(24U, rt, ra, u);
}
/* ---- subtest (k): mfspr/mtspr rD, 259 (SPRG3 TLS) ---- */

typedef struct {
    uint64_t window;
    int sc_count;
} tk_t;

static int handler_k(void *opaque, unsigned long req, void *arg)
{
    tk_t *t = (tk_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        t->window = b->window_base;
        v[0].va = CODE_VA;
        v[0].len = 0x1000U;
        v[0].prot = 5U;
        v[0].flags = 0U;
        v[1].va = DATA_VA;
        v[1].len = 0x1000U;
        v[1].prot = 3U;
        v[1].flags = 0U;
        v[2].va = 0x300000U;
        v[2].len = 0x1000U;
        v[2].prot = 3U;
        v[2].flags = 0U;
        b->vmap_count = 3U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, c + 0U, 0x44000002U);
        w32(t->window, c + 4U, w_dform(15U, 2, 0, 0xDEAD));
        w32(t->window, c + 8U, w_ori(2, 2, 0xBEEF));
        w32(t->window, c + 12U, w_mfspr(5, 259));
        w32(t->window, c + 16U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 20U, w_dform(36U, 5, 4, 0));
        w32(t->window, c + 24U, w_dform(36U, 2, 4, 4));
        w32(t->window, c + 28U, w_dform(15U, 6, 0, 0xA5A5));
        w32(t->window, c + 32U, w_ori(6, 6, 0xA5A5));
        w32(t->window, c + 36U, w_mtspr(6, 259));
        w32(t->window, c + 40U, w_mfspr(7, 259));
        w32(t->window, c + 44U, w_dform(36U, 7, 4, 8));
        w32(t->window, c + 48U, 0x44000002U);
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            t->sc_count++;
            if (t->sc_count == 1) {
                st->tls_tp = 0x12345678U;
                st->pc = st->pc + 4U;
                st->next_pc = st->pc + 4U;
                return 0;
            }
            {
                int ok = 1;
                if (r32(t->window, DATA_VA) != 0x12345678U) {
                    ok = 0;
                }
                /* r2 is an ordinary GPR: the TLS round-trip must
                 * never clobber it. */
                if (r32(t->window, DATA_VA + 4U) != 0xDEADBEEFU) {
                    ok = 0;
                }
                if (st->gpr[2] != 0xDEADBEEFU) {
                    ok = 0;
                }
                if (r32(t->window, DATA_VA + 8U) != 0xA5A5A5A5U) {
                    ok = 0;
                }
                if (st->tls_tp != 0xA5A5A5A5U) {
                    ok = 0;
                }
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = ok ? 0 : 1;
                return 0;
            }
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 2;
        return 0;
    }
    return 0;
}

static int test_k(int engine)
{
    tk_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_k, &t, engine, false);
    CHECK(rc == 0, "k: mfspr 259 TLS without clobbering r2");
    CHECK(t.sc_count == 2, "k: two sc dispatches");
    if (rc == 0) {
        printf("altivec-k (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (l): EXIT_THREAD vs worker EXIT_PROCESS ---- */

#define L_ITERS 50U

typedef struct {
    uint64_t window;
    int thread_exits;
    uint32_t worker_va;
} tl_t;

static int handler_l(void *opaque, unsigned long req, void *arg)
{
    tl_t *t = (tl_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        uint32_t w = 0x100400U;
        t->window = b->window_base;
        t->worker_va = w;
        v[0].va = CODE_VA;
        v[0].len = 0x1000U;
        v[0].prot = 5U;
        v[0].flags = 0U;
        v[1].va = DATA_VA;
        v[1].len = 0x1000U;
        v[1].prot = 3U;
        v[1].flags = 0U;
        v[2].va = 0x300000U;
        v[2].len = 0x2000U;
        v[2].prot = 3U;
        v[2].flags = 0U;
        b->vmap_count = 3U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, DATA_VA, 0U);
        w32(t->window, c + 0U, w_dform(14U, 0, 0, 0x1001));
        w32(t->window, c + 4U, 0x44000002U);
        w32(t->window, c + 8U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 12U, w_dform(32U, 5, 4, 0));
        w32(t->window, c + 16U, w_cmpi(5, L_ITERS));
        w32(t->window, c + 20U, w_bne(c + 20U, c + 8U));
        w32(t->window, c + 24U, w_tw_always());
        /* Worker: atomic increment L_ITERS times, then trap out. */
        w32(t->window, w + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, w + 4U, w_lwarx(5, 0, 4));
        w32(t->window, w + 8U, w_dform(14U, 5, 5, 1));
        w32(t->window, w + 12U, w_stwcx(5, 0, 4));
        w32(t->window, w + 16U, w_bne(w + 16U, w + 4U));
        w32(t->window, w + 20U, w_dform(13U, 3, 3, 0xFFFFU));
        w32(t->window, w + 24U, w_bne(w + 24U, w + 4U));
        w32(t->window, w + 28U, w_tw_always());
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_THREAD_EXIT) {
            t->thread_exits++;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            tr->reply_action = A32H_DACT_SPAWN_THREAD;
            tr->spawn_tid = 2U;
            tr->spawn_pc = t->worker_va;
            tr->spawn_sp = 0x301000U;
            tr->spawn_r0 = L_ITERS;
            tr->spawn_tls = 0x77770000U;
            st->pc = st->pc + 4U;
            st->next_pc = st->pc + 4U;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_BKPT) {
            if (tr->tid == 2U) {
                tr->reply_action = A32H_DACT_EXIT_THREAD;
                return 0;
            }
            if (r32(t->window, DATA_VA) == L_ITERS &&
                t->thread_exits == 1) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 5;
            } else if (r32(t->window, DATA_VA) == L_ITERS) {
                st->pc = CODE_VA + 8U;
                st->next_pc = CODE_VA + 12U;
            } else {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 6;
            }
            return 0;
        }
    }
    return 0;
}

static int test_l(void)
{
    tl_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_l, &t,
        PPC32_ENGINE_INTERP, false);
    CHECK(rc == 5, "l: main EXIT_PROCESS status 5");
    CHECK(t.thread_exits == 1, "l: one THREAD_EXIT rendezvous");
    if (rc == 5 && t.thread_exits == 1) {
        printf("altivec-l (thread exit): PASS\n");
    }
    return (rc == 5) ? 0 : 1;
}

/* Worker EXIT_PROCESS must kill the whole process: exercised in a
 * forked child so the parent's test runner survives the _exit. */
typedef struct {
    uint64_t window;
    uint32_t worker_va;
} tlp_t;

static int handler_lp(void *opaque, unsigned long req, void *arg)
{
    tlp_t *t = (tlp_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        uint32_t w = 0x100400U;
        t->window = b->window_base;
        t->worker_va = w;
        v[0].va = CODE_VA;
        v[0].len = 0x1000U;
        v[0].prot = 5U;
        v[0].flags = 0U;
        v[1].va = DATA_VA;
        v[1].len = 0x1000U;
        v[1].prot = 3U;
        v[1].flags = 0U;
        v[2].va = 0x300000U;
        v[2].len = 0x2000U;
        v[2].prot = 3U;
        v[2].flags = 0U;
        b->vmap_count = 3U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, c + 0U, w_dform(14U, 0, 0, 1));
        w32(t->window, c + 4U, 0x44000002U);
        w32(t->window, c + 8U, w_tw_always());
        w32(t->window, w + 0U, w_tw_always());
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            tr->reply_action = A32H_DACT_SPAWN_THREAD;
            tr->spawn_tid = 2U;
            tr->spawn_pc = t->worker_va;
            tr->spawn_sp = 0x301000U;
            tr->spawn_r0 = 0U;
            tr->spawn_tls = 0U;
            st->pc = st->pc + 4U;
            st->next_pc = st->pc + 4U;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_BKPT) {
            if (tr->tid == 2U) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 7;
                return 0;
            }
            /* Main spins; the worker's EXIT_PROCESS ends us. */
            st->pc = CODE_VA + 8U;
            st->next_pc = CODE_VA + 12U;
            return 0;
        }
    }
    return 0;
}

static int test_l_process(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        CHECK(0, "lp: fork failed");
        return 1;
    }
    if (pid == 0) {
        tlp_t t;
        int rc;
        memset(&t, 0, sizeof t);
        rc = ppc32_run_darwin_with_handler(handler_lp, &t,
            PPC32_ENGINE_INTERP, false);
        _exit(rc == 7 ? 7 : 99);
    }
    {
        int st = 0;
        pid_t w = waitpid(pid, &st, 0);
        CHECK(w == pid, "lp: child reaped");
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7,
            "lp: worker EXIT_PROCESS status 7 kills process");
        if (w == pid && WIFEXITED(st) && WEXITSTATUS(st) == 7) {
            printf("altivec-lp (worker exit process): PASS\n");
            return 0;
        }
        return 1;
    }
}

/* ---- subtest (m): SYNC_VM_PROT(0) unmap ---- */

#define M_PAGE 0x210000U

typedef struct {
    uint64_t window;
    int faults;
    int saw_unmapped;
} tm_t;

static int handler_m(void *opaque, unsigned long req, void *arg)
{
    tm_t *t = (tm_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        t->window = b->window_base;
        v[0].va = CODE_VA;
        v[0].len = 0x1000U;
        v[0].prot = 5U;
        v[0].flags = 0U;
        v[1].va = M_PAGE;
        v[1].len = 0x1000U;
        v[1].prot = 3U;
        v[1].flags = 0U;
        v[2].va = 0x300000U;
        v[2].len = 0x1000U;
        v[2].prot = 3U;
        v[2].flags = 0U;
        b->vmap_count = 3U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, c + 0U, w_dform(15U, 4, 0, 0x21));
        w32(t->window, c + 4U, w_dform(15U, 5, 0, 0x4242));
        w32(t->window, c + 8U, w_ori(5, 5, 0x4242));
        w32(t->window, c + 12U, w_dform(36U, 5, 4, 0));
        w32(t->window, c + 16U, 0x44000002U);
        w32(t->window, c + 20U, w_dform(32U, 6, 4, 0));
        w32(t->window, c + 24U, w_cmpi(6, 0));
        w32(t->window, c + 28U, w_bne(c + 28U, c + 48U));
        w32(t->window, c + 32U, w_dform(15U, 7, 0, 0x1111));
        w32(t->window, c + 36U, w_ori(7, 7, 0x1111));
        w32(t->window, c + 40U, w_dform(36U, 7, 4, 0));
        w32(t->window, c + 44U, 0x44000002U);
        w32(t->window, c + 48U, w_tw_always());
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            if (r32(t->window, M_PAGE) == 0x42424242U && t->faults == 0) {
                /* First sc: unmap the page under the guest. */
                tr->reply_action = A32H_DACT_SYNC_VM_PROT;
                tr->prot_va = M_PAGE;
                tr->prot_len = 0x1000U;
                tr->prot_flags = 0U;
                st->pc = st->pc + 4U;
                st->next_pc = st->pc + 4U;
                return 0;
            }
            if (r32(t->window, M_PAGE) == 0x11111111U &&
                t->saw_unmapped) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
                return 0;
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = 1;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_FAULT) {
            t->faults++;
            if (tr->fault_va == M_PAGE && tr->fault_is_prot == 0U &&
                tr->fault_kind == (uint32_t)A32H_DFAULT_READ) {
                t->saw_unmapped = 1;
            }
            /* Re-map RW (fresh zeros) and resume the faulting load. */
            tr->reply_action = A32H_DACT_SYNC_VM_PROT;
            tr->prot_va = M_PAGE;
            tr->prot_len = 0x1000U;
            tr->prot_flags = 3U;
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 3;
        return 0;
    }
    return 0;
}

static int test_m(int engine)
{
    tm_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_m, &t, engine, false);
    CHECK(rc == 0, "m: unmap/re-map lifecycle exit 0");
    CHECK(t.saw_unmapped, "m: unmapped fault va/prot/kind");
    if (rc == 0 && t.saw_unmapped) {
        printf("altivec-m (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (n): mftb under --difftest (0 divergences) ---- */

typedef struct {
    uint64_t window;
} tn_t;

static int handler_n(void *opaque, unsigned long req, void *arg)
{
    tn_t *t = (tn_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        t->window = b->window_base;
        v[0].va = CODE_VA;
        v[0].len = 0x1000U;
        v[0].prot = 5U;
        v[0].flags = 0U;
        v[1].va = DATA_VA;
        v[1].len = 0x1000U;
        v[1].prot = 3U;
        v[1].flags = 0U;
        v[2].va = 0x300000U;
        v[2].len = 0x1000U;
        v[2].prot = 3U;
        v[2].flags = 0U;
        b->vmap_count = 3U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, c + 0U, w_mftb(20, 268));
        w32(t->window, c + 4U, w_mftb(21, 269));
        w32(t->window, c + 8U, w_mftb(22, 268));
        w32(t->window, c + 12U, w_mftb(23, 269));
        w32(t->window, c + 16U, w_subf(11, 21, 23));
        w32(t->window, c + 20U, w_cmpi(11, 0));
        w32(t->window, c + 24U, w_blt(c + 24U, c + 48U));
        w32(t->window, c + 28U, w_subf(11, 20, 22));
        w32(t->window, c + 32U, w_cmpi(11, 0));
        w32(t->window, c + 36U, w_blt(c + 36U, c + 48U));
        /* No clearing: TB samples stay live in r20..r23, so any
         * engine skew would diverge at the sc compare. */
        w32(t->window, c + 40U, 0x44000002U);
        w32(t->window, c + 44U, 0x44000002U);
        w32(t->window, c + 48U, w_tw_always());
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = 0;
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 5;
        return 0;
    }
    return 0;
}

static int test_n(void)
{
    tn_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_n, &t,
        PPC32_ENGINE_INTERP, true);
    CHECK(rc == 0, "n: mftb difftest 0 divergences");
    if (rc == 0) {
        printf("altivec-n (difftest): PASS\n");
    }
    return rc;
}

/* ---- subtest (o): CLI personality / Mach-O helpers ---- */

static int test_o(void)
{
    char *argv1[] = { (char *)"ppc32rt", (char *)"--personality",
        (char *)"darwin-host", (char *)"--", (char *)"prog" };
    char *argv2[] = { (char *)"ppc32rt", (char *)"--",
        (char *)"--personality", (char *)"darwin-host" };
    char *argv3[] = { (char *)"ppc32rt", (char *)"--personality=hl-darwin" };
    char *argv4[] = { (char *)"ppc32rt", (char *)"--personality",
        (char *)"linux" };
    bool boot = false;
    char path[] = "/tmp/check_p32_altivec_machoXXXXXX";
    int fd = mkstemp(path);
    int ok = 1;

    CHECK(ppc32_darwin_personality_known("darwin-host"), "o: darwin-host");
    CHECK(ppc32_darwin_personality_known("hl-darwin"), "o: hl-darwin");
    CHECK(ppc32_darwin_personality_known("linux"), "o: linux");
    CHECK(!ppc32_darwin_personality_known("windows"), "o: reject windows");
    CHECK(!ppc32_darwin_personality_known(NULL), "o: reject NULL");
    CHECK(ppc32_darwin_cli_wants_bridge(5, argv1, &boot), "o: bridge argv");
    CHECK(ppc32_darwin_cli_wants_bridge(4, argv2, NULL) == false,
        "o: stops at --");
    CHECK(ppc32_darwin_cli_wants_bridge(2, argv3, NULL), "o: = form");
    CHECK(ppc32_darwin_cli_wants_bridge(3, argv4, NULL) == false,
        "o: linux is not bridge");
    if (fd >= 0) {
        uint8_t macho[4] = { 0xFE, 0xED, 0xFA, 0xCE };
        uint8_t elf[4] = { 0x7F, 'E', 'L', 'F' };
        if (write(fd, macho, 4) == 4 && lseek(fd, 0, SEEK_SET) == 0) {
            ok = ppc32_darwin_is_macho_fd(fd) ? 1 : 0;
            CHECK(ok == 1, "o: Mach-O fd detected");
        } else {
            CHECK(0, "o: macho fixture write");
        }
        if (lseek(fd, 0, SEEK_SET) == 0 && write(fd, elf, 4) == 4 &&
            lseek(fd, 0, SEEK_SET) == 0) {
            ok = ppc32_darwin_is_macho_fd(fd) ? 0 : 1;
            CHECK(ok == 1, "o: ELF fd rejected");
        } else {
            CHECK(0, "o: elf fixture write");
        }
        CHECK(ppc32_darwin_is_macho_fd(-1) == false, "o: bad fd rejected");
        close(fd);
        unlink(path);
    } else {
        CHECK(0, "o: mkstemp failed");
    }
    printf("altivec-o (cli helpers): PASS\n");
    return 0;
}

int main(void)
{
    int rc = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    {
        int i;
        int engines[2] = { PPC32_ENGINE_INTERP, PPC32_ENGINE_DBT };
        int (*fns[])(int) = { test_k, test_m };
        size_t nf = sizeof fns / sizeof fns[0];
        size_t f;
        for (f = 0U; f < nf; f++) {
            for (i = 0; i < 2; i++) {
                if (fns[f](engines[i]) != 0) {
                    rc = 1;
                }
            }
        }
    }
    if (test_l() != 0) {
        rc = 1;
    }
    if (test_l_process() != 0) {
        rc = 1;
    }
    if (test_n() != 0) {
        rc = 1;
    }
    if (test_o() != 0) {
        rc = 1;
    }
    if (g_fails == 0 && rc == 0) {
        printf("check_p32_darwin_tlsvm: ALL OK\n");
        return 0;
    }
    printf("check_p32_darwin_tlsvm: %d FAILURE(S)\n", g_fails);
    return 1;
}
