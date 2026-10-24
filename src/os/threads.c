/*
 * src/os/threads.c — PPC32 multithreading: clone/TLS/futex (Phase 4, L4b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the L4b card of docs/lanes/phase-4.md against the frozen
 * ppc32_ctx_t (src/ppc32rt.h): clone(2) thread creation with
 * CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_CHILD_CLEARTID, futex
 * WAIT/WAKE/REQUEUE (+PRIVATE), r2 TLS plumbing (E06), set_tid_address,
 * and LL/SC reservation invalidation (SPEC 2.2).
 *
 * Deliberately self-contained: besides ppc32rt.h static inlines this
 * file calls only libc, so it cross-compiles and links on its own
 * (acceptance) and drops into the full binary unchanged. It performs
 * no guest-window mapping changes itself — stacks and thread memory
 * come from the guest via the normal (D19-locked) ppc32_vm_* mmap
 * path — so the only shared mutable state here is the thread table,
 * guarded by its own spinlock. Reservation invalidation is local to
 * each ctx (res_valid + reservation_epoch), which signal delivery
 * (L4a) and engine helpers also bump.
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "os/threads.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/* ---- local guest-memory helpers (BE scalars, memcpy-based) ----
 * Private copies of the convert.c shapes so this file links alone;
 * semantics match ppc32_ld/st32be and ppc32_range_ok for in-window
 * thread words (tid addresses, futex words, TLS area heads). */

static bool thread_range_ok(const ppc32_ctx_t *ctx, uint32_t va, size_t len)
{
    uint64_t end;

    (void)ctx;
    if (len == 0U) {
        return true;
    }
    if (len > PPC32_TASK_SIZE_TOP) {
        return false;
    }
    end = (uint64_t)va + (uint64_t)len;
    if (end > (uint64_t)PPC32_TASK_SIZE_TOP || end < (uint64_t)va) {
        return false;
    }
    if (va < PPC32_LOW_GUARD_SIZE) {
        return false;
    }
    return true;
}

static uint32_t thread_ld32be(const ppc32_ctx_t *ctx, uint32_t va)
{
    uint32_t raw = 0U;

    memcpy(&raw, ppc32_guest_ptr(ctx, va), sizeof(raw));
    return ppc32_be32(raw);
}

static void thread_st32be(const ppc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint32_t raw = ppc32_be32(v);

    memcpy(ppc32_guest_ptr(ctx, va), &raw, sizeof(raw));
}

/* ---- thread table (fixed, spinlock-guarded) ---- */

typedef struct {
    bool         used;
    ppc32_ctx_t *ctx;
    pthread_t    host;
    uint32_t     guest_tid;
} ppc32_thread_slot_t;

static ppc32_thread_slot_t g_thread_table[PPC32_MAX_THREADS];
static _Atomic uint32_t g_thread_lock = 0U;
static _Atomic uint32_t g_next_tid = 0U;
static bool g_threads_inited = false;

static void thread_lock(void)
{
    ppc32_spin_lock(&g_thread_lock);
}

static void thread_unlock(void)
{
    ppc32_spin_unlock(&g_thread_lock);
}

/* Caller must hold thread_lock. Returns the slot or NULL when full. */
static ppc32_thread_slot_t *thread_claim_locked(ppc32_ctx_t *ctx,
    uint32_t guest_tid)
{
    uint32_t i;

    for (i = 0U; i < PPC32_MAX_THREADS; i++) {
        if (!g_thread_table[i].used) {
            g_thread_table[i].used = true;
            g_thread_table[i].ctx = ctx;
            g_thread_table[i].guest_tid = guest_tid;
            memset(&g_thread_table[i].host, 0, sizeof(pthread_t));
            return &g_thread_table[i];
        }
    }
    return NULL;
}

static ppc32_thread_slot_t *thread_find_locked(uint32_t guest_tid)
{
    uint32_t i;

    for (i = 0U; i < PPC32_MAX_THREADS; i++) {
        if (g_thread_table[i].used && g_thread_table[i].guest_tid == guest_tid) {
            return &g_thread_table[i];
        }
    }
    return NULL;
}

static uint32_t thread_alloc_tid(void)
{
    return atomic_fetch_add_explicit(&g_next_tid, 1U, memory_order_relaxed);
}

#ifdef __linux__
static long host_gettid(void)
{
    return (long)syscall(SYS_gettid);
}
#else
static long host_gettid(void)
{
    return (long)getpid();
}
#endif

long ppc32_thread_init_main(ppc32_ctx_t *ctx)
{
    uint32_t tid;

    if (ctx == NULL) {
        return -EINVAL;
    }
    tid = (uint32_t)host_gettid();
    thread_lock();
    memset(g_thread_table, 0, sizeof(g_thread_table));
    g_thread_table[0].used = true;
    g_thread_table[0].ctx = ctx;
    g_thread_table[0].host = pthread_self();
    g_thread_table[0].guest_tid = tid;
    thread_unlock();
    atomic_store_explicit(&g_next_tid, tid + 1U, memory_order_relaxed);
    g_threads_inited = true;
    ctx->host_tid = (int)tid;
    ctx->guest_pid = tid;
    ctx->guest_tid = tid;
    ctx->is_thread_clone = false;
    ppc32_reservation_invalidate(ctx);
    return 0;
}

uint32_t ppc32_thread_count(void)
{
    uint32_t n = 0U;
    uint32_t i;

    if (!g_threads_inited) {
        return 0U;
    }
    thread_lock();
    for (i = 0U; i < PPC32_MAX_THREADS; i++) {
        if (g_thread_table[i].used) {
            n++;
        }
    }
    thread_unlock();
    return n;
}

/* ---- TLS + reservation ---- */

void ppc32_tls_set(ppc32_ctx_t *ctx, uint32_t tls_va)
{
    if (ctx == NULL) {
        return;
    }
    ctx->gpr[PPC32_REG_TP] = tls_va;
    ppc32_reservation_invalidate(ctx);
}

uint32_t ppc32_tls_get(const ppc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0U;
    }
    return ctx->gpr[PPC32_REG_TP];
}

void ppc32_reservation_invalidate(ppc32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->res_valid = 0;
    ctx->reservation_epoch++;
}

void ppc32_thread_switch_invalidate(ppc32_ctx_t *prev, ppc32_ctx_t *next)
{
    ppc32_reservation_invalidate(prev);
    ppc32_reservation_invalidate(next);
}

long ppc32_set_tid_address(ppc32_ctx_t *ctx, uint32_t tidptr_va)
{
    long tid;

    if (ctx == NULL) {
        return -EINVAL;
    }
    ctx->clear_child_tid = tidptr_va;
    if (ctx->host_tid > 0) {
        tid = (long)ctx->host_tid;
    } else {
        tid = host_gettid();
        ctx->host_tid = (int)tid;
    }
    return tid;
}

/* ---- futex ---- */

static long futex_host(int32_t *uaddr, int op, int32_t val,
    const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
#ifdef __linux__
    long r = syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);

    if (r < 0) {
        return -(long)errno;
    }
    return r;
#else
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout;
    (void)uaddr2;
    (void)val3;
    return -ENOSYS;
#endif
}

/* BE guest timespec -> host. Returns 0 or -EFAULT. */
static int futex_get_timeout(const ppc32_ctx_t *ctx, uint32_t va,
    struct timespec *out)
{
    uint32_t sec;
    uint32_t nsec;

    if (!thread_range_ok(ctx, va, 8U)) {
        return -EFAULT;
    }
    sec = thread_ld32be(ctx, va);
    nsec = thread_ld32be(ctx, va + 4U);
    if (nsec >= 1000000000U) {
        return -EINVAL;
    }
    out->tv_sec = (time_t)(int32_t)sec;
    out->tv_nsec = (long)nsec;
    return 0;
}

long ppc32_futex(ppc32_ctx_t *ctx, uint32_t uaddr, uint32_t op,
    uint32_t val, uint32_t timeout_va, uint32_t uaddr2, uint32_t val3)
{
    uint32_t cmd = op & PPC32_FUTEX_CMD_MASK;
    struct timespec ts;
    struct timespec *tsp = NULL;
    int32_t *up;
    int32_t *up2 = NULL;
    int host_op = (int)(op & (PPC32_FUTEX_PRIVATE_FLAG |
        PPC32_FUTEX_CLOCK_REALTIME | 15U));
    int get_rc;

    if (ctx == NULL) {
        return -EINVAL;
    }
    if (cmd != PPC32_FUTEX_WAIT && cmd != PPC32_FUTEX_WAKE &&
        cmd != PPC32_FUTEX_REQUEUE && cmd != PPC32_FUTEX_CMP_REQUEUE) {
        return -ENOSYS;
    }
    if (!thread_range_ok(ctx, uaddr, 4U)) {
        return -EFAULT;
    }
    if ((cmd == PPC32_FUTEX_REQUEUE || cmd == PPC32_FUTEX_CMP_REQUEUE) &&
        !thread_range_ok(ctx, uaddr2, 4U)) {
        return -EFAULT;
    }
    if (cmd == PPC32_FUTEX_WAIT && timeout_va != 0U) {
        get_rc = futex_get_timeout(ctx, timeout_va, &ts);
        if (get_rc != 0) {
            return (long)get_rc;
        }
        tsp = &ts;
    }
    up = (int32_t *)ppc32_guest_ptr(ctx, uaddr);
    if (cmd == PPC32_FUTEX_REQUEUE || cmd == PPC32_FUTEX_CMP_REQUEUE) {
        up2 = (int32_t *)ppc32_guest_ptr(ctx, uaddr2);
    }
    /* Guest memory is big-endian: the host futex compares raw
     * little-endian words, so numeric register comparands must be
     * byte-swapped to their in-memory image. Counts pass through. */
    if (cmd == PPC32_FUTEX_WAIT) {
        int32_t expect = (int32_t)ppc32_be32(val);

        return futex_host(up, host_op, expect, tsp, NULL, 0);
    }
    if (cmd == PPC32_FUTEX_WAKE) {
        return futex_host(up, host_op, (int32_t)val, NULL, NULL, 0);
    }
    if (cmd == PPC32_FUTEX_REQUEUE) {
        return futex_host(up, host_op, (int32_t)val, NULL, up2,
            (int32_t)val3);
    }
    return futex_host(up, host_op, (int32_t)val, NULL, up2,
        (int32_t)ppc32_be32(val3));
}

/* ---- clone ---- */

typedef struct {
    ppc32_thread_run_t run;
    void              *opaque;
    ppc32_ctx_t       *child;
} ppc32_thread_start_t;

/* Flags this lane implements directly. Namespaces, ptrace attach, and
 * non-VM process separation belong to other lanes (L4c) or take
 * -EINVAL. CLONE_VFORK without CLONE_THREAD runs concurrently (no
 * parent suspension); vfork+exec is L4c's path. */
#define PPC32_CLONE_SUPPORTED (PPC32_CLONE_VM | PPC32_CLONE_FS | \
    PPC32_CLONE_FILES | PPC32_CLONE_SIGHAND | PPC32_CLONE_THREAD | \
    PPC32_CLONE_VFORK | PPC32_CLONE_PARENT | PPC32_CLONE_SYSVSEM | \
    PPC32_CLONE_SETTLS | PPC32_CLONE_PARENT_SETTID | \
    PPC32_CLONE_CHILD_CLEARTID | PPC32_CLONE_UNTRACED | \
    PPC32_CLONE_CHILD_SETTID | PPC32_CLONE_CSIGNAL)

#define PPC32_CLONE_NEW_ANY (PPC32_CLONE_NEWCGROUP | PPC32_CLONE_NEWUTS | \
    PPC32_CLONE_NEWIPC | PPC32_CLONE_NEWUSER | PPC32_CLONE_NEWPID | \
    PPC32_CLONE_NEWNET | PPC32_CLONE_IO | PPC32_CLONE_PTRACE)

static void thread_copy_state(ppc32_ctx_t *dst, const ppc32_ctx_t *src)
{
    size_t n;

    /* Register file + machine state. */
    memcpy(dst->gpr, src->gpr, sizeof(dst->gpr));
    memcpy(dst->gpr_hi, src->gpr_hi, sizeof(dst->gpr_hi));
    dst->nip = src->nip;
    dst->lr = src->lr;
    dst->ctr = src->ctr;
    dst->cr = src->cr;
    dst->xer = src->xer;
    dst->fpscr = src->fpscr;
    dst->spefscr = src->spefscr;
    dst->acc = src->acc;
    memcpy(dst->fpr, src->fpr, sizeof(dst->fpr));
    dst->is_spe = src->is_spe;
    /* Shared-window VM snapshot (CLONE_VM: same 4 GiB window; region
     * bookkeeping is the shared table, copied while holding the table
     * lock so a concurrent D19 mapping change cannot tear it). */
    dst->guest_base = src->guest_base;
    dst->brk_base = src->brk_base;
    dst->brk_curr = src->brk_curr;
    dst->mmap_cursor = src->mmap_cursor;
    dst->interp_base = src->interp_base;
    dst->elf_base = src->elf_base;
    dst->elf_entry = src->elf_entry;
    dst->stack_top = src->stack_top;
    dst->stack_base = src->stack_base;
    dst->vdso_base = src->vdso_base;
    dst->has_host_info = src->has_host_info;
    dst->host_info = src->host_info;
    n = src->region_count <= PPC32_MAX_REGIONS ? src->region_count : 0U;
    dst->region_count = n;
    if (n > 0U) {
        memcpy(dst->regions, src->regions, n * sizeof(ppc32_region_t));
    }
    /* Process-wide identity/config shared by CLONE_THREAD. */
    dst->guest_pid = src->guest_pid;
    dst->guest_argc = src->guest_argc;
    dst->guest_argv = src->guest_argv;
    dst->host_envp = src->host_envp;
    dst->auxv_bytes = src->auxv_bytes;
    if (src->auxv_bytes <= sizeof(dst->auxv_data)) {
        memcpy(dst->auxv_data, src->auxv_data, src->auxv_bytes);
    }
    dst->sysroot = src->sysroot;
    dst->exec_path = src->exec_path;
    dst->cache_dir = src->cache_dir;
    dst->engine = src->engine;
    dst->profile = src->profile;
    dst->sig_mask = src->sig_mask;
    /* Fresh per-thread state: caches, counters, signals, robust. */
    dst->res_valid = 0;
    dst->reservation_epoch = src->reservation_epoch + 1U;
    dst->pending_signals = 0U;
    dst->clear_child_tid = 0U;
    dst->robust_list_head = 0U;
    dst->robust_list_len = 0U;
    dst->altstack_sp = 0U;
    dst->altstack_size = 0U;
    dst->altstack_flags = 0U;
    dst->host_tid = 0;
    dst->is_thread_clone = true;
    dst->sig_last_frame_va = 0U;
    dst->sig_last_frame_rt = 0U;
}

static void *thread_entry(void *arg)
{
    ppc32_thread_start_t *start = (ppc32_thread_start_t *)arg;
    ppc32_ctx_t *child;
    ppc32_thread_run_t run;
    void *opaque;

    if (start == NULL) {
        return NULL;
    }
    child = start->child;
    run = start->run;
    opaque = start->opaque;
    free(start);
    if (child == NULL) {
        return NULL;
    }
    /* Slot + host handle were stored by ppc32_clone before this ran,
     * so join is race-free; only the TID needs recording here. */
    child->host_tid = (int)host_gettid();
    if (run != NULL) {
        run(child, opaque);
    }
    ppc32_thread_exit(child);
    return NULL;
}

long ppc32_clone(ppc32_ctx_t *parent, uint32_t flags, uint32_t stack_va,
    uint32_t parent_tid_va, uint32_t tls_va, uint32_t child_tid_va,
    ppc32_thread_run_t run, void *opaque, ppc32_ctx_t **out_child)
{
    uint32_t child_tid;
    ppc32_ctx_t *child;
    ppc32_thread_slot_t *slot;
    ppc32_thread_start_t *start;
    int rc;

    if (parent == NULL) {
        return -EINVAL;
    }
    if ((flags & PPC32_CLONE_NEW_ANY) != 0U) {
        return -EINVAL;
    }
    if ((flags & ~PPC32_CLONE_SUPPORTED) != 0U) {
        return -EINVAL;
    }
    if ((flags & PPC32_CLONE_VM) == 0U) {
        return -ENOSYS;
    }
    if ((flags & PPC32_CLONE_THREAD) != 0U) {
        if ((flags & PPC32_CLONE_SIGHAND) == 0U) {
            return -EINVAL;
        }
        if ((flags & PPC32_CLONE_CSIGNAL) != 0U) {
            return -EINVAL;
        }
    }
    if ((flags & PPC32_CLONE_PARENT_SETTID) != 0U &&
        !thread_range_ok(parent, parent_tid_va, 4U)) {
        return -EFAULT;
    }
    if ((flags & PPC32_CLONE_CHILD_SETTID) != 0U &&
        !thread_range_ok(parent, child_tid_va, 4U)) {
        return -EFAULT;
    }
    if ((flags & PPC32_CLONE_CHILD_CLEARTID) != 0U &&
        !thread_range_ok(parent, child_tid_va, 4U)) {
        return -EFAULT;
    }
    child = (ppc32_ctx_t *)calloc(1, sizeof(ppc32_ctx_t));
    if (child == NULL) {
        return -ENOMEM;
    }
    child_tid = thread_alloc_tid();
    if (child_tid == 0U) {
        free(child);
        return -EAGAIN;
    }
    thread_lock();
    thread_copy_state(child, parent);
    slot = thread_claim_locked(child, child_tid);
    thread_unlock();
    if (slot == NULL) {
        free(child);
        return -EAGAIN;
    }
    child->guest_tid = child_tid;
    child->nip += 4U;
    child->gpr[3] = 0U;
    child->exit_reason = PPC32_EXIT_NONE;
    if (stack_va != 0U) {
        child->gpr[PPC32_REG_SP] = stack_va;
    }
    if ((flags & PPC32_CLONE_SETTLS) != 0U) {
        child->gpr[PPC32_REG_TP] = tls_va;
    }
    if ((flags & PPC32_CLONE_PARENT_SETTID) != 0U) {
        thread_st32be(parent, parent_tid_va, child_tid);
    }
    if ((flags & PPC32_CLONE_CHILD_SETTID) != 0U) {
        thread_st32be(child, child_tid_va, child_tid);
    }
    if ((flags & PPC32_CLONE_CHILD_CLEARTID) != 0U) {
        child->clear_child_tid = child_tid_va;
    }
    /* The reservation dies at clone birth on both sides (SPEC 2.2). */
    ppc32_reservation_invalidate(parent);
    ppc32_reservation_invalidate(child);
    if (out_child != NULL) {
        *out_child = child;
    }
    if (run == NULL) {
        return (long)(int32_t)child_tid;
    }
    start = (ppc32_thread_start_t *)malloc(sizeof(ppc32_thread_start_t));
    if (start == NULL) {
        thread_lock();
        slot->used = false;
        slot->ctx = NULL;
        thread_unlock();
        free(child);
        return -ENOMEM;
    }
    start->run = run;
    start->opaque = opaque;
    start->child = child;
    {
        pthread_t host = 0;

        rc = pthread_create(&host, NULL, thread_entry, start);
        if (rc != 0) {
            free(start);
            thread_lock();
            slot->used = false;
            slot->ctx = NULL;
            thread_unlock();
            free(child);
            return -EAGAIN;
        }
        /* Stored before the child can exit, so join is race-free. */
        thread_lock();
        {
            ppc32_thread_slot_t *again = thread_find_locked(child_tid);

            if (again != NULL) {
                again->host = host;
            }
        }
        thread_unlock();
    }
    return (long)(int32_t)child_tid;
}

long ppc32_thread_join(uint32_t guest_tid)
{
    pthread_t host = 0;
    bool found = false;

    thread_lock();
    {
        ppc32_thread_slot_t *slot = thread_find_locked(guest_tid);

        if (slot != NULL) {
            host = slot->host;
            found = true;
        }
    }
    thread_unlock();
    if (!found) {
        return -ESRCH;
    }
    if (host == 0) {
        return -EINVAL;
    }
    if (pthread_join(host, NULL) != 0) {
        return -ESRCH;
    }
    return 0;
}

void ppc32_thread_exit(ppc32_ctx_t *child)
{
    uint32_t clear_va;

    if (child == NULL) {
        return;
    }
    clear_va = child->clear_child_tid;
    child->clear_child_tid = 0U;
    if (clear_va != 0U && thread_range_ok(child, clear_va, 4U)) {
        int32_t *up = (int32_t *)ppc32_guest_ptr(child, clear_va);
        long woken;

        thread_st32be(child, clear_va, 0U);
        woken = futex_host(up, (int)PPC32_FUTEX_WAKE, 1, NULL, NULL, 0);
        (void)woken;
    }
    ppc32_reservation_invalidate(child);
    thread_lock();
    {
        ppc32_thread_slot_t *slot = thread_find_locked(child->guest_tid);

        if (slot != NULL) {
            slot->used = false;
            slot->ctx = NULL;
            memset(&slot->host, 0, sizeof(pthread_t));
        }
    }
    thread_unlock();
    free(child);
}

/* ---- self-test (acceptance: prints L4B-OK, exit 0) ----
 * Built only with -DPPC32RT_THREADS_TEST, so the normal binary (which
 * compiles every os source next to main.c) never sees a second main(). Runs
 * host-natively or under the aarch64 container; exercises TLS,
 * reservation invalidation, set_tid_address, clone validation and a
 * real CLONE_VM thread round-trip, plus futex WAIT/WAKE. */

#ifdef PPC32RT_THREADS_TEST

#include <stdio.h>

#define TEST_WIN_SIZE (16U * 1024U * 1024U)
#define TEST_UADDR 0x01000000U
#define TEST_TIMEOUT_VA 0x01000100U
#define TEST_PARENT_TID_VA 0x01000200U
#define TEST_CHILD_TID_VA 0x01000300U
#define TEST_TLS_VA 0x02000000U
#define TEST_STACK_VA 0x03000000U

static volatile int g_test_child_ran = 0;

static void test_child_run(ppc32_ctx_t *child, void *opaque)
{
    (void)opaque;
    if (child != NULL && child->gpr[PPC32_REG_TP] == TEST_TLS_VA) {
        g_test_child_ran = 1;
    }
}

static int test_fail(const char *what, long got, long want)
{
    printf("L4B-FAIL %s: got %ld want %ld\n", what, got, want);
    return 1;
}

int main(void)
{
    ppc32_ctx_t parent;
    ppc32_ctx_t *child = NULL;
    void *win;
    uint32_t flags;
    uint32_t child_tid = 0U;
    long rc;
    long tid;

    /* Plain heap window: alignment suits BE word memcpy access and the
     * host futex operates on it like on any shared mapping. */
    win = malloc(TEST_WIN_SIZE);
    if (win == NULL) {
        printf("L4B-FAIL malloc\n");
        return 1;
    }
    memset(win, 0, TEST_WIN_SIZE);
    memset(&parent, 0, sizeof(parent));
    parent.guest_base = (uint64_t)(uintptr_t)win;
    parent.nip = 0x00100000U;
    parent.gpr[PPC32_REG_SP] = 0x00F00000U;
    parent.res_valid = 1;
    parent.reservation_epoch = 41U;

    /* Main-thread registration. */
    rc = ppc32_thread_init_main(&parent);
    if (rc != 0) {
        return test_fail("init_main", rc, 0);
    }
    if (ppc32_thread_count() != 1U) {
        return test_fail("count-after-init", (long)ppc32_thread_count(), 1);
    }

    /* TLS plumbing: r2 is the PPC32 thread pointer. */
    ppc32_tls_set(&parent, TEST_TLS_VA);
    if (ppc32_tls_get(&parent) != TEST_TLS_VA) {
        return test_fail("tls", (long)ppc32_tls_get(&parent),
            (long)TEST_TLS_VA);
    }

    /* Reservation invalidation bumps the epoch and clears valid.
     * Epoch so far: 41 + init_main + tls_set = 43, this call -> 44. */
    parent.res_valid = 1;
    ppc32_reservation_invalidate(&parent);
    if (parent.res_valid != 0U || parent.reservation_epoch != 44U) {
        return test_fail("res-invalidate", (long)parent.reservation_epoch,
            44);
    }

    /* set_tid_address records the address, returns the TID. */
    tid = ppc32_set_tid_address(&parent, TEST_PARENT_TID_VA);
    if (tid <= 0 || parent.clear_child_tid != TEST_PARENT_TID_VA) {
        return test_fail("set-tid-address", tid, 1);
    }

    /* Clone validation: no VM -> L4c process path; THREAD without
     * SIGHAND is EINVAL per Linux; bad tid address is EFAULT. */
    rc = ppc32_clone(&parent, PPC32_CLONE_FS, 0U, 0U, 0U, 0U, NULL,
        NULL, NULL);
    if (rc != -ENOSYS) {
        return test_fail("clone-no-vm", rc, -ENOSYS);
    }
    rc = ppc32_clone(&parent,
        PPC32_CLONE_VM | PPC32_CLONE_THREAD, 0U, 0U, 0U, 0U, NULL,
        NULL, NULL);
    if (rc != -EINVAL) {
        return test_fail("clone-thread-no-sighand", rc, -EINVAL);
    }
    rc = ppc32_clone(&parent,
        PPC32_CLONE_VM | PPC32_CLONE_THREAD | PPC32_CLONE_SIGHAND |
        PPC32_CLONE_PARENT_SETTID, 0U, 0xFFFFFFFFU, 0U, 0U, NULL,
        NULL, NULL);
    if (rc != -EFAULT) {
        return test_fail("clone-bad-tidaddr", rc, -EFAULT);
    }

    /* Real CLONE_VM thread round-trip. */
    flags = PPC32_CLONE_VM | PPC32_CLONE_FS | PPC32_CLONE_FILES |
        PPC32_CLONE_SIGHAND | PPC32_CLONE_THREAD | PPC32_CLONE_SETTLS |
        PPC32_CLONE_PARENT_SETTID | PPC32_CLONE_CHILD_CLEARTID |
        PPC32_CLONE_CHILD_SETTID;
    parent.res_valid = 1;
    rc = ppc32_clone(&parent, flags, TEST_STACK_VA, TEST_PARENT_TID_VA,
        TEST_TLS_VA, TEST_CHILD_TID_VA, test_child_run, NULL, &child);
    if (rc <= 0 || child == NULL) {
        return test_fail("clone-ok", rc, 1);
    }
    child_tid = (uint32_t)rc;
    if (child->gpr[PPC32_REG_SP] != TEST_STACK_VA) {
        return test_fail("clone-stack", (long)child->gpr[PPC32_REG_SP],
            (long)TEST_STACK_VA);
    }
    if (child->gpr[PPC32_REG_TP] != TEST_TLS_VA) {
        return test_fail("clone-tls", (long)child->gpr[PPC32_REG_TP],
            (long)TEST_TLS_VA);
    }
    if (child->gpr[3] != 0U || child->nip != parent.nip + 4U) {
        return test_fail("clone-child-ret", (long)child->gpr[3], 0);
    }
    if (parent.res_valid != 0U) {
        return test_fail("clone-parent-res", (long)parent.res_valid, 0);
    }
    if (thread_ld32be(&parent, TEST_PARENT_TID_VA) != (uint32_t)rc) {
        return test_fail("clone-parent-tid", 0, rc);
    }
    if (thread_ld32be(&parent, TEST_CHILD_TID_VA) != (uint32_t)rc) {
        return test_fail("clone-child-tid", 0, rc);
    }
    if (ppc32_thread_count() != 2U) {
        return test_fail("count-after-clone", (long)ppc32_thread_count(),
            2);
    }
    /* The first clone after init gets exactly main_tid + 1, which must
     * also equal the TID returned by clone. */
    if (child_tid != (uint32_t)tid + 1U) {
        return test_fail("clone-tid-seq", (long)child_tid,
            (long)((uint32_t)tid + 1U));
    }
    rc = ppc32_thread_join(child_tid);
    if (rc != 0) {
        return test_fail("join", rc, 0);
    }
    if (g_test_child_ran != 1) {
        return test_fail("child-ran", (long)g_test_child_ran, 1);
    }
    /* Child exit cleared the CLEARTID word. */
    if (thread_ld32be(&parent, TEST_CHILD_TID_VA) != 0U) {
        return test_fail("cleartid", 0, 0);
    }
    if (ppc32_thread_count() != 1U) {
        return test_fail("count-after-join", (long)ppc32_thread_count(),
            1);
    }

    /* Futex: matching WAIT times out, mismatched WAIT is immediate,
     * WAKE with no waiters returns 0. */
    thread_st32be(&parent, TEST_UADDR, 5U);
    thread_st32be(&parent, TEST_TIMEOUT_VA, 0U);
    thread_st32be(&parent, TEST_TIMEOUT_VA + 4U, 50000000U);
    rc = ppc32_futex(&parent, TEST_UADDR, PPC32_FUTEX_WAIT, 5U,
        TEST_TIMEOUT_VA, 0U, 0U);
    if (rc != -ETIMEDOUT) {
        return test_fail("futex-wait-timeout", rc, -ETIMEDOUT);
    }
    rc = ppc32_futex(&parent, TEST_UADDR, PPC32_FUTEX_WAIT, 6U, 0U, 0U,
        0U);
    if (rc != -EAGAIN) {
        return test_fail("futex-wait-mismatch", rc, -EAGAIN);
    }
    rc = ppc32_futex(&parent, TEST_UADDR,
        PPC32_FUTEX_WAKE | PPC32_FUTEX_PRIVATE_FLAG, 1U, 0U, 0U, 0U);
    if (rc != 0) {
        return test_fail("futex-wake", rc, 0);
    }
    rc = ppc32_futex(&parent, 0xFFFFFFFFU, PPC32_FUTEX_WAKE, 1U, 0U, 0U,
        0U);
    if (rc != -EFAULT) {
        return test_fail("futex-bad-addr", rc, -EFAULT);
    }
    rc = ppc32_futex(&parent, TEST_UADDR, 6U, 0U, 0U, 0U, 0U);
    if (rc != -ENOSYS) {
        return test_fail("futex-bad-op", rc, -ENOSYS);
    }

    /* Thread-switch invalidation clears both sides. */
    {
        ppc32_ctx_t other;

        memset(&other, 0, sizeof(other));
        parent.res_valid = 1;
        other.res_valid = 1;
        ppc32_thread_switch_invalidate(&parent, &other);
        if (parent.res_valid != 0U || other.res_valid != 0U) {
            return test_fail("switch-invalidate", 0, 0);
        }
    }

    free(win);
    printf("L4B-OK\n");
    return 0;
}

#endif /* PPC32RT_THREADS_TEST */
