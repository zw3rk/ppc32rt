/*
 * src/interp/llsc.c — LL/SC reservation table (lwarx/stwcx., Wave U3 section 4.4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from interp.c (file-size discipline): the shared 64-byte-line
 * reservation table, its spinlock, and the fork coordination around it.
 * Ordinary stores invalidate reservations through
 * vm32_store_invalidate_range (every spanned 64-byte bucket, so a wide
 * store cannot leave a middle-bucket reservation live); successful
 * stwcx. additionally fans staged shared-file bytes out through the
 * file-backing coherence hook after releasing the table lock (lock
 * order: LL before VM never nests, matching the fork VM->TLB->inode->LL
 * order, so the fan-out runs unlocked).
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"
#include "vm/vm32.h"

/* lwarx/stwcx. lines (Wave U3 section 4.4): SEQ_CST epoch + owner/addr/val
 * snapshot (vm/vm32.h). */
typedef struct {
    uint64_t epoch;
    const ppc32_ctx_t *owner;
    uint32_t addr;
    uint32_t val;
} ppc32_ll_line_t;

static ppc32_ll_line_t g_ll_table[1024];
static _Atomic uint32_t g_ll_lock = 0U;
static _Thread_local int g_ll_lock_held = 0;

static void ll_lock_acquire(void)
{
    ppc32_spin_lock(&g_ll_lock);
    g_ll_lock_held = 1;
}

static void ll_lock_release(void)
{
    g_ll_lock_held = 0;
    ppc32_spin_unlock(&g_ll_lock);
}

void vm32_ll_unlock_if_held_by_self(void)
{
    if (g_ll_lock_held != 0) {
        g_ll_lock_held = 0;
        ppc32_spin_unlock(&g_ll_lock);
    }
}

/* Fork coordination (P32-R3-4): hold the reservation lock across the
 * snapshot in the parent; the child drops the inherited locked value
 * and clears the copied thread-local held flag. */
void vm32_ll_fork_prepare(void)
{
    ll_lock_acquire();
}

void vm32_ll_fork_parent(void)
{
    ll_lock_release();
}

void vm32_ll_fork_child(void)
{
    g_ll_lock_held = 0;
    atomic_store_explicit(&g_ll_lock, 0U, memory_order_release);
}

/* Shared mapping generation (RC-U3-r2 #1): guest-mm teardowns bump it
 * via vm32_ll_note_remap, so a pre-teardown reservation can never
 * succeed after it (line epochs alone cannot see a remap). */
static uint64_t g_ll_generation;
void vm32_ll_note_remap(void) { __atomic_fetch_add(&g_ll_generation, 1ULL, __ATOMIC_SEQ_CST); }

void vm32_ll_record(ppc32_ctx_t *ctx, uint32_t gva_aligned, uint32_t val)
{
    uint32_t al = gva_aligned & ~3U;
    uint32_t h = (al >> 6U) & 1023U;

    ll_lock_acquire();
    ctx->res_addr = al;
    ctx->res_val = val;
    ctx->res_valid = 1;
    ctx->res_snap = __atomic_load_n(&g_ll_table[h].epoch, __ATOMIC_SEQ_CST);
    ctx->res_gensnap = __atomic_load_n(&g_ll_generation, __ATOMIC_SEQ_CST);
    g_ll_table[h].owner = ctx;
    g_ll_table[h].addr = al;
    g_ll_table[h].val = val;
    ll_lock_release();
}

/* STWCX. as one SEQ_CST compare-exchange (vm/vm32.h): shared mapping
 * generation + reservation_valid/addr gate the store; consumed either way. */
bool vm32_sc_attempt(ppc32_ctx_t *ctx, uint32_t gva_aligned, uint32_t val)
{
    uint32_t al = gva_aligned & ~3U;
    uint32_t h = (al >> 6U) & 1023U;
    uint32_t *hva = (uint32_t *)ppc32_guest_ptr(ctx, al);
    uint32_t exp = ppc32_be32(ctx->res_val);
    uint32_t des = ppc32_be32(val);
    bool pre_ok;
    bool ok = false;

    ll_lock_acquire();
    pre_ok = ctx->res_valid != 0U && ctx->res_addr == al && g_ll_table[h].owner == ctx &&
        g_ll_table[h].addr == al && g_ll_table[h].val == ctx->res_val &&
        __atomic_load_n(&g_ll_table[h].epoch, __ATOMIC_SEQ_CST) == ctx->res_snap &&
        __atomic_load_n(&g_ll_generation, __ATOMIC_SEQ_CST) == ctx->res_gensnap;
    ctx->res_valid = 0;
    if (g_ll_table[h].owner == ctx) {
        g_ll_table[h].owner = NULL;
    }
    ctx->reservation_epoch++;
    if (pre_ok) {
        ok = __atomic_compare_exchange_n(hva, &exp, des, false,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        if (ok) {
            __atomic_fetch_add(&g_ll_table[h].epoch, 1ULL, __ATOMIC_SEQ_CST);
        }
    }
    ll_lock_release();
    if (ok) {
        /* A successful store is visible guest memory: fan it out to
         * overlapping staged shared-file aliases (same bytes the
         * ordinary store path propagates). Runs without the table
         * lock so the VM-side fan-out cannot invert lock order. */
        vm_file_shared_cohere_store(ctx, al, 4U);
    }
    return ok;
}

/* Store hook: bump the line epoch so a peer stwcx. on the line fails. */
void vm32_reservation_bump(uint32_t gva_aligned)
{
    __atomic_fetch_add(&g_ll_table[((gva_aligned & ~3U) >> 6U) & 1023U].epoch, 1ULL,
        __ATOMIC_SEQ_CST);
}

/* Invalidate every 64-byte LL/SC bucket spanned by [ea, ea + len): a
 * wide store must kill middle-bucket reservations too, not just the
 * first and last lines. 32-bit EA wrap is honored by unsigned
 * arithmetic. Runs without the table lock (fetch_add is atomic). */
void vm32_store_invalidate_range(uint32_t ea, uint32_t len)
{
    uint64_t end;
    uint32_t first;
    uint32_t last;
    uint32_t line;

    if (len == 0U) {
        return;
    }
    end = (uint64_t)ea + (uint64_t)len;
    if (end > 0x100000000ULL) {
        end = 0x100000000ULL;
    }
    first = (ea & ~3U) >> 6U;
    last = (uint32_t)(((end - 1ULL) & ~3ULL) >> 6U);
    line = first;
    for (;;) {
        __atomic_fetch_add(&g_ll_table[line & 1023U].epoch, 1ULL,
            __ATOMIC_SEQ_CST);
        if (line == last) {
            break;
        }
        line++;
    }
}
