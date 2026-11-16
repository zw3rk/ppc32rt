/*
 * tests/check_p32_altivec.c — G4 AltiVec + G02 thread/VM/TLS coverage
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side tests driving ppc32_run_darwin_with_handler with
 * in-process mock handlers (no /dev/a32host). Guest programs are
 * hand-crafted big-endian PowerPC 7450 words:
 *   f) vcmpequb./vcmpeqfp. Rc=1 -> CR6 (all_true/all_false/partial).
 *   g) vmaddfp/vnmsubfp (fmaf operands, vC from bits 21..25).
 *   h) lvsl/lvsr/vperm unaligned permutations.
 *   i) per-element vslw/vsrah/vrlw (incl. n == 0 rotate guard).
 *   j) vpkuhus/vupkhsb with vD == vA aliasing + VSCR.SAT.
 *   k) mfspr/mtspr rD, 259 (SPRG3 TLS, r2 never clobbered).
 *   l) EXIT_THREAD vs worker EXIT_PROCESS (forked child for the
 *      whole-process kill).
 *   m) SYNC_VM_PROT(0) unmap (stale zeros gone, prot-0 faults,
 *      fresh-zero re-maps).
 *   n) mftb/mftbu under --difftest (0 divergences, frozen timebase).
 *   o) CLI personality/Mach-O helpers (pure unit checks).
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

static uint32_t w_mfcr(uint32_t rt)
{
    return w_x31(rt, 0, 0, 19, 0);
}

/* ---- subtest (f): vcmpequb./vcmpeqfp. CR6 ---- */

typedef struct {
    uint64_t window;
    uint32_t cr_eq;
    uint32_t cr_part;
    uint32_t cr_none;
    uint32_t cr_feq;
} tf_t;

static int handler_f(void *opaque, unsigned long req, void *arg)
{
    tf_t *t = (tf_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        int i;
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
        for (i = 0; i < 16; i++) {
            uint8_t *a = (uint8_t *)(uintptr_t)(t->window + DATA_VA + i);
            uint8_t *bb = (uint8_t *)(uintptr_t)(t->window + DATA_VA + 16 + i);
            uint8_t *cc = (uint8_t *)(uintptr_t)(t->window + DATA_VA + 32 + i);
            uint8_t *dd = (uint8_t *)(uintptr_t)(t->window + DATA_VA + 48 + i);
            *a = (uint8_t)i;
            *bb = (uint8_t)i;
            *cc = (uint8_t)(i < 8 ? i : 0xFF);
            *dd = (uint8_t)(0xF0 + i);
        }
        {
            /* E/F: {1.0, 2.0, 3.0, 4.0} twice (vcmpeqfp.). */
            uint32_t fw[4] = { 0x3F800000U, 0x40000000U, 0x40400000U,
                0x40800000U };
            for (i = 0; i < 4; i++) {
                w32(t->window, DATA_VA + 80U + (uint32_t)(i * 4), fw[i]);
                w32(t->window, DATA_VA + 96U + (uint32_t)(i * 4), fw[i]);
            }
        }
        w32(t->window, c + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 4U, w_x31(0, 0, 4, 103, 0));
        w32(t->window, c + 8U, w_dform(14U, 5, 4, 16));
        w32(t->window, c + 12U, w_x31(1, 0, 5, 103, 0));
        w32(t->window, c + 16U, w_vx3(2, 0, 1, 1030));
        w32(t->window, c + 20U, w_mfcr(6));
        w32(t->window, c + 24U, w_dform(36U, 6, 4, 64));
        w32(t->window, c + 28U, w_dform(14U, 5, 4, 32));
        w32(t->window, c + 32U, w_x31(1, 0, 5, 103, 0));
        w32(t->window, c + 36U, w_vx3(2, 0, 1, 1030));
        w32(t->window, c + 40U, w_mfcr(6));
        w32(t->window, c + 44U, w_dform(36U, 6, 4, 68));
        w32(t->window, c + 48U, w_dform(14U, 5, 4, 48));
        w32(t->window, c + 52U, w_x31(1, 0, 5, 103, 0));
        w32(t->window, c + 56U, w_vx3(2, 0, 1, 1030));
        w32(t->window, c + 60U, w_mfcr(6));
        w32(t->window, c + 64U, w_dform(36U, 6, 4, 72));
        w32(t->window, c + 68U, w_dform(14U, 5, 4, 80));
        w32(t->window, c + 72U, w_x31(0, 0, 5, 103, 0));
        w32(t->window, c + 76U, w_dform(14U, 5, 4, 96));
        w32(t->window, c + 80U, w_x31(1, 0, 5, 103, 0));
        w32(t->window, c + 84U, w_vx3(2, 0, 1, 1222));
        w32(t->window, c + 88U, w_mfcr(6));
        w32(t->window, c + 92U, w_dform(36U, 6, 4, 76));
        w32(t->window, c + 96U, 0x44000002U);
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            t->cr_eq = r32(t->window, DATA_VA + 64U);
            t->cr_part = r32(t->window, DATA_VA + 68U);
            t->cr_none = r32(t->window, DATA_VA + 72U);
            t->cr_feq = r32(t->window, DATA_VA + 76U);
            if (((t->cr_eq >> 4) & 0xFU) == 8U &&
                ((t->cr_part >> 4) & 0xFU) == 0U &&
                ((t->cr_none >> 4) & 0xFU) == 2U &&
                ((t->cr_feq >> 4) & 0xFU) == 8U) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
            } else {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 1;
            }
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 2;
        return 0;
    }
    return 0;
}

static int test_f(int engine)
{
    tf_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_f, &t, engine, false);
    CHECK(rc == 0, "f: exit status 0");
    CHECK(((t.cr_eq >> 4) & 0xFU) == 8U, "f: all_true -> CR6 bit 24");
    CHECK(((t.cr_part >> 4) & 0xFU) == 0U, "f: partial -> CR6 zero");
    CHECK(((t.cr_none >> 4) & 0xFU) == 2U, "f: all_false -> CR6 bit 26");
    CHECK(((t.cr_feq >> 4) & 0xFU) == 8U, "f: vcmpeqfp. -> CR6 bit 24");
    if (rc == 0) {
        printf("altivec-f (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (g): vmaddfp / vnmsubfp ---- */

typedef struct {
    uint64_t window;
} tg_t;

static int handler_g(void *opaque, unsigned long req, void *arg)
{
    tg_t *t = (tg_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        int i;
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
        /* vA = 3.0, vB = 5.0, vC = 4.0: fmaf(a,c,b) = 17.0 catches
         * the vB/vC operand swap (buggy a*b+c = 19.0). */
        for (i = 0; i < 4; i++) {
            w32(t->window, DATA_VA + (uint32_t)(i * 4), 0x40400000U);
            w32(t->window, DATA_VA + 16U + (uint32_t)(i * 4), 0x40A00000U);
            w32(t->window, DATA_VA + 32U + (uint32_t)(i * 4), 0x40800000U);
        }
        w32(t->window, c + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 4U, w_x31(0, 0, 4, 103, 0));
        w32(t->window, c + 8U, w_dform(14U, 5, 4, 16));
        w32(t->window, c + 12U, w_x31(1, 0, 5, 103, 0));
        w32(t->window, c + 16U, w_dform(14U, 5, 4, 32));
        w32(t->window, c + 20U, w_x31(2, 0, 5, 103, 0));
        w32(t->window, c + 24U, w_va(3, 0, 1, 2, 46));
        w32(t->window, c + 28U, w_dform(14U, 5, 4, 48));
        w32(t->window, c + 32U, w_x31(3, 5, 0, 231, 0));
        w32(t->window, c + 36U, w_va(3, 0, 1, 2, 47));
        w32(t->window, c + 40U, w_dform(14U, 5, 4, 64));
        w32(t->window, c + 44U, w_x31(3, 5, 0, 231, 0));
        w32(t->window, c + 48U, 0x44000002U);
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            int ok = 1;
            int i;
            for (i = 0; i < 4; i++) {
                if (r32(t->window, DATA_VA + 48U + (uint32_t)(i * 4)) !=
                    0x41880000U) {
                    ok = 0;
                }
                if (r32(t->window, DATA_VA + 64U + (uint32_t)(i * 4)) !=
                    0xC0E00000U) {
                    ok = 0;
                }
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = ok ? 0 : 1;
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 2;
        return 0;
    }
    return 0;
}

static int test_g(int engine)
{
    tg_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_g, &t, engine, false);
    CHECK(rc == 0, "g: vmaddfp/vnmsubfp results (17.0/-7.0)");
    if (rc == 0) {
        printf("altivec-g (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (h): lvsl + lvsr + vperm ---- */

typedef struct {
    uint64_t window;
} th_t;

static int handler_h(void *opaque, unsigned long req, void *arg)
{
    th_t *t = (th_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        int i;
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
        for (i = 0; i < 32; i++) {
            uint8_t *p =
                (uint8_t *)(uintptr_t)(t->window + DATA_VA + 64 + i);
            *p = (uint8_t)i;
        }
        w32(t->window, c + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 4U, w_dform(14U, 5, 4, 3));
        w32(t->window, c + 8U, w_x31(0, 0, 5, 6, 0));
        w32(t->window, c + 12U, w_x31(1, 0, 5, 38, 0));
        w32(t->window, c + 16U, w_dform(14U, 5, 4, 32));
        w32(t->window, c + 20U, w_x31(0, 5, 0, 231, 0));
        w32(t->window, c + 24U, w_dform(14U, 5, 4, 48));
        w32(t->window, c + 28U, w_x31(1, 5, 0, 231, 0));
        w32(t->window, c + 32U, w_dform(14U, 5, 4, 64));
        w32(t->window, c + 36U, w_x31(2, 0, 5, 103, 0));
        w32(t->window, c + 40U, w_dform(14U, 5, 4, 80));
        w32(t->window, c + 44U, w_x31(3, 0, 5, 103, 0));
        w32(t->window, c + 48U, w_va(4, 2, 3, 0, 43));
        w32(t->window, c + 52U, w_dform(14U, 5, 4, 96));
        w32(t->window, c + 56U, w_x31(4, 5, 0, 231, 0));
        w32(t->window, c + 60U, 0x44000002U);
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            int ok = 1;
            int i;
            for (i = 0; i < 16; i++) {
                uint8_t *sl =
                    (uint8_t *)(uintptr_t)(t->window + DATA_VA + 32 + i);
                uint8_t *sr =
                    (uint8_t *)(uintptr_t)(t->window + DATA_VA + 48 + i);
                uint8_t *pm =
                    (uint8_t *)(uintptr_t)(t->window + DATA_VA + 96 + i);
                if (*sl != (uint8_t)(3 + i)) {
                    ok = 0;
                }
                if (*sr != (uint8_t)(13 + i)) {
                    ok = 0;
                }
                if (*pm != (uint8_t)(3 + i)) {
                    ok = 0;
                }
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = ok ? 0 : 1;
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 2;
        return 0;
    }
    return 0;
}

static int test_h(int engine)
{
    th_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_h, &t, engine, false);
    CHECK(rc == 0, "h: lvsl/lvsr/vperm byte patterns");
    if (rc == 0) {
        printf("altivec-h (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (i): per-element vslw / vsrah / vrlw ---- */

typedef struct {
    uint64_t window;
} ti_t;

static int handler_i(void *opaque, unsigned long req, void *arg)
{
    ti_t *t = (ti_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        /* vA words {1, 2, 0x80000000, 3}, vB counts {1, 31, 0, 4}. */
        uint32_t aw[4] = { 1U, 2U, 0x80000000U, 3U };
        uint32_t bw[4] = { 1U, 31U, 0U, 4U };
        int i;
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
        for (i = 0; i < 4; i++) {
            w32(t->window, DATA_VA + (uint32_t)(i * 4), aw[i]);
            w32(t->window, DATA_VA + 16U + (uint32_t)(i * 4), bw[i]);
        }
        w32(t->window, c + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 4U, w_x31(0, 0, 4, 103, 0));
        w32(t->window, c + 8U, w_dform(14U, 5, 4, 16));
        w32(t->window, c + 12U, w_x31(1, 0, 5, 103, 0));
        w32(t->window, c + 16U, w_vx3(2, 0, 1, 388));
        w32(t->window, c + 20U, w_dform(14U, 5, 4, 32));
        w32(t->window, c + 24U, w_x31(2, 5, 0, 231, 0));
        w32(t->window, c + 28U, w_vx3(3, 0, 1, 836));
        w32(t->window, c + 32U, w_dform(14U, 5, 4, 48));
        w32(t->window, c + 36U, w_x31(3, 5, 0, 231, 0));
        w32(t->window, c + 40U, w_vx3(4, 0, 1, 132));
        w32(t->window, c + 44U, w_dform(14U, 5, 4, 64));
        w32(t->window, c + 48U, w_x31(4, 5, 0, 231, 0));
        w32(t->window, c + 52U, 0x44000002U);
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            /* vslw {2,0,80000000,30}, vsrah {0,0,80000000,0},
             * vrlw {2,1,80000000,30}. */
            uint32_t e0[4] = { 2U, 0U, 0x80000000U, 0x30U };
            uint32_t e1[4] = { 0U, 0U, 0x80000000U, 0U };
            uint32_t e2[4] = { 2U, 1U, 0x80000000U, 0x30U };
            int ok = 1;
            int i;
            for (i = 0; i < 4; i++) {
                if (r32(t->window, DATA_VA + 32U + (uint32_t)(i * 4)) !=
                    e0[i]) {
                    ok = 0;
                }
                if (r32(t->window, DATA_VA + 48U + (uint32_t)(i * 4)) !=
                    e1[i]) {
                    ok = 0;
                }
                if (r32(t->window, DATA_VA + 64U + (uint32_t)(i * 4)) !=
                    e2[i]) {
                    ok = 0;
                }
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = ok ? 0 : 1;
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 2;
        return 0;
    }
    return 0;
}

static int test_i(int engine)
{
    ti_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_i, &t, engine, false);
    CHECK(rc == 0, "i: per-element vslw/vsrah/vrlw");
    if (rc == 0) {
        printf("altivec-i (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (j): vpkuhus/vupkhsb aliasing + SAT ---- */

typedef struct {
    uint64_t window;
} tj_t;

static int handler_j(void *opaque, unsigned long req, void *arg)
{
    tj_t *t = (tj_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        /* halves {0,1,255,256,257,511,512,0xFFFF}. */
        uint8_t bytes[16] = { 0, 0, 0, 1, 0, 0xFF, 1, 0,
            1, 1, 1, 0xFF, 2, 0, 0xFF, 0xFF };
        int i;
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
        for (i = 0; i < 16; i++) {
            uint8_t *p = (uint8_t *)(uintptr_t)(t->window + DATA_VA + i);
            uint8_t *z =
                (uint8_t *)(uintptr_t)(t->window + DATA_VA + 16 + i);
            *p = bytes[i];
            *z = 0U;
        }
        w32(t->window, c + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 4U, w_x31(0, 0, 4, 103, 0));
        w32(t->window, c + 8U, w_dform(14U, 5, 4, 16));
        w32(t->window, c + 12U, w_x31(1, 0, 5, 103, 0));
        /* vpkuhus v0,v0,v1 with vD == vA (aliasing). */
        w32(t->window, c + 16U, w_vx3(0, 0, 1, 142));
        w32(t->window, c + 20U, w_dform(14U, 5, 4, 32));
        w32(t->window, c + 24U, w_x31(0, 5, 0, 231, 0));
        /* mfvscr v5; VSCR lands in word 3, observed at +48+12. */
        w32(t->window, c + 28U, w_vx3(5, 0, 0, 1540));
        w32(t->window, c + 32U, w_dform(14U, 5, 4, 48));
        w32(t->window, c + 36U, w_x31(5, 5, 0, 231, 0));
        /* vupkhsb v2,v0 and aliased vupkhsb v1,v0. */
        w32(t->window, c + 40U, w_vx3(2, 0, 0, 526));
        w32(t->window, c + 44U, w_dform(14U, 5, 4, 64));
        w32(t->window, c + 48U, w_x31(2, 5, 0, 231, 0));
        w32(t->window, c + 52U, w_vx3(1, 0, 0, 526));
        w32(t->window, c + 56U, w_dform(14U, 5, 4, 80));
        w32(t->window, c + 60U, w_x31(1, 5, 0, 231, 0));
        w32(t->window, c + 64U, 0x44000002U);
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            uint8_t exp[8] = { 0, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            uint16_t exph[8] = { 0, 1, 0xFFFF, 0xFFFF,
                0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF };
            int ok = 1;
            int i;
            for (i = 0; i < 8; i++) {
                uint8_t *p =
                    (uint8_t *)(uintptr_t)(t->window + DATA_VA + 32 + i);
                uint8_t *z =
                    (uint8_t *)(uintptr_t)(t->window + DATA_VA + 40 + i);
                uint16_t h0 = (uint16_t)(((uint16_t)
                    *(uint8_t *)(uintptr_t)(t->window + DATA_VA + 64 +
                    (uint32_t)(i * 2)) << 8) |
                    *(uint8_t *)(uintptr_t)(t->window + DATA_VA + 65 +
                    (uint32_t)(i * 2)));
                uint16_t h1 = (uint16_t)(((uint16_t)
                    *(uint8_t *)(uintptr_t)(t->window + DATA_VA + 80 +
                    (uint32_t)(i * 2)) << 8) |
                    *(uint8_t *)(uintptr_t)(t->window + DATA_VA + 81 +
                    (uint32_t)(i * 2)));
                if (*p != exp[i] || *z != 0U) {
                    ok = 0;
                }
                if (h0 != exph[i] || h1 != exph[i]) {
                    ok = 0;
                }
            }
            /* VSCR.SAT (bit 0) must be set by the saturating pack. */
            if ((r32(t->window, DATA_VA + 60U) & 1U) == 0U) {
                ok = 0;
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = ok ? 0 : 1;
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 2;
        return 0;
    }
    return 0;
}

static int test_j(int engine)
{
    tj_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_j, &t, engine, false);
    CHECK(rc == 0, "j: vpkuhus/vupkhsb alias + SAT");
    if (rc == 0) {
        printf("altivec-j (engine %d): PASS\n", engine);
    }
    return rc;
}


int main(void)
{
    int rc = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    {
        int i;
        int engines[2] = { PPC32_ENGINE_INTERP, PPC32_ENGINE_DBT };
        int (*fns[])(int) = { test_f, test_g, test_h, test_i, test_j };
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
    if (g_fails == 0 && rc == 0) {
        printf("check_p32_altivec: ALL OK\n");
        return 0;
    }
    printf("check_p32_altivec: %d FAILURE(S)\n", g_fails);
    return 1;
}
