/*
 * tests/check_p32_darwin_g02.c — G02 Darwin host-bridge lifecycle tests
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-side tests driving ppc32_run_darwin_with_handler with an
 * in-process mock a32h_darwin_handler_fn (no /dev/a32host, no HVF).
 * Guest programs are hand-crafted big-endian PowerPC 7450 words
 * running inside the 4 GiB window:
 *   a) VRSAVE + AltiVec + dcbz + icbi SMC patch with FLUSH_ICACHE.
 *   b) sc BSD success (pc+8) vs BSD error (pc+4) vs Mach negative-r0.
 *   c) Precise FAULT (unmapped vs RO) + SYNC_VM_PROT + DELIVER_SIGNAL.
 *   d) SPAWN_THREAD + lwarx/stwcx. across 2 workers (interp).
 *   e) Lockstep --difftest (interp vs dbt, 0 divergences) + AOT keys.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "a32host.h"
#include "dbt/aot/aot.h"
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

/* ---- subtest (a): VRSAVE + AltiVec + dcbz + icbi SMC ---- */

typedef struct {
    uint64_t window;
    int sc_count;
    int saw_vrsave_ok;
    int saw_vec_ok;
    int saw_dcbz_ok;
    int saw_patch_ok;
} ta_t;

static int handler_a(void *opaque, unsigned long req, void *arg)
{
    ta_t *t = (ta_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        uint32_t stub = 0x100800U;
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
        b->entry_r0 = 0x00FF00FFU;
        b->entry_cpsr_or_msr = 0U;
        b->commpage_va = 0xFFFF8000U;
        b->commpage_size = 0U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        b->initial_tid = 1U;
        for (i = 0; i < 16; i++) {
            uint8_t *p =
                (uint8_t *)(uintptr_t)(t->window + DATA_VA + (uint32_t)i);
            *p = (uint8_t)i;
        }
        w32(t->window, c + 0U, w_mtspr(3, 256));
        w32(t->window, c + 4U, w_mfspr(4, 256));
        w32(t->window, c + 8U, w_dform(15U, 5, 0, 0x20));
        w32(t->window, c + 12U, w_dform(36U, 4, 5, 32));
        w32(t->window, c + 16U, w_x31(0, 0, 5, 103, 0));
        w32(t->window, c + 20U, w_vx3(1, 0, 0, 0));
        w32(t->window, c + 24U, w_vx3(3, 3, 3, 1220));
        w32(t->window, c + 28U, w_x31(4, 5, 0, 6, 0));
        w32(t->window, c + 32U, w_va(2, 1, 0, 4, 43));
        w32(t->window, c + 36U, w_vx3(5, 0, 0, 1030));
        w32(t->window, c + 40U, w_dform(14U, 7, 5, 16));
        w32(t->window, c + 44U, w_x31(2, 0, 7, 231, 0));
        w32(t->window, c + 48U, w_dform(14U, 8, 5, 64));
        w32(t->window, c + 52U, w_x31(0, 8, 0, 1014, 0));
        w32(t->window, c + 56U, w_x31(0, 0, 0, 822, 0));
        w32(t->window, c + 60U, w_b(c + 60U, stub, 1));
        w32(t->window, c + 64U, 0x44000002U);
        w32(t->window, stub + 0U, w_dform(14U, 10, 0, 1));
        w32(t->window, stub + 4U, w_blr());
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            t->sc_count++;
            if (t->sc_count == 1) {
                uint32_t vrsave_mem = r32(t->window, DATA_VA + 32U);
                if (st->vrsave == 0x00FF00FFU &&
                    vrsave_mem == 0x00FF00FFU) {
                    t->saw_vrsave_ok = 1;
                }
                if (st->gpr[10] == 1U) {
                    uint8_t *o = (uint8_t *)(uintptr_t)(t->window +
                        DATA_VA + 16U);
                    int ok = 1;
                    int k;
                    for (k = 0; k < 16; k++) {
                        if (o[k] != (uint8_t)((k + k) & 0xFF)) {
                            ok = 0;
                        }
                    }
                    if (ok && ((st->cpsr_or_cr >> 4) & 0xFU) == 0x8U) {
                        t->saw_vec_ok = 1;
                    }
                }
                {
                    uint8_t *z = (uint8_t *)(uintptr_t)(t->window +
                        DATA_VA + 64U);
                    int k;
                    int ok = 1;
                    for (k = 0; k < 32; k++) {
                        if (z[k] != 0U) {
                            ok = 0;
                        }
                    }
                    if (ok) {
                        t->saw_dcbz_ok = 1;
                    }
                }
                /* SMC stub rewrite through the host mapping: the
                 * code page is host READ (RX guest), so widen, copy,
                 * and restore, then FLUSH_ICACHE the translation. */
                {
                    uint32_t nw = w_dform(14U, 10, 0, 2);
                    uint8_t pb[4];

                    pb[0] = (uint8_t)(nw >> 24);
                    pb[1] = (uint8_t)(nw >> 16);
                    pb[2] = (uint8_t)(nw >> 8);
                    pb[3] = (uint8_t)nw;
                    t->saw_patch_ok = (ppc32_darwin_patch_code(t->window,
                        0x100800U, pb, sizeof pb, 5U) == 0);
                }
                tr->reply_action = A32H_DACT_FLUSH_ICACHE;
                tr->flush_va = 0x100800U;
                tr->flush_len = 8U;
                st->pc = CODE_VA + 60U;
                st->next_pc = CODE_VA + 64U;
                return 0;
            }
            if (t->saw_vrsave_ok && t->saw_vec_ok && t->saw_dcbz_ok &&
                st->gpr[10] == 2U) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
                return 0;
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = 1;
            return 0;
        }
    }
    return 0;
}

static int test_a(int engine)
{
    ta_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_a, &t, engine, false);
    CHECK(rc == 0, "a: exit status 0");
    CHECK(t.saw_vrsave_ok, "a: VRSAVE mtspr/mfspr round-trip");
    CHECK(t.saw_vec_ok, "a: lvx/vaddubm/vperm/vcmpeq/stvx + CR6");
    CHECK(t.saw_dcbz_ok, "a: dcbz 32-byte zeroing");
    CHECK(t.saw_patch_ok, "a: SMC host patch applied");
    CHECK(t.sc_count == 2, "a: SMC re-execution after FLUSH_ICACHE");
    if (rc == 0 && t.saw_vrsave_ok && t.saw_vec_ok && t.saw_dcbz_ok &&
        t.saw_patch_ok && t.sc_count == 2) {
        printf("darwin-g02-a (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (b): sc BSD success / BSD error / Mach trap ---- */

typedef struct {
    uint64_t window;
    int sc_count;
    uint32_t after_success;
    uint32_t after_error;
    uint32_t after_mach;
} tb_t;

static int handler_b(void *opaque, unsigned long req, void *arg)
{
    tb_t *t = (tb_t *)opaque;
    if (req == (unsigned long)A32H_DARWIN_BOOT) {
        a32h_darwin_boot_t *b = (a32h_darwin_boot_t *)arg;
        a32h_darwin_vmap_t *v =
            (a32h_darwin_vmap_t *)(uintptr_t)b->vmap_ptr;
        uint32_t c = CODE_VA;
        uint32_t fail = c + 68U;
        t->window = b->window_base;
        v[0].va = CODE_VA;
        v[0].len = 0x1000U;
        v[0].prot = 5U;
        v[0].flags = 0U;
        v[1].va = 0x300000U;
        v[1].len = 0x1000U;
        v[1].prot = 3U;
        v[1].flags = 0U;
        b->vmap_count = 2U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->entry_r0 = 0U;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, c + 0U, w_dform(14U, 0, 0, 10));
        w32(t->window, c + 4U, 0x44000002U);
        w32(t->window, c + 8U, w_b(c + 8U, fail, 0));
        w32(t->window, c + 12U, w_cmpi(3, 0x1234));
        w32(t->window, c + 16U, w_bne(c + 16U, fail));
        w32(t->window, c + 20U, w_dform(14U, 0, 0, 11));
        w32(t->window, c + 24U, 0x44000002U);
        w32(t->window, c + 28U, w_b(c + 28U, c + 40U, 0));
        w32(t->window, c + 32U, w_b(c + 32U, fail, 0));
        w32(t->window, c + 40U, w_cmpi(3, 5));
        w32(t->window, c + 44U, w_bne(c + 44U, fail));
        w32(t->window, c + 48U, w_dform(14U, 0, 0, (uint32_t)(int32_t)-25));
        w32(t->window, c + 52U, 0x44000002U);
        w32(t->window, c + 56U, w_cmpi(3, 0));
        w32(t->window, c + 60U, w_bne(c + 60U, fail));
        w32(t->window, c + 64U, w_dform(3U, 31, 0, 0));
        w32(t->window, fail, w_dform(3U, 31, 0, 0));
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            int32_t r0 = (int32_t)st->gpr[0];
            t->sc_count++;
            if (r0 == 10) {
                st->gpr[3] = 0x1234U;
                st->pc = st->pc + 8U;
                st->next_pc = st->pc + 4U;
                t->after_success = st->pc;
                return 0;
            }
            if (r0 == 11) {
                st->gpr[3] = 5U;
                st->cpsr_or_cr |= 0x10000000U;
                st->pc = st->pc + 4U;
                st->next_pc = st->pc + 4U;
                t->after_error = st->pc;
                return 0;
            }
            if (r0 == -25) {
                st->gpr[3] = 0U;
                st->pc = st->pc + 4U;
                st->next_pc = st->pc + 4U;
                t->after_mach = st->pc;
                return 0;
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = 1;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_BKPT) {
            if (st->pc == CODE_VA + 64U && t->sc_count == 3) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
            } else {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 2;
            }
            return 0;
        }
    }
    return 0;
}

static int test_b(int engine)
{
    tb_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_b, &t, engine, false);
    CHECK(rc == 0, "b: exit status 0");
    CHECK(t.sc_count == 3, "b: three sc dispatches");
    CHECK(t.after_success == CODE_VA + 12U, "b: BSD success pc+8");
    CHECK(t.after_error == CODE_VA + 28U, "b: BSD error pc+4");
    CHECK(t.after_mach == CODE_VA + 56U, "b: Mach trap pc+4");
    if (rc == 0 && t.sc_count == 3) {
        printf("darwin-g02-b (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (c): FAULT precision + SYNC_VM_PROT + DELIVER_SIGNAL ---- */

typedef struct {
    uint64_t window;
    int faults;
    int saw_unmapped;
    int saw_prot;
    int saw_signal;
} tc_t;

static int handler_c(void *opaque, unsigned long req, void *arg)
{
    tc_t *t = (tc_t *)opaque;
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
        v[3].va = RO_VA;
        v[3].len = 0x1000U;
        v[3].prot = 1U;
        v[3].flags = 0U;
        b->vmap_count = 4U;
        b->entry_pc = CODE_VA;
        b->entry_sp = STACK_TOP;
        b->entry_r0 = 0U;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, c + 0U, w_dform(15U, 5, 0, 0x50));
        w32(t->window, c + 4U, w_dform(32U, 4, 5, 0));
        w32(t->window, c + 8U, w_cmpi(4, 0));
        w32(t->window, c + 12U, w_bne(c + 12U, c + 72U));
        w32(t->window, c + 16U, w_dform(15U, 7, 0, 0x40));
        w32(t->window, c + 20U, w_dform(14U, 6, 0, 0x42));
        w32(t->window, c + 24U, w_dform(36U, 6, 7, 0));
        w32(t->window, c + 28U, w_dform(32U, 8, 7, 0));
        w32(t->window, c + 32U, w_cmpi(8, 0x42));
        w32(t->window, c + 36U, w_bne(c + 36U, c + 72U));
        w32(t->window, c + 40U, w_dform(15U, 5, 0, 0x20));
        w32(t->window, c + 44U, w_dform(3U, 31, 0, 0));
        w32(t->window, c + 48U, w_dform(54U, 1, 5, 32));
        w32(t->window, c + 52U, w_x31(0, 0, 5, 231, 0));
        w32(t->window, c + 56U, w_mfspr(11, 256));
        w32(t->window, c + 60U, w_dform(36U, 10, 5, 48));
        w32(t->window, c + 64U, w_dform(36U, 11, 5, 16));
        w32(t->window, c + 68U, 0x44000002U);
        w32(t->window, c + 72U, w_dform(3U, 31, 0, 0));
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_FAULT) {
            t->faults++;
            if (tr->fault_va == UNMAPPED_VA &&
                tr->fault_is_prot == 0U &&
                tr->fault_kind == (uint32_t)A32H_DFAULT_READ) {
                t->saw_unmapped = 1;
            }
            if (tr->fault_va == RO_VA &&
                tr->fault_is_prot == 1U &&
                tr->fault_kind == (uint32_t)A32H_DFAULT_WRITE) {
                t->saw_prot = 1;
            }
            tr->reply_action = A32H_DACT_SYNC_VM_PROT;
            tr->prot_va = tr->fault_va & ~0xFFFU;
            tr->prot_len = 0x1000U;
            tr->prot_flags = 3U;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_BKPT) {
            int k;
            if (st->pc != CODE_VA + 44U) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 3;
                return 0;
            }
            st->gpr[10] = 0xDEADBEEFU;
            for (k = 0; k < 32; k++) {
                st->fpr[k] = 0x400921FB54442D18ULL + (uint64_t)(uint32_t)k;
                st->vr[k][0] = (uint8_t)(0xA0 + k);
                st->vr[k][15] = (uint8_t)k;
            }
            st->fpscr = 0x12340000U;
            st->vscr = 0x00010000U;
            st->vrsave = 0xFFFFFFFFU;
            st->state_flags |= (uint32_t)(A32H_DSTATE_FP_DIRTY |
                A32H_DSTATE_VEC_DIRTY);
            tr->reply_action = A32H_DACT_DELIVER_SIGNAL;
            st->pc = CODE_VA + 48U;
            st->next_pc = CODE_VA + 52U;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            uint32_t g = r32(t->window, DATA_VA + 48U);
            uint32_t vs = r32(t->window, DATA_VA + 16U);
            uint64_t fbits = ((uint64_t)r32(t->window, DATA_VA + 32U) << 32) |
                r32(t->window, DATA_VA + 36U);
            uint8_t *vv = (uint8_t *)(uintptr_t)(t->window + DATA_VA);
            /* Guest stores fr1, and the handler fills fpr[k] with
             * BASE+k, so the double at DATA+32 is BASE+1. */
            if (g == 0xDEADBEEFU && vs == 0xFFFFFFFFU &&
                fbits == 0x400921FB54442D19ULL && vv[0] == 0xA0 &&
                st->vrsave == 0xFFFFFFFFU && st->fpscr == 0x12340000U &&
                t->saw_unmapped && t->saw_prot) {
                t->saw_signal = 1;
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
            } else {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 3;
            }
            return 0;
        }
    }
    return 0;
}

static int test_c(int engine)
{
    tc_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_c, &t, engine, false);
    CHECK(rc == 0, "c: exit status 0");
    CHECK(t.saw_unmapped, "c: unmapped fault va/prot/kind");
    CHECK(t.saw_prot, "c: RO-write fault va/prot/kind");
    CHECK(t.saw_signal, "c: DELIVER_SIGNAL GPR/FPR/VR round-trip");
    if (rc == 0 && t.saw_unmapped && t.saw_prot && t.saw_signal) {
        printf("darwin-g02-c (engine %d): PASS\n", engine);
    }
    return rc;
}

/* ---- subtest (d): SPAWN_THREAD + lwarx/stwcx. across 2 workers ---- */

#define D_SPAWN1 0xD01001U
#define D_SPAWN2 0xD01002U
#define D_ITERS 100U

typedef struct {
    uint64_t window;
    int sc_count;
    int thread_exits;
    uint32_t worker_va;
} td_t;

static int handler_d(void *opaque, unsigned long req, void *arg)
{
    td_t *t = (td_t *)opaque;
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
        b->entry_r0 = 0U;
        b->initial_tid = 1U;
        b->aot_personality_hash = 0xD4A71C0DEU;
        w32(t->window, DATA_VA, 0U);
        w32(t->window, c + 0U, w_dform(14U, 0, 0, D_SPAWN1 & 0xFFFFU));
        w32(t->window, c + 4U, 0x44000002U);
        w32(t->window, c + 8U, w_dform(14U, 0, 0, D_SPAWN2 & 0xFFFFU));
        w32(t->window, c + 12U, 0x44000002U);
        w32(t->window, c + 16U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, c + 20U, w_dform(32U, 5, 4, 0));
        w32(t->window, c + 24U, w_cmpi(5, 200));
        w32(t->window, c + 28U, w_bne(c + 28U, c + 16U));
        w32(t->window, c + 32U, w_dform(3U, 7, 0, 0));
        w32(t->window, w + 0U, w_dform(15U, 4, 0, 0x20));
        w32(t->window, w + 4U, w_lwarx(5, 0, 4));
        w32(t->window, w + 8U, w_dform(14U, 5, 5, 1));
        w32(t->window, w + 12U, w_stwcx(5, 0, 4));
        w32(t->window, w + 16U, w_bne(w + 16U, w + 4U));
        w32(t->window, w + 20U, w_dform(13U, 3, 3, 0xFFFFU));
        w32(t->window, w + 24U, w_bne(w + 24U, w + 4U));
        /* Worker epilogue: trap (never `ba 0`; a branch to 0 is an
         * exec fault, not a clean thread exit). The handler replies
         * EXIT_THREAD and the bridge rendezvous follow. */
        w32(t->window, w + 28U, w_x31(31, 0, 0, 4, 0));
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
            uint32_t r0 = st->gpr[0] & 0xFFFFU;
            t->sc_count++;
            if (r0 == (D_SPAWN1 & 0xFFFFU) || r0 == (D_SPAWN2 & 0xFFFFU)) {
                tr->reply_action = A32H_DACT_SPAWN_THREAD;
                tr->spawn_tid = (r0 == (D_SPAWN1 & 0xFFFFU)) ? 2U : 3U;
                tr->spawn_pc = t->worker_va;
                tr->spawn_sp = (tr->spawn_tid == 2U) ? 0x301000U : 0x302000U;
                tr->spawn_r0 = D_ITERS;
                tr->spawn_tls = 0U;
                st->pc = st->pc + 4U;
                st->next_pc = st->pc + 4U;
                return 0;
            }
            tr->reply_action = A32H_DACT_EXIT_PROCESS;
            tr->exit_status = 1;
            return 0;
        }
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_BKPT) {
            uint32_t counter;
            if (tr->tid == 2U || tr->tid == 3U) {
                /* Worker epilogue trap: end only this thread. */
                tr->reply_action = A32H_DACT_EXIT_THREAD;
                return 0;
            }
            counter = r32(t->window, DATA_VA);
            if (counter == 2U * D_ITERS && t->thread_exits == 2) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
            } else if (counter == 2U * D_ITERS) {
                st->pc = CODE_VA + 16U;
                st->next_pc = CODE_VA + 20U;
            } else {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 4;
            }
            return 0;
        }
    }
    return 0;
}

static int test_d(void)
{
    td_t t;
    int rc;
    memset(&t, 0, sizeof t);
    rc = ppc32_run_darwin_with_handler(handler_d, &t,
        PPC32_ENGINE_INTERP, false);
    CHECK(rc == 0, "d: exit status 0");
    CHECK(t.sc_count == 2, "d: two SPAWN_THREAD dispatches");
    CHECK(t.thread_exits == 2, "d: two THREAD_EXIT reports");
    if (rc == 0 && t.sc_count == 2 && t.thread_exits == 2) {
        printf("darwin-g02-d (interp): PASS\n");
    }
    return rc;
}

/* ---- subtest (e): lockstep --difftest + AOT personality isolation ---- */

typedef struct {
    uint64_t window;
    uint32_t hash;
} te_t;

static int handler_e(void *opaque, unsigned long req, void *arg)
{
    te_t *t = (te_t *)opaque;
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
        b->entry_r0 = 0x00FF00FFU;
        b->initial_tid = 1U;
        b->aot_personality_hash = t->hash;
        for (i = 0; i < 16; i++) {
            uint8_t *p =
                (uint8_t *)(uintptr_t)(t->window + DATA_VA + (uint32_t)i);
            *p = (uint8_t)(0x10 + i);
        }
        w32(t->window, c + 0U, w_mtspr(3, 256));
        w32(t->window, c + 4U, w_mfspr(4, 256));
        /* Timebase sample 1 (hi/lo); monotonicity is checked below. */
        w32(t->window, c + 8U, w_mftb(20, 268));
        w32(t->window, c + 12U, w_mftb(21, 269));
        w32(t->window, c + 16U, w_dform(15U, 5, 0, 0x20));
        w32(t->window, c + 20U, w_dform(36U, 4, 5, 256));
        w32(t->window, c + 24U, w_x31(0, 0, 5, 103, 0));
        w32(t->window, c + 28U, w_vx3(1, 0, 0, 0));
        w32(t->window, c + 32U, w_vx3(10, 0, 0, 10));
        w32(t->window, c + 36U, w_vx3(3, 3, 3, 1220));
        w32(t->window, c + 40U, w_x31(4, 5, 0, 6, 0));
        w32(t->window, c + 44U, w_va(2, 1, 10, 4, 43));
        w32(t->window, c + 48U, w_va(6, 2, 2, 2, 44));
        w32(t->window, c + 52U, w_vx3(7, 6, 6, 64));
        w32(t->window, c + 56U, w_vx3(8, 6, 6, 1088));
        w32(t->window, c + 60U, w_vx3(9, 7, 8, 12));
        w32(t->window, c + 64U, w_vx3(11, 9, 9, 14));
        w32(t->window, c + 68U, w_vx3(12, 11, 11, 398));
        w32(t->window, c + 72U, w_vx3(5, 2, 2, 1030));
        w32(t->window, c + 76U, w_dform(14U, 7, 5, 64));
        w32(t->window, c + 80U, w_x31(2, 0, 7, 231, 0));
        w32(t->window, c + 84U, w_dform(14U, 8, 5, 128));
        w32(t->window, c + 88U, w_x31(0, 8, 0, 1014, 0));
        w32(t->window, c + 92U, w_x31(0, 0, 0, 822, 0));
        w32(t->window, c + 96U, w_x31(0, 8, 0, 982, 0));
        w32(t->window, c + 100U, 0x4C00012CU);
        /* Sample 2; trap (BKPT) unless (hi2:lo2) >= (hi1:lo1). */
        w32(t->window, c + 104U, w_mftb(22, 268));
        w32(t->window, c + 108U, w_mftb(23, 269));
        w32(t->window, c + 112U, w_subf(11, 21, 23));
        w32(t->window, c + 116U, w_cmpi(11, 0));
        w32(t->window, c + 120U, w_blt(c + 120U, c + 160U));
        w32(t->window, c + 124U, w_subf(11, 20, 22));
        w32(t->window, c + 128U, w_cmpi(11, 0));
        w32(t->window, c + 132U, w_blt(c + 132U, c + 160U));
        /* Clear the samples: TB varies per engine run, so it must not
         * leak into the difftest architectural compare at the sc. */
        w32(t->window, c + 136U, w_dform(14U, 20, 0, 0));
        w32(t->window, c + 140U, w_dform(14U, 21, 0, 0));
        w32(t->window, c + 144U, w_dform(14U, 22, 0, 0));
        w32(t->window, c + 148U, w_dform(14U, 23, 0, 0));
        w32(t->window, c + 152U, w_dform(14U, 11, 0, 0));
        w32(t->window, c + 156U, 0x44000002U);
        w32(t->window, c + 160U, w_dform(3U, 31, 0, 0));
        return 0;
    }
    if (req == (unsigned long)A32H_DARWIN_TRAP) {
        a32h_darwin_trap_t *tr = (a32h_darwin_trap_t *)arg;
        a32h_darwin_cpu_state_t *st =
            (a32h_darwin_cpu_state_t *)(uintptr_t)tr->cpu_state_ptr;
        if (tr->exit_reason == (uint32_t)A32H_DEXIT_SVC_TRAP) {
            uint32_t mem = r32(t->window, DATA_VA + 256U);
            if (st->vrsave == 0x00FF00FFU && mem == 0x00FF00FFU) {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 0;
            } else {
                tr->reply_action = A32H_DACT_EXIT_PROCESS;
                tr->exit_status = 5;
            }
            return 0;
        }
        tr->reply_action = A32H_DACT_EXIT_PROCESS;
        tr->exit_status = 6;
        return 0;
    }
    return 0;
}

static int test_e(void)
{
    te_t t;
    int rc;
    ppc32_ctx_t da;
    ppc32_ctx_t la;
    uint64_t kd;
    uint64_t kl;
    memset(&t, 0, sizeof t);
    t.hash = 0xD4A71C0DU;
    rc = ppc32_run_darwin_with_handler(handler_e, &t, PPC32_ENGINE_INTERP,
        true);
    CHECK(rc == 0, "e: difftest exit status 0 (0 divergences)");
    memset(&da, 0, sizeof da);
    memset(&la, 0, sizeof la);
    da.profile = PPC32_PROFILE_CLASSIC;
    da.darwin_aot_hash = 0xD4A71C0DEU;
    la.profile = PPC32_PROFILE_CLASSIC;
    la.darwin_aot_hash = 0U;
    kd = ppc32_darwin_cache_key(&da);
    kl = ppc32_darwin_cache_key(&la);
    CHECK(kd != kl, "e: Darwin vs Linux AOT cache keys differ");
    CHECK(ppc32_darwin_cache_key(&da) == kd, "e: AOT key deterministic");
    {
        ppc32_aot_hdr_t hdr;

        memset(&hdr, 0, sizeof hdr);
        memcpy(hdr.magic, PPC32_AOT_MAGIC, PPC32_AOT_MAGIC_LEN);
        hdr.version = PPC32_AOT_VERSION;
        hdr.profile = (uint32_t)PPC32_PROFILE_CLASSIC;
        hdr.personality =
            ppc32_aot_personality_tag(da.darwin_aot_hash);
        CHECK(ppc32_aot_header_ok(&hdr), "e: AOT header valid");
        CHECK(ppc32_aot_personality_ok(&hdr, da.darwin_aot_hash),
            "e: AOT header accepts Darwin personality");
        CHECK(!ppc32_aot_personality_ok(&hdr, la.darwin_aot_hash),
            "e: AOT header rejects Linux personality");
        CHECK(ppc32_aot_personality_tag(da.darwin_aot_hash) !=
            ppc32_aot_personality_tag(la.darwin_aot_hash),
            "e: AOT personality tags differ");
    }
    if (rc == 0 && kd != kl) {
        printf("darwin-g02-e (difftest): PASS\n");
    }
    return rc;
}

int main(void)
{
    int rc = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    int ra1;
    int ra2;
    int rb1;
    int rb2;
    int rc1;
    int rd;

    ra1 = test_a(PPC32_ENGINE_INTERP);
    ra2 = test_a(PPC32_ENGINE_DBT);
    rb1 = test_b(PPC32_ENGINE_INTERP);
    rb2 = test_b(PPC32_ENGINE_DBT);
    rc1 = test_c(PPC32_ENGINE_INTERP);
    {
        tc_t t2;
        int r2;
        memset(&t2, 0, sizeof t2);
        r2 = ppc32_run_darwin_with_handler(handler_c, &t2,
            PPC32_ENGINE_DBT, false);
        CHECK(r2 == 0, "c-dbt: exit status 0");
        CHECK(t2.saw_unmapped && t2.saw_prot && t2.saw_signal,
            "c-dbt: fault+signal coverage");
        if (r2 == 0 && t2.saw_unmapped && t2.saw_prot && t2.saw_signal) {
            printf("darwin-g02-c (engine dbt): PASS\n");
        }
        if (r2 != 0) {
            rc1 = r2;
        }
    }
    rd = test_d();
    {
        int re = test_e();
        if (re != 0) {
            rc = re;
        }
    }
    if (ra1 != 0 || ra2 != 0 || rb1 != 0 || rb2 != 0 || rc1 != 0 ||
        rd != 0) {
        rc = 1;
    }
    if (g_fails == 0 && rc == 0) {
        printf("check_p32_darwin_g02: ALL OK\n");
        return 0;
    }
    printf("check_p32_darwin_g02: %d FAILURE(S)\n", g_fails);
    return 1;
}
