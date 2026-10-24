/*
 * src/rt32/ppc32_stack32.c — 32-bit initial stack, argv, envp, and auxv builder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from i686rt/src/rt32/rt32_stack32.c (itself vendored
 * from a32rt/src/stack32.c @ d84feb3, SPEC D13): mechanical renames,
 * retyped on ppc32_ctx_t; guest stack top PPC32_STACK_TOP (0xBFFF0000,
 * SPEC 1.1); AT_PLATFORM "ppc".
 *
 * Phase 0 scope: maps the stack and builds a minimal valid initial frame
 * (argc/argv/envp + AT_NULL-terminated auxv). The full PPC32 auxv
 * (AT_PHDR/AT_ENTRY/AT_UID/..., AT_DCACHEBSIZE from E04/E07 follow-ups),
 * AT_RANDOM/AT_EXECFN, and the synthetic vDSO/sigtramp mapping at
 * PPC32_SIGTRAMP_BASE arrive with the Phase 2 os lane; this file's
 * ppc32_stack_setup() signature is frozen for it.
 */

#define _GNU_SOURCE
#include "ppc32.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PPC32_STACK_SIZE (8U * 1024U * 1024U)

static uint32_t push_bytes(ppc32_ctx_t *ctx, uint32_t *sp,
                           const void *data, size_t len)
{
    if (*sp < ctx->stack_base || len > (size_t)(*sp - ctx->stack_base)) {
        return 0U;
    }
    *sp -= (uint32_t)len;
    memcpy(ppc32_guest_ptr(ctx, *sp), data, len);
    return *sp;
}

static uint32_t push_cstring(ppc32_ctx_t *ctx, uint32_t *sp, const char *s)
{
    size_t len = strlen(s) + 1U;
    return push_bytes(ctx, sp, s, len);
}

static int push_string_table(ppc32_ctx_t *ctx, uint32_t *sp, char **strs,
                             int max_count, uint32_t *out_ptrs, int *out_count)
{
    int count = 0;
    if (strs) {
        while (count < max_count && count < 511 && strs[count] != NULL) {
            count++;
        }
        for (int i = count - 1; i >= 0; i--) {
            out_ptrs[i] = push_cstring(ctx, sp, strs[i]);
            if (out_ptrs[i] == 0U) {
                return -1;
            }
        }
    }
    *out_count = count;
    return 0;
}

int ppc32_stack_setup(ppc32_ctx_t *ctx, const ppc32_elf_info_t *elf_info,
                      int guest_argc, char **guest_argv, char **host_envp,
                      uint32_t *out_sp)
{
    if (!ctx || !elf_info || !out_sp || guest_argc < 1 || !guest_argv ||
        !guest_argv[0]) {
        return -1;
    }

    uint32_t stack_base = PPC32_STACK_TOP - PPC32_STACK_SIZE;
    void *host_stack = ppc32_guest_ptr(ctx, stack_base);
    void *res = mmap(host_stack, PPC32_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        fprintf(stderr, "ppc32rt: failed to map guest stack: %s\n",
                strerror(errno));
        return -1;
    }
    ctx->stack_top  = PPC32_STACK_TOP;
    ctx->stack_base = stack_base;
    ppc32_vm_record_region(ctx, stack_base, PPC32_STACK_TOP,
                           (uint32_t)(PROT_READ | PROT_WRITE), 0x12U,
                           "[stack]");

    uint32_t sp = PPC32_STACK_TOP - 64U;

    uint32_t at_platform_va = push_cstring(ctx, &sp, "ppc");
    if (at_platform_va == 0U) {
        return -1;
    }

    uint32_t env_ptrs[512];
    uint32_t arg_ptrs[512];
    int envc = 0;
    int argc = 0;
    if (push_string_table(ctx, &sp, host_envp, 511, env_ptrs, &envc) != 0 ||
        push_string_table(ctx, &sp, guest_argv, guest_argc, arg_ptrs,
                          &argc) != 0) {
        return -1;
    }

    sp &= ~0xFU;

    /* Phase 0 minimal auxv: AT_NULL only. The Phase 2 os lane extends this
     * with AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY/AT_UID/AT_PLATFORM/AT_RANDOM
     * and the vDSO pair once the vDSO/sigtramp mapping lands. */
    uint32_t auxv[2];
    auxv[0] = 0U; /* AT_NULL */
    auxv[1] = 0U;
    size_t aux_idx = 2U;

    /* Frame layout: argc, argv[0..argc-1], NULL, envp[0..envc-1], NULL,
     * auxv[] (16-byte aligned). */
    size_t total_words   = 1U + ((size_t)argc + 1U) + ((size_t)envc + 1U) + aux_idx;
    uint32_t frame_bytes = (uint32_t)(total_words * sizeof(uint32_t));
    if (sp < ctx->stack_base || (sp - ctx->stack_base) < frame_bytes + 16U) {
        return -1;
    }
    uint32_t final_sp = (sp - frame_bytes) & ~0xFU;

    uint32_t *w = (uint32_t *)ppc32_guest_ptr(ctx, final_sp);
    size_t pos = 0;
    w[pos++] = (uint32_t)argc;
    memcpy(&w[pos], arg_ptrs, (size_t)argc * sizeof(uint32_t));
    pos += (size_t)argc;
    w[pos++] = 0U;
    memcpy(&w[pos], env_ptrs, (size_t)envc * sizeof(uint32_t));
    pos += (size_t)envc;
    w[pos++] = 0U;
    memcpy(&w[pos], auxv, aux_idx * sizeof(uint32_t));

    ctx->guest_argc = argc;
    ctx->guest_argv = guest_argv;
    ctx->host_envp  = host_envp;

    size_t copy_words = aux_idx;
    if (copy_words > (sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]))) {
        copy_words = sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]);
    }
    memcpy(ctx->auxv_data, auxv, copy_words * sizeof(uint32_t));
    ctx->auxv_bytes = copy_words * sizeof(uint32_t);

    *out_sp = final_sp;
    return 0;
}
