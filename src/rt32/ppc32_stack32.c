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

#include "vm/vm32.h"

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
    /* Mirror for the A2 union layer (anonymous RW pages). */
    vm32_record_map(stack_base, PPC32_STACK_TOP,
        (uint8_t)(PROT_READ | PROT_WRITE), (uint8_t)VM32_PAGE_ANON);
    if (vm32_is_a2()) {
        (void)vm32_sync_host_range(stack_base, PPC32_STACK_TOP);
    }

    uint32_t sp = PPC32_STACK_TOP - 64U;

    uint32_t at_platform_va = push_cstring(ctx, &sp, "ppc");
    if (at_platform_va == 0U) {
        return -1;
    }
    uint32_t at_execfn_va = push_cstring(ctx, &sp,
        (guest_argv != NULL && guest_argv[0] != NULL) ? guest_argv[0] : "ppc32rt");
    if (at_execfn_va == 0U) {
        return -1;
    }
    /* AT_RANDOM: 16 bytes from the host RNG, 16-byte aligned. */
    uint8_t rand_bytes[16];
    {
        FILE *rf = fopen("/dev/urandom", "rb");
        size_t got = 0U;

        if (rf != NULL) {
            got = fread(rand_bytes, 1U, sizeof(rand_bytes), rf);
            fclose(rf);
        }
        if (got != sizeof(rand_bytes)) {
            uint32_t seed = 0x9E3779B9U ^ (uint32_t)(uintptr_t)ctx;

            for (size_t ri = 0U; ri < sizeof(rand_bytes); ri++) {
                seed = seed * 1664525U + 1013904223U;
                rand_bytes[ri] = (uint8_t)(seed >> 24);
            }
        }
    }
    sp &= ~0xFU;
    uint32_t at_random_va = push_bytes(ctx, &sp, rand_bytes, sizeof(rand_bytes));
    if (at_random_va == 0U) {
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

    /* RC2 full auxv (Phase 2 L2a scope): static glibc startup walks
     * AT_PHDR (TLS/relro), reads AT_RANDOM (pointer guard), and dispatches
     * IFUNCs off AT_HWCAP. HWCAP bits per arch/powerpc uapi cputable.h. */
    uint32_t auxv[40];
    size_t aux_idx = 0U;

    auxv[aux_idx++] = 3U; /* AT_PHDR */
    auxv[aux_idx++] = elf_info->phdr_vaddr;
    auxv[aux_idx++] = 4U; /* AT_PHENT */
    auxv[aux_idx++] = elf_info->phent;
    auxv[aux_idx++] = 5U; /* AT_PHNUM */
    auxv[aux_idx++] = elf_info->phnum;
    auxv[aux_idx++] = 6U; /* AT_PAGESZ */
    auxv[aux_idx++] = 4096U;
    auxv[aux_idx++] = 8U; /* AT_FLAGS */
    auxv[aux_idx++] = 0U;
    auxv[aux_idx++] = 9U; /* AT_ENTRY */
    auxv[aux_idx++] = elf_info->entry;
    auxv[aux_idx++] = 11U; /* AT_UID */
    auxv[aux_idx++] = (uint32_t)getuid();
    auxv[aux_idx++] = 12U; /* AT_EUID */
    auxv[aux_idx++] = (uint32_t)geteuid();
    auxv[aux_idx++] = 13U; /* AT_GID */
    auxv[aux_idx++] = (uint32_t)getgid();
    auxv[aux_idx++] = 14U; /* AT_EGID */
    auxv[aux_idx++] = (uint32_t)getegid();
    auxv[aux_idx++] = 15U; /* AT_PLATFORM */
    auxv[aux_idx++] = at_platform_va;
    auxv[aux_idx++] = 16U; /* AT_HWCAP */
    auxv[aux_idx++] = (ctx->profile == PPC32_PROFILE_SPE) ?
        0x80E00002U : 0x8000000AU;
    auxv[aux_idx++] = 17U; /* AT_CLKTCK */
    auxv[aux_idx++] = 100U;
    auxv[aux_idx++] = 25U; /* AT_RANDOM */
    auxv[aux_idx++] = at_random_va;
    auxv[aux_idx++] = 26U; /* AT_HWCAP2 */
    auxv[aux_idx++] = 0U;
    auxv[aux_idx++] = 31U; /* AT_EXECFN */
    auxv[aux_idx++] = at_execfn_va;
    /* Phase 5 L5a: AT_BASE (interpreter base, 0 when static) and
     * AT_SECURE (0: no setuid/setgid elevation). Appended after the
     * existing slots; AT_NULL still terminates the vector. */
    auxv[aux_idx++] = 7U; /* AT_BASE */
    auxv[aux_idx++] = elf_info->interp_base;
    auxv[aux_idx++] = 23U; /* AT_SECURE */
    auxv[aux_idx++] = 0U;
    auxv[aux_idx++] = 0U; /* AT_NULL */
    auxv[aux_idx++] = 0U;

    /* Frame layout: argc, argv[0..argc-1], NULL, envp[0..envc-1], NULL,
     * auxv[] (16-byte aligned). */
    size_t total_words   = 1U + ((size_t)argc + 1U) + ((size_t)envc + 1U) + aux_idx;
    uint32_t frame_bytes = (uint32_t)(total_words * sizeof(uint32_t));
    if (sp < ctx->stack_base || (sp - ctx->stack_base) < frame_bytes + 16U) {
        return -1;
    }
    uint32_t final_sp = (sp - frame_bytes) & ~0xFU;

    /* Guest is big-endian: every word in the initial frame must be
     * byte-swapped on the (little-endian) host (RC2: argc arrived as
     * 0x01000000 and killed static glibc startup). */
    uint32_t *w = (uint32_t *)ppc32_guest_ptr(ctx, final_sp);
    size_t pos = 0;
    int i;

    w[pos++] = ppc32_be32((uint32_t)argc);
    for (i = 0; i < argc; i++) {
        w[pos++] = ppc32_be32(arg_ptrs[i]);
    }
    w[pos++] = 0U;
    for (i = 0; i < envc; i++) {
        w[pos++] = ppc32_be32(env_ptrs[i]);
    }
    w[pos++] = 0U;
    for (i = 0; (size_t)i < aux_idx; i++) {
        w[pos++] = ppc32_be32(auxv[i]);
    }

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
