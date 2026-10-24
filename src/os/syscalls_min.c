/*
 * src/os/syscalls_min.c — Minimal PPC32 Linux syscall layer (Phase 1, L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PPC32 `sc` convention (SPEC 2.3, experiments/E01): number in r0,
 * arguments in r3..r8; 64-bit arguments ride consecutive register pairs
 * high word first. Success: CR0.SO=0, r3=(uint32_t)ret. Error:
 * CR0.SO=1, r3=(uint32_t)(-ret). Unknown numbers take the -ENOSYS error
 * path. nip advances past the 4-byte sc on return.
 *
 * Implemented here: exit, exit_group, read, write, brk, mmap, mmap2,
 * munmap, mprotect, uname (ppc 6x65 layout, machine "ppc"),
 * set_tid_address. Memory-backed calls delegate to the frozen rt32
 * window manager (src/rt32/ppc32.h); read/write/uname/set_tid_address
 * use direct host calls. Char buffers are byte streams: no byte-swap.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/syscalls_min.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/syscall_nr.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

/* ppc utsname: six NUL-padded fields of 65 bytes (matches i686 layout). */
#define PPC32_UTS_FIELD 65U
#define PPC32_UTS_FIELDS 6U

/* Convert a host return (bytes or negative errno) to the kernel-style
 * long the return convention below classifies: negative errno stays
 * negative, values stay non-negative. Short counts are real results. */
static long host_ret(ssize_t n, int err)
{
    if (n < 0) {
        return -(long)err;
    }
    return (long)n;
}

static long sys_read(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    if (count > 0U && (uint64_t)buf_va + (uint64_t)count > 0x100000000ULL) {
        return -EFAULT;
    }
    ssize_t n = read((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    return host_ret(n, errno);
}

static long sys_write(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    if (count > 0U && (uint64_t)buf_va + (uint64_t)count > 0x100000000ULL) {
        return -EFAULT;
    }
    ssize_t n = write((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    return host_ret(n, errno);
}

static long sys_brk(ppc32_ctx_t *ctx, uint32_t new_brk)
{
    /* ppc32_vm_brk: new_brk == 0 reads the current break; otherwise it
     * grows/shrinks the heap and returns the new (or old, when invalid)
     * break, matching Linux brk semantics. The u32 packs addresses and
     * (uint32_t)-errno alike; sign-extend so errors stay negative. */
    return (long)(int32_t)ppc32_vm_brk(ctx, new_brk);
}

static long sys_mmap2(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
    uint32_t flags, uint32_t fd, uint32_t pgoffset)
{
    /* Guest PPC MAP bits (SHARED 0x01, PRIVATE 0x02, FIXED 0x10,
     * ANONYMOUS 0x20) match the vm layer's expectations; pass through.
     * (int)fd keeps -1 anonymous maps. */
    uint32_t r = ppc32_vm_mmap2(ctx, addr, len, prot, flags, (int)fd, pgoffset);
    return (long)(int32_t)r;
}

static long sys_mmap(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
    uint32_t flags, uint32_t fd, uint32_t offset)
{
    /* PowerPC sys_mmap(90) takes a byte offset; the vm layer takes pages. */
    if ((offset & (PPC32_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    return sys_mmap2(ctx, addr, len, prot, flags, fd, offset >> 12U);
}

static long sys_munmap(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    return (long)ppc32_vm_munmap(ctx, addr, len);
}

static long sys_mprotect(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    return (long)ppc32_vm_mprotect(ctx, addr, len, prot);
}

static long sys_uname(ppc32_ctx_t *ctx, uint32_t buf_va)
{
    static const char *const fields[PPC32_UTS_FIELDS] = {
        "Linux",
        "ppc32rt",
        "6.1.0",
        "#1 SMP ppc32rt",
        "ppc",
        "(none)",
    };
    uint8_t *buf;
    size_t i;
    size_t j;

    if (buf_va > (uint32_t)(0xFFFFFFFFU - (PPC32_UTS_FIELD * PPC32_UTS_FIELDS - 1U))) {
        return -EFAULT;
    }
    buf = (uint8_t *)ppc32_guest_ptr(ctx, buf_va);
    for (i = 0U; i < PPC32_UTS_FIELDS; i++) {
        uint8_t *field = buf + (size_t)i * PPC32_UTS_FIELD;
        memset(field, 0, PPC32_UTS_FIELD);
        for (j = 0U; fields[i][j] != '\0' && j < PPC32_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)fields[i][j];
        }
    }
    return 0;
}

static long sys_set_tid_address(ppc32_ctx_t *ctx, uint32_t tidptr_va)
{
    long tid;

    ctx->clear_child_tid = tidptr_va;
    /* Linux returns the caller's thread id; musl uses it to seed the
     * main thread's tid. Prefer the recorded host tid, else getpid. */
    if (ctx->host_tid > 0) {
        tid = (long)ctx->host_tid;
    } else {
        tid = (long)getpid();
    }
    return tid;
}

int ppc32_syscall_min_is_exit(uint32_t nr)
{
    return (nr == PPC32_NR_EXIT || nr == PPC32_NR_EXIT_GROUP) ? 1 : 0;
}

void ppc32_syscall_min(ppc32_ctx_t *ctx)
{
    uint32_t nr;
    uint32_t a0;
    uint32_t a1;
    uint32_t a2;
    uint32_t a3;
    uint32_t a4;
    uint32_t a5;
    long ret;

    if (ctx == NULL) {
        return;
    }
    nr = ctx->gpr[0];
    a0 = ctx->gpr[3];
    a1 = ctx->gpr[4];
    a2 = ctx->gpr[5];
    a3 = ctx->gpr[6];
    a4 = ctx->gpr[7];
    a5 = ctx->gpr[8];

    /* Reservations die at syscall entry (SPEC 2.2, lwarx/stwcx.). */
    ctx->res_valid = 0;
    ctx->reservation_epoch++;

    switch (nr) {
    case PPC32_NR_EXIT:
        ctx->exit_arg = a0 & 0xFFU;
        ret = (long)(int32_t)ctx->exit_arg;
        break;
    case PPC32_NR_EXIT_GROUP:
        ctx->exit_arg = a0 & 0xFFU;
        ret = (long)(int32_t)ctx->exit_arg;
        break;
    case PPC32_NR_READ:
        ret = sys_read(ctx, a0, a1, a2);
        break;
    case PPC32_NR_WRITE:
        ret = sys_write(ctx, a0, a1, a2);
        break;
    case PPC32_NR_BRK:
        ret = sys_brk(ctx, a0);
        break;
    case PPC32_NR_MMAP:
        ret = sys_mmap(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case PPC32_NR_MMAP2:
        ret = sys_mmap2(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case PPC32_NR_MUNMAP:
        ret = sys_munmap(ctx, a0, a1);
        break;
    case PPC32_NR_MPROTECT:
        ret = sys_mprotect(ctx, a0, a1, a2);
        break;
    case PPC32_NR_UNAME:
        ret = sys_uname(ctx, a0);
        break;
    case PPC32_NR_SET_TID_ADDRESS:
        ret = sys_set_tid_address(ctx, a0);
        break;
    default:
        ret = -ENOSYS;
        break;
    }

    /* E01 return convention: classify on the kernel-style long, never on
     * the magnitude of the truncated r3 alone. */
    if (ret < 0L && ret >= -4095L) {
        ctx->gpr[3] = (uint32_t)(-ret);
        ctx->cr |= PPC32_CR0_SO;
    } else {
        ctx->gpr[3] = (uint32_t)ret;
        ctx->cr &= (uint32_t)~PPC32_CR0_SO;
    }
    ctx->syscalls_executed++;
    ctx->nip += 4U;
}
