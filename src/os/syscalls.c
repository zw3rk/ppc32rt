/*
 * src/os/syscalls.c — Full static-libc PPC32 Linux syscall layer (Phase 2, L2a)
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
 * Memory-backed calls delegate to the frozen rt32 window manager
 * (src/rt32/ppc32.h); fd and time calls use direct host calls. Char
 * buffers are byte streams (no byte-swap); every multi-byte struct
 * field converts through os/convert.h. Four guest O_* flag bits differ
 * from the host asm-generic layout (DIRECTORY/NOFOLLOW/LARGEFILE/DIRECT),
 * so syscalls_file.c translates them on every open/fcntl crossing.
 * Phase 4
 * (RC4) wires the lane-owned layers: signals via os/signals.h
 * (ppc32_sig_syscall, no-advance rt_sigreturn), threads via os/threads.h
 * (clone/futex/set_tid_address), and process lifecycle via os/proc.h
 * (fork/execve/wait4/pipe/dup2). Old-style sigaction/sigprocmask stay
 * -ENOSYS (the static-libc oracle path uses the rt_* variants).
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "os/syscalls.h"
#include "dbt/dbt.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/proc.h"
#include "os/procfs.h"
#include "os/signals.h"
#include "os/syscall_nr.h"
#include "os/threads.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"
#include "vm/vm32.h"

#ifdef __linux__
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <termios.h>
#endif

/* See convert.h: drop the host st_atime aliases so guest spellings survive. */
#undef st_atime
#undef st_mtime
#undef st_ctime

/* Identity truncate (P32-R4-10) is declared in vm/vm32.h alongside
 * the other Provider-A helpers. */

/* Numbers absent from the frozen os/syscall_nr.h (powerpc syscall.tbl):
 * clock_gettime 246, openat 286, getrandom 359. Guarded so a future
 * header update wins. */
#ifndef PPC32_NR_CLOCK_GETTIME
#define PPC32_NR_CLOCK_GETTIME 246U
#endif
#ifndef PPC32_NR_CLOCK_GETTIME64
#define PPC32_NR_CLOCK_GETTIME64 403U
#endif
#ifndef PPC32_NR_OPENAT
#define PPC32_NR_OPENAT 286U
#endif
#ifndef PPC32_NR_GETRANDOM
#define PPC32_NR_GETRANDOM 359U
#endif

/* ppc utsname: six NUL-padded fields of 65 bytes (matches i686 layout). */
#define PPC32_UTS_FIELD 65U
#define PPC32_UTS_FIELDS 6U

#define PPC32_IOV_MAX 1024U

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

/* Landed read bytes: evict blocks, kill LL/SC (P32-R4-12), fan out to
 * staged aliases and write through to the file (P32-R5-6: a read into a
 * writable staged MAP_SHARED mapping is a coherent store). */
static void sys_read_landed(ppc32_ctx_t *ctx, uint32_t base, uint32_t n)
{
    if (n == 0U) {
        return;
    }
    ppc32_smc_store(ctx, base, n, NULL);
    vm32_store_invalidate_range(base, n);
    vm_file_shared_cohere_store(ctx, base, n);
}

/* P1: read/pread64 helper; landed bytes evict overlapping blocks. */
static long sys_read_at(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va,
    uint32_t count, bool use_pread, int64_t off)
{
    ssize_t n;

    if (count > 0U && !ppc32_range_ok(buf_va, count)) {
        return -EFAULT;
    }
    /* P32-R4-11: the destination needs guest write permission, checked
     * per sub-page so an accessible host-page neighbor cannot launder
     * a read-only or unmapped target. */
    if (count > 0U &&
        !ppc32_vm_range_prot_ok(ctx, buf_va, count, 2U)) {
        return -EFAULT;
    }
    n = use_pread ? pread((int)fd, ppc32_guest_ptr(ctx, buf_va),
        (size_t)count, (off_t)off) :
        read((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    if (n > 0) {
        sys_read_landed(ctx, buf_va, (uint32_t)n);
    }
    return host_ret(n, errno);
}

static long sys_write(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    ssize_t n;

    if (count > 0U && !ppc32_range_ok(buf_va, count)) {
        return -EFAULT;
    }
    /* P32-R4-11: the source needs guest read permission (sub-page). */
    if (count > 0U &&
        !ppc32_vm_range_prot_ok(ctx, buf_va, count, 1U)) {
        return -EFAULT;
    }
    n = write((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    if (n > 0) {
        /* Provider-A hook: an extending write moves the inode EOF
         * forward (no-op until a file mapping registers the fd),
         * then overlapping staged aliases refresh from the file. */
        off_t end = lseek((int)fd, 0, SEEK_CUR);

        if (end >= (off_t)0) {
            (void)vm_file_hook_write((int)fd, (uint64_t)end);
            vm_file_shared_refresh_file_range((int)fd,
                (uint64_t)(end - n), (uint64_t)end);
        }
    }
    return host_ret(n, errno);
}

/* Single-shot vectored I/O (P32-R5-4/5): snapshot guest (base,len)
 * pairs before issuing one host readv/writev (atomic datagram/pipe
 * semantics, no re-read of guest iovec after I/O). */
static long sys_vec(ppc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t count, int is_write)
{
    struct iovec *hv = NULL;
    uint32_t *bases = NULL;
    uint32_t *lens = NULL;
    uint64_t result = 0ULL;
    uint32_t need_prot = (is_write != 0) ? 1U : 2U;
    ssize_t got;
    uint32_t j;

    if (count == 0U) {
        return 0;
    }
    if (count > PPC32_IOV_MAX) {
        return -EINVAL;
    }
    if (!ppc32_range_ok(iov_va, (size_t)count * sizeof(ppc32_iovec_t))) {
        return -EFAULT;
    }
    /* P32-R4-11: the iovec table itself is guest-read in both modes. */
    if (!ppc32_vm_range_prot_ok(ctx, iov_va,
            (size_t)count * sizeof(ppc32_iovec_t), 1U)) {
        return -EFAULT;
    }
    hv = (struct iovec *)malloc((size_t)count * sizeof(*hv));
    bases = (uint32_t *)malloc((size_t)count * sizeof(*bases));
    lens = (uint32_t *)malloc((size_t)count * sizeof(*lens));
    if (hv == NULL || bases == NULL || lens == NULL) {
        free(hv);
        free(bases);
        free(lens);
        return -ENOMEM;
    }
    for (j = 0U; j < count; j++) {
        uint32_t base = ppc32_ld32be(ctx, iov_va + j * 8U);
        uint32_t len = ppc32_ld32be(ctx, iov_va + j * 8U + 4U);

        if (len > 0U && !ppc32_range_ok(base, len)) {
            free(hv);
            free(bases);
            free(lens);
            return -EFAULT;
        }
        /* P32-R4-11: per-range sub-page perms (read src / write dst). */
        if (len > 0U &&
            !ppc32_vm_range_prot_ok(ctx, base, len, need_prot)) {
            free(hv);
            free(bases);
            free(lens);
            return -EFAULT;
        }
        bases[j] = base;
        lens[j] = len;
        hv[j].iov_base = len == 0U ? NULL : ppc32_guest_ptr(ctx, base);
        hv[j].iov_len = (size_t)len;
    }
    got = is_write ? writev((int)fd, hv, (int)count) :
        readv((int)fd, hv, (int)count);
    if (got < 0) {
        int e = errno;
        free(hv);
        free(bases);
        free(lens);
        return -(long)e;
    }
    if (got > 0 && is_write == 0) {
        /* P32-R4-1 + R5-4: landed bookkeeping from the snapshot. */
        uint64_t rem = (uint64_t)got;

        for (j = 0U; j < count && rem > 0ULL; j++) {
            uint32_t hit = (uint64_t)lens[j] > rem ?
                (uint32_t)rem : lens[j];
            sys_read_landed(ctx, bases[j], hit);
            rem -= (uint64_t)hit;
        }
    }
    result = (uint64_t)got;
    free(hv);
    free(bases);
    free(lens);
    if (is_write != 0 && result > 0ULL) {
        /* Same Provider-A EOF hook as sys_write above. */
        off_t end = lseek((int)fd, 0, SEEK_CUR);

        if (end >= (off_t)0) {
            (void)vm_file_hook_write((int)fd, (uint64_t)end);
            vm_file_shared_refresh_file_range((int)fd,
                (uint64_t)((uint64_t)end - result), (uint64_t)end);
        }
    }
    return (long)result;
}

/* File opens, close, unlink, lseek, llseek, stat, and ioctl live in
 * syscalls_file.c. */

/* Provider-A truncate hook: the host call resizes first; only then
 * does the mem layer discard/regrow translations (section 4.5). The
 * identity form moves just the truncated file's mapping (RC-U3-r2 #4). */
static long sys_ftruncate(uint32_t fd, uint32_t length)
{
    if (ftruncate((int)fd, (off_t)length) != 0) {
        return -(long)errno;
    }
    (void)vm_file_on_truncate_fd((int)fd, (uint64_t)length);
    return 0;
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
    /* P32-R9-5: compose into a host buffer, then publish through the
     * permission-checked copyout (mapped/write/trap-checked) so an
     * unmapped or kernel-region VA returns -EFAULT instead of killing
     * the host with a SIGSEGV outside hostfault_run. */
    uint8_t buf[PPC32_UTS_FIELD * PPC32_UTS_FIELDS];
    size_t i;
    size_t j;

    if (!ppc32_range_ok(buf_va, sizeof buf) ||
        !ppc32_vm_range_prot_ok(ctx, buf_va, sizeof buf, 2U)) {
        return -EFAULT;
    }
    for (i = 0U; i < PPC32_UTS_FIELDS; i++) {
        uint8_t *field = buf + (size_t)i * PPC32_UTS_FIELD;

        memset(field, 0, PPC32_UTS_FIELD);
        for (j = 0U; fields[i][j] != '\0' && j < PPC32_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)fields[i][j];
        }
    }
    return (long)ppc32_vm_copyout_safe(ctx, buf_va, buf, sizeof buf);
}

static long sys_clock_gettime(ppc32_ctx_t *ctx, uint32_t clk, uint32_t ts_va,
    int is64)
{
    struct timespec ts;
    clockid_t hclk = (clockid_t)clk;

#ifdef __APPLE__
    hclk = (clk == 1U || clk == 4U || clk == 6U || clk == 7U) ?
        CLOCK_MONOTONIC : CLOCK_REALTIME;
#endif
    if (clock_gettime(hclk, &ts) != 0) {
        return -(long)errno;
    }
    if (is64) {
        /* P32-R9-5: publish through the permission-checked copyout so
         * an unmapped VA faults with -EFAULT instead of crashing. */
        uint64_t sec_be = ppc32_be64((uint64_t)(int64_t)ts.tv_sec);
        uint64_t nsec_be = ppc32_be64((uint64_t)(int64_t)ts.tv_nsec);
        uint8_t tmp[16];

        memcpy(tmp, &sec_be, sizeof sec_be);
        memcpy(tmp + 8U, &nsec_be, sizeof nsec_be);
        if (!ppc32_range_ok(ts_va, sizeof tmp)) {
            return -EFAULT;
        }
        return (long)ppc32_vm_copyout_safe(ctx, ts_va, tmp, sizeof tmp);
    }
    return (long)ppc32_put_timespec(ctx, ts_va, &ts);
}

static long sys_gettimeofday(ppc32_ctx_t *ctx, uint32_t tv_va)
{
    struct timeval tv;

    /* The guest tz argument is obsolete on Linux; always ignore it. */
    if (gettimeofday(&tv, NULL) != 0) {
        return -(long)errno;
    }
    return (long)ppc32_put_timeval(ctx, tv_va, &tv);
}

static long sys_getrandom(ppc32_ctx_t *ctx, uint32_t buf_va, uint32_t len,
    uint32_t flags)
{
#ifdef __linux__
    char *host;
    ssize_t n;

    if (len == 0U) {
        return 0;
    }
    if (!ppc32_range_ok(buf_va, len)) {
        return -EFAULT;
    }
    if (!ppc32_vm_range_prot_ok(ctx, buf_va, len, 2U)) {
        return -EFAULT;
    }
    host = (char *)malloc((size_t)len);
    if (host == NULL) {
        return -ENOMEM;
    }
    /* GRND_* flag bits are Linux-generic: pass through. */
    n = getrandom(host, (size_t)len, (unsigned int)flags);
    if (n > 0) {
        if (ppc32_vm_copyout_safe(ctx, buf_va, host, (size_t)n) != 0) {
            free(host);
            return -EFAULT;
        }
        sys_read_landed(ctx, buf_va, (uint32_t)n);
    }
    {
        int err = errno;
        free(host);
        return host_ret(n, err);
    }
#else
    (void)ctx;
    (void)buf_va;
    (void)len;
    (void)flags;
    return -ENOSYS;
#endif
}

extern long ppc32_run_guest_child(ppc32_ctx_t *child);
/* Concurrent clone runner (P32-R5-1): runs the guest child to exit on a
 * host pthread via threads.c thread_entry; parent returns immediately. */
static void sys_clone_run(ppc32_ctx_t *child, void *opaque)
{
    (void)opaque;
    if (child != NULL) {
        (void)ppc32_run_guest_child(child);
    }
}

/* E01 return convention (SPEC 2.3, experiments/E01): classify on the
 * kernel-style long, never on the magnitude of the truncated r3 alone.
 * Under --trace, also reports the kernel-style result (G3 bring-up). */
static void sys_apply_ret(ppc32_ctx_t *ctx, uint32_t nr, long ret)
{
    if (ctx->trace_syscalls) {
        fprintf(stderr, "  sc=%u -> %ld\n", nr, ret);
    }
    if (ret < 0L && ret >= -4095L) {
        ctx->gpr[3] = (uint32_t)(-ret);
        ctx->cr |= PPC32_CR0_SO;
    } else {
        ctx->gpr[3] = (uint32_t)ret;
        ctx->cr &= (uint32_t)~PPC32_CR0_SO;
    }
}

/* getpid(2) and kill(2) live in their owning layers (proc.c, signals.c):
 * the switch below calls ppc32_proc_getpid and ppc32_sig_kill. */

int ppc32_syscall_is_exit(uint32_t nr)
{
    return (nr == PPC32_NR_EXIT || nr == PPC32_NR_EXIT_GROUP) ? 1 : 0;
}

void ppc32_syscall(ppc32_ctx_t *ctx)
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
    if (ctx->vm_ready) {
        ppc32_vm_sync_ctx(ctx);
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

    /* RC5 (G3): guest syscall trace for dynamic bring-up; prints the
     * number + raw args at entry. Quiet unless --trace is passed. */
    if (ctx->trace_syscalls) {
        fprintf(stderr, "ppc32rt: sc=%u(%u,%u,%u,%u,%u,%u)\n", nr, a0, a1,
            a2, a3, a4, a5);
    }

    /* Phase 4 signal syscalls (L4a): rt_sigaction/procmask/pending,
     * rt_sigreturn, sigaltstack. rt_sigreturn restores nip/r3/cr from
     * the frame, so neither the E01 convention nor the sc advance
     * applies to it (ppc32_sig_nr_no_advance). */
    {
        long hook = 0L;

        if (ppc32_sig_syscall(ctx, nr, a0, a1, a2, a3, &hook)) {
            if (!ppc32_sig_nr_no_advance(nr)) {
                sys_apply_ret(ctx, nr, hook);
                ctx->nip += 4U;
            }
            ctx->syscalls_executed++;
            ppc32_sig_pump_pending(ctx);
            return;
        }
    }
    /* Phase 4 process lifecycle (L4c): fork/execve/wait4/pipe/dup2.
     * Owned numbers apply E01 + nip internally (proc_dispatch owns the
     * tail, including the execve-success no-advance reparking). */
    if (ppc32_proc_dispatch(ctx, nr, a0, a1, a2, a3, a4, a5)) {
        return;
    }
    /* RC5 dynamic-loading layer (access/statx/getcwd/rlimit/dents64/
     * ids). Owned numbers take the common E01 + advance tail below. */
    {
        long dyn = 0L;

        if (ppc32_dyn_dispatch(ctx, nr, a0, a1, a2, a3, a4, a5, &dyn)) {
            sys_apply_ret(ctx, nr, dyn);
            ctx->nip += 4U;
            ctx->syscalls_executed++;
            ppc32_sig_pump_pending(ctx);
            return;
        }
    }

    switch (nr) {
    case PPC32_NR_EXIT:
        /* Thread exit: ends the calling thread only (main.c waits out
         * live siblings for the initial thread; workers return to the
         * thread_entry teardown). */
        ctx->exit_arg = a0 & 0xFFU;
        ret = (long)(int32_t)ctx->exit_arg;
        break;
    case PPC32_NR_EXIT_GROUP:
        /* Group exit: ends every thread (main.c _exit(2)s from workers
         * and returns the status from the initial thread). */
        ctx->exit_arg = a0 & 0xFFU;
        ret = (long)(int32_t)ctx->exit_arg;
        break;
    case PPC32_NR_READ:
        ret = sys_read_at(ctx, a0, a1, a2, false, 0);
        break;
    case PPC32_NR_PREAD64: {
        uint64_t uoff = ((uint64_t)a3 << 32U) | (uint64_t)a4;
        ret = sys_read_at(ctx, a0, a1, a2, true, (off_t)(int64_t)uoff);
        break;
    }
    case PPC32_NR_WRITE:
        ret = sys_write(ctx, a0, a1, a2);
        break;
    case PPC32_NR_READV:
        ret = sys_vec(ctx, a0, a1, a2, 0);
        break;
    case PPC32_NR_WRITEV:
        ret = sys_vec(ctx, a0, a1, a2, 1);
        break;
    case PPC32_NR_OPEN:
        ret = sys_openat(ctx, (uint32_t)(int32_t)-100, a0, a1, a2);
        break;
    case PPC32_NR_OPENAT:
        ret = sys_openat(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_CLOSE:
        ret = sys_close(a0);
        break;
    case PPC32_NR_READLINK:
        /* Phase 5 L5a: /proc/self/exe keeps symlink semantics; other
         * paths fall through to the host readlink inside procfs.c. */
        ret = ppc32_procfs_readlink(ctx, a0, a1, a2);
        break;
    case PPC32_NR_READLINKAT:
        /* RC5: readlinkat (BusyBox resolves /proc/self/exe through it);
         * dirfd-relative resolution matches openat semantics. */
        ret = ppc32_procfs_readlinkat(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_UNLINK:
        ret = sys_unlink(ctx, a0);
        break;
    case PPC32_NR_LSEEK:
        ret = sys_lseek(a0, a1, a2);
        break;
    case PPC32_NR_LLSEEK:
        ret = sys_llseek(ctx, a0, a1, a2, a3, a4);
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
    case PPC32_NR_MREMAP:
        /* P32-R9-3: the vm layer implements mremap; dispatch it so the
         * guest does not always see -ENOSYS. */
        ret = (long)(int32_t)ppc32_vm_mremap(ctx, a0, a1, a2, a3, a4);
        break;
    case PPC32_NR_UNAME:
        ret = sys_uname(ctx, a0);
        break;
    case PPC32_NR_STAT:
        ret = sys_stat_path(ctx, a0, a1, 0U, 0);
        break;
    case PPC32_NR_LSTAT:
        ret = sys_stat_path(ctx, a0, a1, 0U, 1);
        break;
    case PPC32_NR_FSTAT:
        ret = sys_fstat(ctx, a0, a1, 0U);
        break;
    case PPC32_NR_STAT64:
        ret = sys_stat_path(ctx, a0, a1, 1U, 0);
        break;
    case PPC32_NR_LSTAT64:
        ret = sys_stat_path(ctx, a0, a1, 1U, 1);
        break;
    case PPC32_NR_FSTAT64:
        ret = sys_fstat(ctx, a0, a1, 1U);
        break;
    case PPC32_NR_GETTIMEOFDAY:
        ret = sys_gettimeofday(ctx, a0);
        break;
    case PPC32_NR_CLOCK_GETTIME:
        ret = sys_clock_gettime(ctx, a0, a1, 0);
        break;
    case PPC32_NR_CLOCK_GETTIME64:
        ret = sys_clock_gettime(ctx, a0, a1, 1);
        break;
    case PPC32_NR_GETRANDOM:
        ret = sys_getrandom(ctx, a0, a1, a2);
        break;
    case PPC32_NR_FUTEX:
        ret = ppc32_futex(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case PPC32_NR_FCNTL:
    case PPC32_NR_FCNTL64:
        ret = sys_fcntl(ctx, a0, a1, a2);
        break;
    case PPC32_NR_FTRUNCATE:
        ret = sys_ftruncate(a0, a1);
        break;
    case PPC32_NR_IOCTL:
        ret = sys_ioctl(ctx, a0, a1, a2);
        break;
    case PPC32_NR_GETPID:
        ret = ppc32_proc_getpid();
        break;
    case PPC32_NR_KILL:
    case PPC32_NR_GETTID:
    case PPC32_NR_TKILL:
    case PPC32_NR_TGKILL:
        if (ppc32_sig_pid_nr(ctx, nr, a0, a1, a2, &ret)) {
            return;
        }
        break;
    case PPC32_NR_CLONE:
    {
        /* PPC clone arg order: flags, stack, parent_tid, tls,
         * child_tid in r3..r7. P32-R5-1 runs the CLONE_VM child
         * concurrently on a host pthread (threads.c runner) so
         * parent/child handshakes never deadlock. */
        /* Fork-style clone (no CLONE_VM): process semantics, e.g. the
         * BusyBox posix_spawn idiom SIGCHLD|CHILD_CLEARTID|CHILD_SETTID.
         * A host fork copies mm/files/fs exactly like fork(2); thread
         * semantics w/o an address space stay -EINVAL (kernel parity).
         * SETTID stores honored; CLEARTID clearing is best-effort. */
        if ((a0 & PPC32_CLONE_VM) == 0U) {
            long pid;

            if ((a0 & (PPC32_CLONE_THREAD | PPC32_CLONE_SIGHAND)) != 0U) {
                ret = -EINVAL;
                break;
            }
            /* P32-R10-6: validate TID addresses before the fork side
             * effect, mirroring the CLONE_VM path (write prot). */
            if ((a0 & PPC32_CLONE_PARENT_SETTID) != 0U && a2 != 0U &&
                !ppc32_vm_range_prot_ok(ctx, a2, 4U, 2U)) {
                ret = -EFAULT;
                break;
            }
            if ((a0 & PPC32_CLONE_CHILD_SETTID) != 0U && a4 != 0U &&
                !ppc32_vm_range_prot_ok(ctx, a4, 4U, 2U)) {
                ret = -EFAULT;
                break;
            }
            pid = ppc32_proc_fork(ctx);
            if (pid < 0L) {
                ret = pid;
                break;
            }
            if (pid == 0L) {
                if ((a0 & PPC32_CLONE_CHILD_SETTID) != 0U &&
                    a4 != 0U && ppc32_range_ok(a4, 4U)) {
                    ppc32_st32be(ctx, a4, ctx->guest_pid);
                }
                ret = 0L;
                break;
            }
            if ((a0 & PPC32_CLONE_PARENT_SETTID) != 0U &&
                a2 != 0U && ppc32_range_ok(a2, 4U)) {
                ppc32_st32be(ctx, a2, (uint32_t)pid);
            }
            ret = pid;
            break;
        }
        ppc32_ctx_t *child = NULL;
        long tid = ppc32_clone(ctx, a0, a1, a2, a3, a4, sys_clone_run,
            NULL, &child);

        if (tid < 0L) {
            ret = tid;
            break;
        }
        if (child == NULL) {
            ret = -EFAULT;
            break;
        }
        if (ctx->difftest) {
            (void)ppc32_thread_join((uint32_t)tid);
        }
        ret = tid;
        break;
    }
    case PPC32_NR_SIGPROCMASK:
        /* Old-style mask stays -ENOSYS; the rt_* path above owns it. */
        ret = -ENOSYS;
        break;
    case PPC32_NR_SET_TID_ADDRESS:
        ret = ppc32_set_tid_address(ctx, a0);
        break;
    default:
        ret = -ENOSYS;
        break;
    }

    sys_apply_ret(ctx, nr, ret);
    ctx->syscalls_executed++;
    ctx->nip += 4U;
    /* P32-R6-6: serve sibling-pended signals at every syscall boundary
     * (the frame captures post-sc nip); exiting threads skip it so a
     * pending bit cannot hijack exit/exit_group. */
    if (!ppc32_syscall_is_exit(nr)) {
        ppc32_sig_pump_pending(ctx);
    }
}
