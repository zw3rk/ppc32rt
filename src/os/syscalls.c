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
 * field converts through os/convert.h. The guest O_* flag bits match
 * the host asm-generic values, so open flags pass through; clone and
 * rt_sigprocmask are -ENOSYS stubs (Phase 4 owns threads/signals).
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "os/syscalls.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/syscall_nr.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

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

/* Numbers absent from the frozen os/syscall_nr.h (powerpc syscall.tbl):
 * clock_gettime 246, openat 286, getrandom 359. Guarded so a future
 * header update wins. */
#ifndef PPC32_NR_CLOCK_GETTIME
#define PPC32_NR_CLOCK_GETTIME 246U
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

#define PPC32_PATH_MAX 4096U
#define PPC32_IOV_CHUNK 16U
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

static long sys_read(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    ssize_t n;

    if (count > 0U && !ppc32_range_ok(buf_va, count)) {
        return -EFAULT;
    }
    n = read((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    return host_ret(n, errno);
}

static long sys_write(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    ssize_t n;

    if (count > 0U && !ppc32_range_ok(buf_va, count)) {
        return -EFAULT;
    }
    n = write((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    return host_ret(n, errno);
}

/* Chunked vectored I/O: a fixed host iovec array (no VLA) walks the BE
 * guest array; partial transfers return the bytes moved so far. */
static long sys_vec(ppc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t count, int is_write)
{
    struct iovec hv[PPC32_IOV_CHUNK];
    uint64_t total = 0ULL;
    uint32_t done = 0U;

    if (count == 0U) {
        return 0;
    }
    if (count > PPC32_IOV_MAX) {
        return -EINVAL;
    }
    if (!ppc32_range_ok(iov_va, (size_t)count * sizeof(ppc32_iovec_t))) {
        return -EFAULT;
    }
    while (done < count) {
        uint32_t n = count - done;
        size_t want = 0U;
        ssize_t got;
        uint32_t j;

        if (n > PPC32_IOV_CHUNK) {
            n = PPC32_IOV_CHUNK;
        }
        for (j = 0U; j < n; j++) {
            uint32_t base = ppc32_ld32be(ctx, iov_va + (done + j) * 8U);
            uint32_t len = ppc32_ld32be(ctx, iov_va + (done + j) * 8U + 4U);

            if (len > 0U && !ppc32_range_ok(base, len)) {
                return total > 0ULL ? (long)total : -EFAULT;
            }
            hv[j].iov_base = ppc32_guest_ptr(ctx, base);
            hv[j].iov_len = (size_t)len;
            want += (size_t)len;
        }
        got = is_write ? writev((int)fd, hv, (int)n) : readv((int)fd, hv, (int)n);
        if (got < 0) {
            return total > 0ULL ? (long)total : -(long)errno;
        }
        total += (uint64_t)got;
        done += n;
        if ((uint64_t)got < (uint64_t)want) {
            break;
        }
    }
    return (long)total;
}

static long sys_openat(ppc32_ctx_t *ctx, uint32_t dfd_va, uint32_t path_va,
    uint32_t flags, uint32_t mode)
{
    char path[PPC32_PATH_MAX];
    int host_dfd;
    int fd;

    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    /* AT_FDCWD (-100) is ABI-identical; anything else is a guest fd. */
    host_dfd = (dfd_va == (uint32_t)(int32_t)-100) ? -100 : (int)dfd_va;
    fd = openat(host_dfd, path, (int)flags, (mode_t)(mode & 07777U));
    if (fd < 0) {
        return -(long)errno;
    }
    return (long)fd;
}

static long sys_close(uint32_t fd)
{
    if (close((int)fd) != 0) {
        return -(long)errno;
    }
    return 0;
}

static long sys_lseek(uint32_t fd, uint32_t offset, uint32_t whence)
{
    off_t r = lseek((int)fd, (off_t)(int32_t)offset, (int)whence);

    if (r == (off_t)-1) {
        return -(long)errno;
    }
    return (long)r;
}

/* Bonus (file I/O): ppc llseek(140) carries the 64-bit offset as a
 * high/low word pair and stores the result through a BE u64 pointer. */
static long sys_llseek(ppc32_ctx_t *ctx, uint32_t fd, uint32_t hi,
    uint32_t lo, uint32_t res_va, uint32_t whence)
{
    int64_t off = ((int64_t)(int32_t)hi << 32) | (int64_t)(uint64_t)lo;
    off_t r = lseek((int)fd, (off_t)off, (int)whence);

    if (r == (off_t)-1) {
        return -(long)errno;
    }
    if (!ppc32_range_ok(res_va, 8U)) {
        return -EFAULT;
    }
    ppc32_st64be(ctx, res_va, (uint64_t)(int64_t)r);
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
    uint8_t *buf;
    size_t i;
    size_t j;

    if (!ppc32_range_ok(buf_va, PPC32_UTS_FIELD * PPC32_UTS_FIELDS)) {
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

static long sys_stat_path(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va,
    uint32_t use64, int nofollow)
{
    char path[PPC32_PATH_MAX];
    struct stat hs;

    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if ((nofollow ? lstat(path, &hs) : stat(path, &hs)) != 0) {
        return -(long)errno;
    }
    if (use64 != 0U) {
        return (long)ppc32_put_stat64(ctx, buf_va, &hs);
    }
    return (long)ppc32_put_stat(ctx, buf_va, &hs);
}

static long sys_fstat(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t use64)
{
    struct stat hs;

    if (fstat((int)fd, &hs) != 0) {
        return -(long)errno;
    }
    if (use64 != 0U) {
        return (long)ppc32_put_stat64(ctx, buf_va, &hs);
    }
    return (long)ppc32_put_stat(ctx, buf_va, &hs);
}

static long sys_clock_gettime(ppc32_ctx_t *ctx, uint32_t clk, uint32_t ts_va)
{
    struct timespec ts;

    /* CLOCK_* ids are Linux-generic: pass through. */
    if (clock_gettime((clockid_t)clk, &ts) != 0) {
        return -(long)errno;
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
    ssize_t n;

    if (len > 0U && !ppc32_range_ok(buf_va, len)) {
        return -EFAULT;
    }
    /* GRND_* flag bits are Linux-generic: pass through. */
    n = getrandom(ppc32_guest_ptr(ctx, buf_va), (size_t)len, (unsigned int)flags);
    return host_ret(n, errno);
#else
    (void)ctx;
    (void)buf_va;
    (void)len;
    (void)flags;
    return -ENOSYS;
#endif
}

/* FUTEX_WAIT/FUTEX_WAKE (+PRIVATE variants): the guest window is host
 * memory, so the host futex operates on the guest address directly. The
 * WAIT comparator needs the raw little-endian word (the byte-reversed
 * image of the guest's big-endian value), which is exactly what a plain
 * memcpy yields — no ppc32_be32. Single-threaded until Phase 4 wires up
 * clone, so an unmatched WAIT can only return via timeout or signal. */
static long sys_futex(ppc32_ctx_t *ctx, uint32_t uaddr, uint32_t op,
    uint32_t val, uint32_t timeout_va)
{
#ifdef __linux__
    uint32_t base = op & ~((uint32_t)128U | (uint32_t)256U);
    int32_t *up;
    int32_t hval;
    struct timespec ts;
    struct timespec *tsp = NULL;
    long r;

    if (base != 0U && base != 1U) {
        return -ENOSYS;
    }
    if (!ppc32_range_ok(uaddr, 4U)) {
        return -EFAULT;
    }
    if (base == 0U && timeout_va != 0U) {
        if (ppc32_get_timespec(ctx, timeout_va, &ts) != 0) {
            return -EFAULT;
        }
        tsp = &ts;
    }
    up = (int32_t *)ppc32_guest_ptr(ctx, uaddr);
    memcpy(&hval, up, sizeof hval);
    /* WAIT compares memory against the raw LE word; WAKE takes the guest
     * count directly. */
    r = syscall(SYS_futex, up, (int)op,
        base == 0U ? hval : (int32_t)val, tsp, NULL, 0);
    if (r < 0) {
        return -(long)errno;
    }
    return r;
#else
    (void)ctx;
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout_va;
    return -ENOSYS;
#endif
}

static long sys_fcntl(ppc32_ctx_t *ctx, uint32_t fd, uint32_t cmd, uint32_t arg)
{
    /* F_* numbers used here are Linux-generic: pass through. */
    switch (cmd) {
    case 0U: /* F_DUPFD */
    case 1U: /* F_GETFD */
    case 3U: /* F_GETFL */
    case 2U: /* F_SETFD */
    case 4U: /* F_SETFL */
    {
        int r = fcntl((int)fd, (int)cmd, (int)arg);

        if (r < 0) {
            return -(long)errno;
        }
        return (long)r;
    }
#ifdef F_DUPFD_CLOEXEC
    case 1030U: /* F_DUPFD_CLOEXEC */
    {
        int r = fcntl((int)fd, F_DUPFD_CLOEXEC, (int)arg);

        if (r < 0) {
            return -(long)errno;
        }
        return (long)r;
    }
#endif
    case 5U: /* F_GETLK */
    case 6U: /* F_SETLK */
    case 7U: /* F_SETLKW */
    {
#ifdef __linux__
        struct flock hs;
        int r;

        if (ppc32_flock_from_guest(ctx, arg, &hs) != 0) {
            return -EFAULT;
        }
        r = fcntl((int)fd, (int)cmd, &hs);
        if (r < 0) {
            return -(long)errno;
        }
        if (cmd == 5U && ppc32_flock_to_guest(ctx, arg, &hs) != 0) {
            return -EFAULT;
        }
        return (long)r;
#else
        (void)ctx;
        (void)fd;
        (void)arg;
        return -ENOSYS;
#endif
    }
    default:
        break;
    }
    return -ENOSYS;
}

/* ioctl allowlist: only pure-status queries plus termios and winsize
 * cross the boundary; everything else takes -ENOSYS rather than leaking
 * host ioctls to the guest. The allowlisted request numbers are
 * asm-generic on Linux, so the guest values compare directly against
 * the host macros. */
static long sys_ioctl(ppc32_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg_va)
{
#ifdef __linux__
    switch (req) {
    case 0x5401U: /* TCGETS */
    {
        struct termios hs;

        if (ioctl((int)fd, TCGETS, &hs) != 0) {
            return -(long)errno;
        }
        return (long)ppc32_termios_to_guest(ctx, arg_va, &hs);
    }
    case 0x5402U: /* TCSETS */
    case 0x5403U: /* TCSETSW */
    case 0x5404U: /* TCSETSF */
    {
        struct termios hs;
        int kind = (req == 0x5402U) ? TCSANOW :
            (req == 0x5403U) ? TCSADRAIN : TCSAFLUSH;

        if (ppc32_termios_from_guest(ctx, arg_va, &hs) != 0) {
            return -EFAULT;
        }
        if (tcsetattr((int)fd, kind, &hs) != 0) {
            return -(long)errno;
        }
        return 0;
    }
    case 0x5413U: /* TIOCGWINSZ */
    {
        struct winsize hs;

        if (ioctl((int)fd, TIOCGWINSZ, &hs) != 0) {
            return -(long)errno;
        }
        return (long)ppc32_winsize_to_guest(ctx, arg_va, &hs);
    }
    case 0x5414U: /* TIOCSWINSZ */
    {
        struct winsize hs;

        if (ppc32_winsize_from_guest(ctx, arg_va, &hs) != 0) {
            return -EFAULT;
        }
        if (ioctl((int)fd, TIOCSWINSZ, &hs) != 0) {
            return -(long)errno;
        }
        return 0;
    }
    case 0x541BU: /* FIONREAD */
    {
        int n = 0;

        if (ioctl((int)fd, FIONREAD, &n) != 0) {
            return -(long)errno;
        }
        if (!ppc32_range_ok(arg_va, 4U)) {
            return -EFAULT;
        }
        ppc32_st32be(ctx, arg_va, (uint32_t)n);
        return 0;
    }
    default:
        break;
    }
    return -ENOSYS;
#else
    (void)ctx;
    (void)fd;
    (void)req;
    (void)arg_va;
    return -ENOSYS;
#endif
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
        ret = sys_clock_gettime(ctx, a0, a1);
        break;
    case PPC32_NR_GETRANDOM:
        ret = sys_getrandom(ctx, a0, a1, a2);
        break;
    case PPC32_NR_FUTEX:
        ret = sys_futex(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_FCNTL:
        ret = sys_fcntl(ctx, a0, a1, a2);
        break;
    case PPC32_NR_IOCTL:
        ret = sys_ioctl(ctx, a0, a1, a2);
        break;
    case PPC32_NR_CLONE:
        ret = -ENOSYS;
        break;
    case PPC32_NR_SIGPROCMASK:
    case PPC32_NR_RT_SIGPROCMASK:
        ret = -ENOSYS;
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
