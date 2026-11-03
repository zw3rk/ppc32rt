/*
 * src/os/syscalls_file.c — File open/fcntl flag translation (RC5, E3 gaps)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PPC open-time flag bits (uapi/asm-powerpc/fcntl.h) differ from the
 * aarch64 host layout (arch/arm64 fcntl.h) in two positions: PPC
 * LARGEFILE is 0200000 where the host has DIRECT, and PPC DIRECT is
 * 0400000 where the host has LARGEFILE (DIRECTORY 040000 and NOFOLLOW
 * 0100000 match). Passing flags through untranslated makes BusyBox
 * `ls /` (which opens "/" with CLOEXEC|LARGEFILE|DIRECTORY|NONBLOCK)
 * fail with EINVAL on the host, where the oracle (qemu-ppc -cpu 750)
 * succeeds. Every open and file-status-flag crossing swaps those two
 * bits; all other bits are ABI-identical and pass through.
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <termios.h>
#endif

#include "os/convert.h"
#include "os/procfs.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

/* The two PPC/host open-flag bits that share positions but not meaning:
 * PPC LARGEFILE 0200000 sits where the host has DIRECT, and PPC DIRECT
 * 0400000 sits where the host has LARGEFILE. */
#define PPC_O_LARGEFILE 0x10000U
#define PPC_O_DIRECT 0x20000U
#define HOST_O_DIRECT 0x10000U
#define HOST_O_LARGEFILE 0x20000U

uint32_t ppc32_open_flags_ppc2host(uint32_t flags)
{
    uint32_t out;

    out = flags & (uint32_t)~(PPC_O_LARGEFILE | PPC_O_DIRECT);
    if ((flags & PPC_O_LARGEFILE) != 0U) {
        out |= HOST_O_LARGEFILE;
    }
    if ((flags & PPC_O_DIRECT) != 0U) {
        out |= HOST_O_DIRECT;
    }
    return out;
}

uint32_t ppc32_open_flags_host2ppc(uint32_t flags)
{
    uint32_t out;

    out = flags & (uint32_t)~(HOST_O_DIRECT | HOST_O_LARGEFILE);
    if ((flags & HOST_O_DIRECT) != 0U) {
        out |= PPC_O_DIRECT;
    }
    if ((flags & HOST_O_LARGEFILE) != 0U) {
        out |= PPC_O_LARGEFILE;
    }
    return out;
}

long sys_openat(ppc32_ctx_t *ctx, uint32_t dfd_va, uint32_t path_va,
    uint32_t flags, uint32_t mode)
{
    char path[PPC32_PATH_MAX];
    uint32_t host_flags;
    int host_dfd;
    int fd;

    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if (ctx->trace_syscalls) {
        fprintf(stderr, "  openat path=%s\n", path);
    }
    /* Phase 5 L5a: /proc/self/... opens serve synthetic translator state. */
    if (ppc32_procfs_kind(path) != PPC32_PROCFS_NONE) {
        return (long)ppc32_procfs_open(ctx, path);
    }
    host_flags = ppc32_open_flags_ppc2host(flags);
    /* RC5 E2: absolute guest paths resolve against the sysroot so the
     * sysroot's ld.so/libc are found; relative paths pass through
     * (guest cwd == host cwd in the qualification setup). Missing
     * sysroot entries fall back to the raw path (qemu -L parity: the
     * sysroot holds libc, not coreutils, so `ls`/`wc` resolve to the
     * host root and the shell uses its applets). */
    if (path[0] == '/') {
        char host[PPC32_PATH_MAX];

        if (ppc32_sysroot_path(ctx, path, host, sizeof host) == 0) {
            int saved;

            host_dfd = (dfd_va == (uint32_t)(int32_t)-100) ? AT_FDCWD :
                (int)dfd_va;
            fd = openat(host_dfd, host, (int)host_flags,
                (mode_t)(mode & 07777U));
            if (fd >= 0) {
                return (long)fd;
            }
            saved = errno;
            if (saved != ENOENT && saved != ENOTDIR) {
                return -(long)saved;
            }
        }
    }
    /* Guest AT_FDCWD (-100) maps to the host AT_FDCWD (-100 on Linux,
     * -2 on macOS); anything else is a guest fd (identity-mapped). */
    host_dfd = (dfd_va == (uint32_t)(int32_t)-100) ? AT_FDCWD : (int)dfd_va;
    fd = openat(host_dfd, path, (int)host_flags, (mode_t)(mode & 07777U));
    if (fd < 0) {
        return -(long)errno;
    }
    return (long)fd;
}

long sys_fcntl(ppc32_ctx_t *ctx, uint32_t fd, uint32_t cmd, uint32_t arg)
{
    /* F_* numbers used here are Linux-generic: pass through, except
     * file-status flags (F_SETFL in, F_GETFL out), whose O_DIRECT and
     * O_LARGEFILE bits trade places (see above). */
    switch (cmd) {
    case 0U: /* F_DUPFD */
    case 1U: /* F_GETFD */
    case 2U: /* F_SETFD */
    {
        int r = fcntl((int)fd, (int)cmd, (int)arg);

        if (r < 0) {
            return -(long)errno;
        }
        return (long)r;
    }
    case 3U: /* F_GETFL */
    {
        int r = fcntl((int)fd, (int)cmd);

        if (r < 0) {
            return -(long)errno;
        }
        return (long)(int)ppc32_open_flags_host2ppc((uint32_t)r);
    }
    case 4U: /* F_SETFL */
    {
        uint32_t host_arg = ppc32_open_flags_ppc2host(arg);
        int r = fcntl((int)fd, (int)cmd, (int)host_arg);

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
            return (errno == EDEADLK) ? -58L : -(long)errno;
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
    /* 64-bit lock layout (uapi asm-generic/fcntl.h: F_GETLK64 12,
     * F_SETLK64 13, F_SETLKW64 14). musl on 32-bit PPC routes every
     * lock command through these numbers with struct flock64, so the
     * plain 5/6/7 arms above never fire for musl guests. The host
     * numbers match (asm-generic on aarch64 too). */
    case 12U: /* F_GETLK64 */
    case 13U: /* F_SETLK64 */
    case 14U: /* F_SETLKW64 */
    {
#ifdef __linux__
        struct flock hs;
        int host_cmd;
        int r;

        if (cmd == 12U) {
            host_cmd = 5; /* F_GETLK */
        } else if (cmd == 13U) {
            host_cmd = 6; /* F_SETLK */
        } else {
            host_cmd = 7; /* F_SETLKW */
        }
        if (ppc32_flock64_from_guest(ctx, arg, &hs) != 0) {
            return -EFAULT;
        }
        r = fcntl((int)fd, host_cmd, &hs);
        if (r < 0) {
            return (errno == EDEADLK) ? -58L : -(long)errno;
        }
        if (cmd == 12U && ppc32_flock64_to_guest(ctx, arg, &hs) != 0) {
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

long sys_close(uint32_t fd)
{
    if (close((int)fd) != 0) {
        return -(long)errno;
    }
    return 0;
}

long sys_unlink(ppc32_ctx_t *ctx, uint32_t path_va)
{
    char path[PPC32_PATH_MAX];

    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if (unlink(path) != 0) {
        return -(long)errno;
    }
    return 0;
}

long sys_lseek(uint32_t fd, uint32_t offset, uint32_t whence)
{
    off_t r = lseek((int)fd, (off_t)(int32_t)offset, (int)whence);

    if (r == (off_t)-1) {
        return -(long)errno;
    }
    return (long)r;
}

/* Bonus (file I/O): ppc llseek(140) carries the 64-bit offset as a
 * high/low word pair and stores the result through a BE u64 pointer. */
long sys_llseek(ppc32_ctx_t *ctx, uint32_t fd, uint32_t hi,
    uint32_t lo, uint32_t res_va, uint32_t whence)
{
    uint64_t uoff = ((uint64_t)hi << 32U) | (uint64_t)lo;
    off_t r = lseek((int)fd, (off_t)(int64_t)uoff, (int)whence);

    if (r == (off_t)-1) {
        return -(long)errno;
    }
    if (!ppc32_range_ok(res_va, 8U)) {
        return -EFAULT;
    }
    ppc32_st64be(ctx, res_va, (uint64_t)(int64_t)r);
    return 0;
}

long sys_stat_path(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va,
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

long sys_fstat(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t use64)
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

long sys_ioctl(ppc32_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg_va)
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
