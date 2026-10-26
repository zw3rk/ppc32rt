/*
 * src/os/syscalls_dyn.c — RC5 dynamic-loading syscall layer (Phase 5, L5b
 * escalation E3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the syscalls the Debian powerpc `ld.so`/`libc` startup and
 * BusyBox applets need beyond the static-libc layer (lane L5b inventory,
 * verified against the powerpc sysroot `asm/unistd_32.h`): statx(383,
 * first fatal gap in every shared-object load), access(33),
 * getrlimit(76)/ugetrlimit(190), getcwd(182), getdents64(202),
 * getuid(24)/geteuid(49)/getgid(47)/getegid(50), getppid(64).
 * `set_robust_list(300)` and `rseq(387)` stay -ENOSYS (glibc tolerates
 * both on a single thread).
 *
 * Absolute guest paths resolve against `ctx->sysroot` (RC5 E2) so the
 * sysroot's `/lib/ld.so.1` and `libc.so.6` are found; relative paths
 * pass through (guest cwd == host cwd in the qualification setup).
 * `ppc32_dyn_dispatch` mirrors the `ppc32_sig_syscall` hook shape: 1
 * with `*out_ret` set when the number is owned, 0 otherwise (the
 * caller applies the E01 convention and the sc advance). It takes the
 * full six-arg cell because `statx` is a five-argument call.
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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/syscall_nr.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define DYN_PATH_MAX 4096U
#define DYN_RLIM_INFINITY 0xFFFFFFFFU
/* Linux statx(2) guest struct is 256 B, fixed UAPI layout (all fields
 * scalar, converted member-wise below). */
#define DYN_STATX_SIZE 256U
/* linux_dirent64 member offsets (arch-generic, same on host/guest). */
#define DYN_DENT_RECLEN_OFF 16U
#define DYN_DENT_NAME_OFF 19U

/* Resolve a guest path VA to a host path (sysroot for absolute guest
 * paths, plain copy otherwise). Missing sysroot entries fall back to
 * the raw path (qemu -L parity). Returns 0 with `out` filled, or
 * a negative errno. */
static long dyn_resolve(ppc32_ctx_t *ctx, uint32_t path_va,
    char out[DYN_PATH_MAX])
{
    char guest[DYN_PATH_MAX];
    size_t i;

    if (ppc32_copyin_str(ctx, path_va, guest, sizeof guest) != 0) {
        return -EFAULT;
    }
    if (ppc32_sysroot_path(ctx, guest, out, DYN_PATH_MAX) != 0) {
        return -ENAMETOOLONG;
    }
    if (guest[0] == '/' && access(out, F_OK) != 0) {
        for (i = 0U; guest[i] != '\0'; i++) {
            if (i + 1U >= DYN_PATH_MAX) {
                return -ENAMETOOLONG;
            }
            out[i] = guest[i];
        }
        out[i] = '\0';
    }
    return 0;
}

static long dyn_access(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char host[DYN_PATH_MAX];
    long rc = dyn_resolve(ctx, path_va, host);

    if (rc != 0) {
        return rc;
    }
    /* R_OK/W_OK/X_OK/F_OK are Linux-generic: pass through. */
    if (access(host, (int)mode) != 0) {
        return -(long)errno;
    }
    return 0;
}

#ifdef __linux__
/* Verify the host statx shape once: the member-wise converter below
 * addresses the 256 B UAPI layout by offset. */
_Static_assert(sizeof(struct statx) == DYN_STATX_SIZE,
    "host struct statx must be the 256 B UAPI layout");

static long dyn_put_statx(ppc32_ctx_t *ctx, uint32_t va,
    const struct statx *hs)
{
    uint64_t mnt_id;

    if (!ppc32_range_ok(va, DYN_STATX_SIZE)) {
        return -EFAULT;
    }
    memcpy(&mnt_id, (const unsigned char *)hs + 144U, sizeof mnt_id);
    ppc32_st32be(ctx, va + 0U, hs->stx_mask);
    ppc32_st32be(ctx, va + 4U, hs->stx_blksize);
    ppc32_st64be(ctx, va + 8U, hs->stx_attributes);
    ppc32_st32be(ctx, va + 16U, hs->stx_nlink);
    ppc32_st32be(ctx, va + 20U, hs->stx_uid);
    ppc32_st32be(ctx, va + 24U, hs->stx_gid);
    ppc32_st16be(ctx, va + 28U, hs->stx_mode);
    ppc32_st64be(ctx, va + 32U, hs->stx_ino);
    ppc32_st64be(ctx, va + 40U, hs->stx_size);
    ppc32_st64be(ctx, va + 48U, hs->stx_blocks);
    ppc32_st64be(ctx, va + 56U, hs->stx_attributes_mask);
    ppc32_st64be(ctx, va + 64U, (uint64_t)hs->stx_atime.tv_sec);
    ppc32_st32be(ctx, va + 72U, hs->stx_atime.tv_nsec);
    ppc32_st64be(ctx, va + 80U, (uint64_t)hs->stx_btime.tv_sec);
    ppc32_st32be(ctx, va + 88U, hs->stx_btime.tv_nsec);
    ppc32_st64be(ctx, va + 96U, (uint64_t)hs->stx_ctime.tv_sec);
    ppc32_st32be(ctx, va + 104U, hs->stx_ctime.tv_nsec);
    ppc32_st64be(ctx, va + 112U, (uint64_t)hs->stx_mtime.tv_sec);
    ppc32_st32be(ctx, va + 120U, hs->stx_mtime.tv_nsec);
    ppc32_st32be(ctx, va + 128U, hs->stx_rdev_major);
    ppc32_st32be(ctx, va + 132U, hs->stx_rdev_minor);
    ppc32_st32be(ctx, va + 136U, hs->stx_dev_major);
    ppc32_st32be(ctx, va + 140U, hs->stx_dev_minor);
    ppc32_st64be(ctx, va + 144U, mnt_id);
    return 0;
}

static long dyn_statx(ppc32_ctx_t *ctx, uint32_t dfd_va, uint32_t path_va,
    uint32_t flags, uint32_t mask, uint32_t buf_va)
{
    char guest[DYN_PATH_MAX];
    char host[DYN_PATH_MAX];
    struct statx hs;
    int host_dfd;

    if (ppc32_copyin_str(ctx, path_va, guest, sizeof guest) != 0) {
        return -EFAULT;
    }
    if (ctx->trace_syscalls) {
        fprintf(stderr, "  statx path=%s\n", guest);
    }
    /* AT_EMPTY_PATH re-opens the dfd itself: an empty guest string stays
     * empty for the host call. Missing sysroot entries fall back to the
     * raw path (qemu -L parity). */
    if (guest[0] == '\0') {
        host[0] = '\0';
    } else {
        size_t i;

        if (ppc32_sysroot_path(ctx, guest, host, sizeof host) != 0) {
            return -ENAMETOOLONG;
        }
        if (access(host, F_OK) != 0) {
            for (i = 0U; guest[i] != '\0'; i++) {
                if (i + 1U >= sizeof host) {
                    return -ENAMETOOLONG;
                }
                host[i] = guest[i];
            }
            host[i] = '\0';
        }
    }
    host_dfd = (dfd_va == (uint32_t)(int32_t)-100) ? -100 : (int)dfd_va;
    /* AT_* flags and the mask are Linux-generic: pass through. */
    if (statx(host_dfd, host, (int)flags, (unsigned int)mask, &hs) !=
        0) {
        return -(long)errno;
    }
    return dyn_put_statx(ctx, buf_va, &hs);
}

/* Host getdents64 entries are LE; the guest linux_dirent64 has the
 * identical layout but big-endian scalars. Lengths match, so convert
 * in place from the host buffer into the guest window. */
static long dyn_getdents64(ppc32_ctx_t *ctx, uint32_t fd, uint32_t dirp_va,
    uint32_t count)
{
    static uint8_t heap[8192U];
    uint8_t *buf = heap;
    uint32_t done = 0U;

    if (count == 0U) {
        return -EINVAL;
    }
    if (!ppc32_range_ok(dirp_va, count)) {
        return -EFAULT;
    }
    /* Guest counts exceed the staging heap (BusyBox passes 32K): refill
     * per chunk; the fd position advances across host calls. */
    while (done < count) {
        uint32_t want = count - done;
        uint32_t off = 0U;
        long n;

        if (want > sizeof heap) {
            want = sizeof heap;
        }
        n = syscall(SYS_getdents64, (int)fd, buf, (size_t)want);
        if (n < 0) {
            return done > 0U ? (long)done : -(long)errno;
        }
        if (n == 0) {
            break;
        }
        while (off + DYN_DENT_NAME_OFF <= (uint32_t)n) {
            uint64_t ino = 0ULL;
            uint64_t d_off = 0ULL;
            uint16_t reclen = 0U;
            uint32_t k;

            memcpy(&ino, buf + off, sizeof ino);
            memcpy(&d_off, buf + off + 8U, sizeof d_off);
            memcpy(&reclen, buf + off + DYN_DENT_RECLEN_OFF,
                sizeof reclen);
            if (reclen < DYN_DENT_NAME_OFF + 1U ||
                off + reclen > (uint32_t)n ||
                done + reclen > count) {
                break;
            }
            ppc32_st64be(ctx, dirp_va + done, ino);
            ppc32_st64be(ctx, dirp_va + done + 8U, d_off);
            ppc32_st16be(ctx, dirp_va + done + DYN_DENT_RECLEN_OFF,
                reclen);
            /* Type byte + name copy raw (single bytes have no
             * endianness); reclen stays the big-endian word above. */
            for (k = DYN_DENT_RECLEN_OFF + 2U; k < (uint32_t)reclen;
                k++) {
                uint8_t b = buf[off + k];

                memcpy(ppc32_guest_ptr(ctx, dirp_va + done + k), &b, 1U);
            }
            off += (uint32_t)reclen;
            done += (uint32_t)reclen;
        }
        if ((long)off < n) {
            break;
        }
    }
    return (long)done;
}
#else
static long dyn_statx(ppc32_ctx_t *ctx, uint32_t dfd_va, uint32_t path_va,
    uint32_t flags, uint32_t mask, uint32_t buf_va)
{
    (void)ctx;
    (void)dfd_va;
    (void)path_va;
    (void)flags;
    (void)mask;
    (void)buf_va;
    return -ENOSYS;
}

static long dyn_getdents64(ppc32_ctx_t *ctx, uint32_t fd, uint32_t dirp_va,
    uint32_t count)
{
    (void)ctx;
    (void)fd;
    (void)dirp_va;
    (void)count;
    return -ENOSYS;
}
#endif

static long dyn_getcwd(ppc32_ctx_t *ctx, uint32_t buf_va, uint32_t size)
{
    char host[DYN_PATH_MAX];

    if (size == 0U || !ppc32_range_ok(buf_va, size)) {
        return -EFAULT;
    }
    if (getcwd(host, sizeof host) == NULL) {
        return -(long)errno;
    }
    {
        size_t len = strlen(host) + 1U;

        if (len > (size_t)size) {
            return -ERANGE;
        }
        memcpy(ppc32_guest_ptr(ctx, buf_va), host, len);
        /* Kernel-like length: bytes written including the NUL. */
        return (long)len;
    }
}

/* PPC32 rlimit is a u32 pair; clamp host u64 infinities to 0xFFFFFFFF. */
static long dyn_getrlimit(ppc32_ctx_t *ctx, uint32_t res, uint32_t rlim_va)
{
    struct rlimit hs;
    uint64_t cur;
    uint64_t max;

    if (getrlimit((int)res, &hs) != 0) {
        return -(long)errno;
    }
    if (!ppc32_range_ok(rlim_va, 8U)) {
        return -EFAULT;
    }
    cur = (uint64_t)hs.rlim_cur;
    max = (uint64_t)hs.rlim_max;
    ppc32_st32be(ctx, rlim_va,
        cur >= (uint64_t)DYN_RLIM_INFINITY ? DYN_RLIM_INFINITY :
        (uint32_t)cur);
    ppc32_st32be(ctx, rlim_va + 4U,
        max >= (uint64_t)DYN_RLIM_INFINITY ? DYN_RLIM_INFINITY :
        (uint32_t)max);
    return 0;
}

int ppc32_dyn_dispatch(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
    long *out_ret)
{
    long ret;

    if (ctx == NULL || out_ret == NULL) {
        return 0;
    }
    (void)a5;
    switch (nr) {
    case PPC32_NR_ACCESS:
        ret = dyn_access(ctx, a0, a1);
        break;
    case PPC32_NR_STATX:
        ret = dyn_statx(ctx, a0, a1, a2, a3, a4);
        break;
    case PPC32_NR_GETCWD:
        ret = dyn_getcwd(ctx, a0, a1);
        break;
    case PPC32_NR_GETRLIMIT:
    case PPC32_NR_UGETRLIMIT:
        ret = dyn_getrlimit(ctx, a0, a1);
        break;
    case PPC32_NR_GETDENTS64:
        ret = dyn_getdents64(ctx, a0, a1, a2);
        break;
    case PPC32_NR_GETUID:
        ret = (long)getuid();
        break;
    case PPC32_NR_GETEUID:
        ret = (long)geteuid();
        break;
    case PPC32_NR_GETGID:
        ret = (long)getgid();
        break;
    case PPC32_NR_GETEGID:
        ret = (long)getegid();
        break;
    case PPC32_NR_GETPPID:
        ret = (long)getppid();
        break;
    default:
        return 0;
    }
    *out_ret = ret;
    return 1;
}
