/*
 * src/os/syscalls_fs.c — Filesystem mutation / *at syscalls (T1-T4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * chdir/fchdir, chmod/chown family, link/rename/mkdir/rmdir/symlink,
 * the *at variants (unlinkat, mkdirat, renameat(2), linkat, symlinkat,
 * fchmodat, fchownat, fstatat64, faccessat), utimensat(+_time64),
 * truncate64/ftruncate64, umask and sync. All numbers are arch/powerpc
 * 32-bit; mode bits are Linux-generic and pass through, while AT_*
 * flag bits translate on Darwin (Linux values pass through on Linux).
 * Reads resolve through ppc32_path_resolve (sysroot aware
 * with exists-or-raw fallback); every mutation resolves through the
 * shared ppc32_path_resolve_mut (parent-exists-in-sysroot stays) so one
 * guest directory never scatters across sysroot and host root
 * (T4 rename-dest containment).
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
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/convert.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

/* arch/powerpc unistd_32.h */
#define FS_NR_LINK 9U
#define FS_NR_CHDIR 12U
#define FS_NR_CHMOD 15U
#define FS_NR_LCHOWN 16U
#define FS_NR_SYNC 36U
#define FS_NR_RENAME 38U
#define FS_NR_MKDIR 39U
#define FS_NR_RMDIR 40U
#define FS_NR_UMASK 60U
#define FS_NR_SYMLINK 83U
#define FS_NR_TRUNCATE 92U
#define FS_NR_FCHMOD 94U
#define FS_NR_FCHOWN 95U
#define FS_NR_FSYNC 118U
#define FS_NR_FCHDIR 133U
#define FS_NR_FDATASYNC 148U
#define FS_NR_CHOWN 181U
#define FS_NR_TRUNCATE64 193U
#define FS_NR_FTRUNCATE64 194U
#define FS_NR_MKDIRAT 287U
#define FS_NR_FCHOWNAT 289U
#define FS_NR_FSTATAT64 291U
#define FS_NR_UNLINKAT 292U
#define FS_NR_RENAMEAT 293U
#define FS_NR_LINKAT 294U
#define FS_NR_SYMLINKAT 295U
#define FS_NR_FCHMODAT 297U
#define FS_NR_FACCESSAT 298U
#define FS_NR_UTIMENSAT 304U
#define FS_NR_RENAMEAT2 357U
#define FS_NR_UTIMENSAT64 412U
#define FS_NR_FACCESSAT2 439U

#define FS_AT_FDCWD (-100)

static int fs_dfd(uint32_t v)
{
    return ((int32_t)v == FS_AT_FDCWD) ? AT_FDCWD : (int)v;
}

static long fs_rc(int r)
{
    if (r >= 0) {
        return (long)r;
    }
    return -(long)ppc32_errno_map(errno);
}

/* Guest Linux AT_* bits vs host: Linux-generic on __linux__, translated
 * on Darwin (NOFOLLOW 0x100->0x20, FOLLOW 0x400->0x40, REMOVEDIR/EACCESS
 * 0x200->0x80/0x10 per call site, EMPTY_PATH 0x1000 dropped). */
static int fs_at_common(uint32_t g)
{
#ifdef __APPLE__
    int h = 0;

    if ((g & 0x100U) != 0U) {
        h |= 0x20;
    }
    if ((g & 0x400U) != 0U) {
        h |= 0x40;
    }
    return h;
#else
    return (int)g;
#endif
}

static int fs_at_unlink(uint32_t g)
{
#ifdef __APPLE__
    int h = fs_at_common(g);

    if ((g & 0x200U) != 0U) {
        h |= 0x80;
    }
    return h;
#else
    return (int)g;
#endif
}

static int fs_at_access(uint32_t g)
{
#ifdef __APPLE__
    int h = 0;

    if ((g & 0x100U) != 0U) {
        h |= 0x20;
    }
    if ((g & 0x200U) != 0U) {
        h |= 0x10;
    }
    if ((g & 0x400U) != 0U) {
        h |= 0x40;
    }
    return h;
#else
    return (int)g;
#endif
}

/* Resolve a guest path, then run `op`-style calls below on it. The
 * read-side resolver keeps the missing-entry raw fallback (qemu -L
 * parity for reads). */
static long fs_path(ppc32_ctx_t *ctx, uint32_t va, char *out)
{
    if (va == 0U) {
        return -EFAULT;
    }
    return ppc32_path_resolve(ctx, va, out);
}

/* Mutation-side single path (create/replace/remove): the shared
 * parent-exists rule (ppc32_path_resolve_mut) so one guest directory
 * never scatters across sysroot and host root (T4 containment). */
static long fs_mpath(ppc32_ctx_t *ctx, uint32_t va, char *out)
{
    if (va == 0U) {
        return -EFAULT;
    }
    return ppc32_path_resolve_mut(ctx, va, out);
}

/* Two-path helper for the link/rename families (both ends mutate, so
 * both resolve without the read-side fallback). */
static long fs_path2(ppc32_ctx_t *ctx, uint32_t a, uint32_t b, char *pa,
    char *pb)
{
    long rc = fs_mpath(ctx, a, pa);

    return (rc != 0L) ? rc : fs_mpath(ctx, b, pb);
}

/* True when the guest string at va is present and empty (""). A bad
 * pointer yields 0 so the normal resolver reports the fault. */
static int fs_guest_empty(ppc32_ctx_t *ctx, uint32_t va)
{
    char b = '\0';

    if (va == 0U) {
        return 0;
    }
    if (ppc32_copyin(ctx, va, &b, 1U) != 0) {
        return 0;
    }
    return (b == '\0') ? 1 : 0;
}

static long fs_utimens(ppc32_ctx_t *ctx, uint32_t dfd, uint32_t path_va,
    uint32_t times_va, uint32_t flags, int wide)
{
    char path[PPC32_PATH_MAX];
    struct timespec ts[2];
    long rc;
    int i;

    if (times_va != 0U) {
        for (i = 0; i < 2; i++) {
            if (wide != 0) {
                /* 32-bit big-endian userland struct __timespec64:
                 * tv_sec is 64-bit, tv_nsec is 32-bit at off + 12
                 * (off + 8 is uninitialized padding). UTIME_NOW and
                 * UTIME_OMIT are 0x3fffffff/0x3ffffffe on Linux. */
                uint32_t off = times_va + (uint32_t)i * 16U;
                uint32_t nsec32;

                if (!ppc32_range_ok(off, 16U) ||
                    !ppc32_vm_range_prot_ok(ctx, off, 16U, 1U)) {
                    return -EFAULT;
                }
                ts[i].tv_sec = (time_t)(int64_t)ppc32_ld64be(ctx, off);
                nsec32 = ppc32_ld32be(ctx, off + 12U);
                if (nsec32 != 0x3fffffffU && nsec32 != 0x3ffffffeU &&
                    nsec32 >= 1000000000U) {
                    return -EINVAL;
                }
#ifdef __APPLE__
                /* Darwin encodes the sentinels as -1/-2. */
                if (nsec32 == 0x3fffffffU) {
                    ts[i].tv_nsec = (long)-1;
                } else if (nsec32 == 0x3ffffffeU) {
                    ts[i].tv_nsec = (long)-2;
                } else {
                    ts[i].tv_nsec = (long)nsec32;
                }
#else
                ts[i].tv_nsec = (long)nsec32;
#endif
            } else {
                /* 32-bit timespec: BE tv_sec followed by BE tv_nsec.
                 * UTIME_NOW/OMIT sentinels map to the host spellings
                 * (Darwin -1/-2); any other tv_nsec outside
                 * [0, 999999999] is -EINVAL, matching the wide arm. */
                uint32_t off = times_va + (uint32_t)i * 8U;
                uint32_t nsec32;

                if (!ppc32_range_ok(off, 8U) ||
                    !ppc32_vm_range_prot_ok(ctx, off, 8U, 1U)) {
                    return -EFAULT;
                }
                ts[i].tv_sec = (time_t)(int32_t)ppc32_ld32be(ctx, off);
                nsec32 = ppc32_ld32be(ctx, off + 4U);
                if (nsec32 != 0x3fffffffU && nsec32 != 0x3ffffffeU &&
                    nsec32 >= 1000000000U) {
                    return -EINVAL;
                }
#ifdef __APPLE__
                if (nsec32 == 0x3fffffffU) {
                    ts[i].tv_nsec = (long)-1;
                } else if (nsec32 == 0x3ffffffeU) {
                    ts[i].tv_nsec = (long)-2;
                } else {
                    ts[i].tv_nsec = (long)nsec32;
                }
#else
                ts[i].tv_nsec = (long)nsec32;
#endif
            }
        }
    }
    /* AT_EMPTY_PATH with "": operate on dfd itself (glibc fstat-style
     * O_PATH use, tar/touch -a/-m, cp -p). Skip path resolution. */
    if ((flags & 0x1000U) != 0U && fs_guest_empty(ctx, path_va)) {
        return fs_rc(futimens(fs_dfd(dfd), times_va != 0U ? ts : NULL));
    }
    if (path_va == 0U) {
        return fs_rc(futimens(fs_dfd(dfd), times_va != 0U ? ts : NULL));
    }
    rc = fs_mpath(ctx, path_va, path);
    if (rc != 0L) {
        return rc;
    }
    return fs_rc(utimensat(fs_dfd(dfd), path, times_va != 0U ? ts : NULL,
        fs_at_common(flags)));
}

static long fs_fstatat64(ppc32_ctx_t *ctx, uint32_t dfd, uint32_t path_va,
    uint32_t buf_va, uint32_t flags)
{
    char path[PPC32_PATH_MAX];
    struct stat st;
    long rc;

    /* AT_EMPTY_PATH with "": stat dfd itself (32-bit glibc implements
     * fstat64 as fstatat64(fd, "", buf, AT_EMPTY_PATH)). */
    if ((flags & 0x1000U) != 0U && fs_guest_empty(ctx, path_va)) {
        if (fstat(fs_dfd(dfd), &st) != 0) {
            return -(long)ppc32_errno_map(errno);
        }
        return (ppc32_put_stat64(ctx, buf_va, &st) == 0) ? 0L : -EFAULT;
    }
    rc = fs_path(ctx, path_va, path);
    if (rc != 0L) {
        return rc;
    }
    if (fstatat(fs_dfd(dfd), path, &st, fs_at_common(flags)) != 0) {
        return -(long)ppc32_errno_map(errno);
    }
    return (ppc32_put_stat64(ctx, buf_va, &st) == 0) ? 0L : -EFAULT;
}

static long fs_dispatch_paths(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, int *owned)
{
    char p1[PPC32_PATH_MAX];
    char p2[PPC32_PATH_MAX];
    long rc;

    *owned = 1;
    switch (nr) {
    case FS_NR_CHDIR:
        rc = fs_path(ctx, a0, p1);
        return (rc != 0L) ? rc : fs_rc(chdir(p1));
    case FS_NR_CHMOD:
        rc = fs_mpath(ctx, a0, p1);
        return (rc != 0L) ? rc : fs_rc(chmod(p1, (mode_t)(a1 & 07777U)));
    case FS_NR_CHOWN:
    case FS_NR_LCHOWN:
        rc = fs_mpath(ctx, a0, p1);
        if (rc != 0L) {
            return rc;
        }
        return fs_rc((nr == FS_NR_CHOWN ? chown : lchown)(p1, (uid_t)a1,
            (gid_t)a2));
    case FS_NR_MKDIR:
        rc = fs_mpath(ctx, a0, p1);
        return (rc != 0L) ? rc : fs_rc(mkdir(p1, (mode_t)(a1 & 07777U)));
    case FS_NR_RMDIR:
        rc = fs_mpath(ctx, a0, p1);
        return (rc != 0L) ? rc : fs_rc(rmdir(p1));
    case FS_NR_TRUNCATE:
        rc = fs_mpath(ctx, a0, p1);
        return (rc != 0L) ? rc : fs_rc(truncate(p1, (off_t)(int32_t)a1));
    case FS_NR_TRUNCATE64:
        /* 32-bit PPC passes the 64-bit length in an aligned pair
         * (r3 path, r4 pad, r5 hi, r6 lo). */
        rc = fs_mpath(ctx, a0, p1);
        return (rc != 0L) ? rc : fs_rc(truncate(p1,
            (off_t)(int64_t)(((uint64_t)a2 << 32U) | a3)));
    case FS_NR_LINK:
    case FS_NR_RENAME:
        rc = fs_path2(ctx, a0, a1, p1, p2);
        if (rc != 0L) {
            return rc;
        }
        return fs_rc(nr == FS_NR_LINK ? link(p1, p2) : rename(p1, p2));
    case FS_NR_SYMLINK:
        /* The link target is stored verbatim (not sysroot mapped). */
        if (ppc32_copyin_str(ctx, a0, p1, sizeof p1) != 0) {
            return -EFAULT;
        }
        rc = fs_mpath(ctx, a1, p2);
        return (rc != 0L) ? rc : fs_rc(symlink(p1, p2));
    case FS_NR_MKDIRAT:
        rc = fs_mpath(ctx, a1, p1);
        return (rc != 0L) ? rc : fs_rc(mkdirat(fs_dfd(a0), p1,
            (mode_t)(a2 & 07777U)));
    case FS_NR_UNLINKAT:
        rc = fs_mpath(ctx, a1, p1);
        return (rc != 0L) ? rc :
            fs_rc(unlinkat(fs_dfd(a0), p1, fs_at_unlink(a2)));
    case FS_NR_FCHMODAT:
        /* Guest fchmodat is a 3-argument call: the 4th register (a3)
         * is caller garbage, never flags (fchmodat2/452 owns flags). */
        (void)a3;
        rc = fs_mpath(ctx, a1, p1);
        return (rc != 0L) ? rc : fs_rc(fchmodat(fs_dfd(a0), p1,
            (mode_t)(a2 & 07777U), 0));
    case FS_NR_FACCESSAT:
        /* Guest faccessat is a 3-argument call: a3 is caller garbage
         * (faccessat2/439 owns flags; see below). */
        (void)a3;
        rc = fs_path(ctx, a1, p1);
        return (rc != 0L) ? rc : fs_rc(faccessat(fs_dfd(a0), p1, (int)a2,
            0));
    case FS_NR_FACCESSAT2:
        rc = fs_path(ctx, a1, p1);
        return (rc != 0L) ? rc : fs_rc(faccessat(fs_dfd(a0), p1, (int)a2,
            fs_at_access(a3)));
    case FS_NR_FCHOWNAT:
        /* AT_EMPTY_PATH with "": chown dfd itself, no resolution. */
        if ((a4 & 0x1000U) != 0U && fs_guest_empty(ctx, a1)) {
            return fs_rc(fchown(fs_dfd(a0), (uid_t)a2, (gid_t)a3));
        }
        rc = fs_mpath(ctx, a1, p1);
        return (rc != 0L) ? rc : fs_rc(fchownat(fs_dfd(a0), p1, (uid_t)a2,
            (gid_t)a3, fs_at_common(a4)));
    case FS_NR_RENAMEAT:
    case FS_NR_RENAMEAT2:
        rc = fs_path2(ctx, a1, a3, p1, p2);
        if (rc != 0L) {
            return rc;
        }
#ifdef __linux__
        if (nr == FS_NR_RENAMEAT2 && a4 != 0U) {
            return fs_rc((int)syscall(SYS_renameat2, fs_dfd(a0), p1,
                fs_dfd(a2), p2, a4));
        }
#else
        if (nr == FS_NR_RENAMEAT2 && a4 != 0U) {
            /* Linux -ENOSYS (38): raw Darwin ENOSYS (78) would decode
             * as EREMCHG in the guest. */
            return -(long)ppc32_errno_map(ENOSYS);
        }
#endif
        return fs_rc(renameat(fs_dfd(a0), p1, fs_dfd(a2), p2));
    case FS_NR_LINKAT:
        /* linkat(olddfd, old, newdfd, new, flags) */
        rc = fs_path2(ctx, a1, a3, p1, p2);
        if (rc != 0L) {
            return rc;
        }
        return fs_rc(linkat(fs_dfd(a0), p1, fs_dfd(a2), p2,
            fs_at_common(a4)));
    case FS_NR_SYMLINKAT:
        if (ppc32_copyin_str(ctx, a0, p1, sizeof p1) != 0) {
            return -EFAULT;
        }
        rc = fs_mpath(ctx, a2, p2);
        return (rc != 0L) ? rc : fs_rc(symlinkat(p1, fs_dfd(a1), p2));
    default:
        *owned = 0;
        return 0L;
    }
}

int ppc32_fs_dispatch(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
    long *out_ret)
{
    long ret;
    int owned = 0;

    (void)a5;
    if (ctx == NULL || out_ret == NULL) {
        return 0;
    }
    switch (nr) {
    case FS_NR_FCHDIR:
        ret = fs_rc(fchdir((int)a0));
        break;
    case FS_NR_FCHMOD:
        ret = fs_rc(fchmod((int)a0, (mode_t)(a1 & 07777U)));
        break;
    case FS_NR_FCHOWN:
        ret = fs_rc(fchown((int)a0, (uid_t)a1, (gid_t)a2));
        break;
    case FS_NR_FTRUNCATE64:
        ret = fs_rc(ftruncate((int)a0,
            (off_t)(int64_t)(((uint64_t)a2 << 32U) | a3)));
        break;
    case FS_NR_FSYNC:
    case FS_NR_FDATASYNC:
        ret = fs_rc(fsync((int)a0));
        break;
    case FS_NR_SYNC:
        sync();
        ret = 0L;
        break;
    case FS_NR_UMASK:
        ret = (long)umask((mode_t)(a0 & 0777U));
        break;
    case FS_NR_FSTATAT64:
        ret = fs_fstatat64(ctx, a0, a1, a2, a3);
        break;
    case FS_NR_UTIMENSAT:
        ret = fs_utimens(ctx, a0, a1, a2, a3, 0);
        break;
    case FS_NR_UTIMENSAT64:
        ret = fs_utimens(ctx, a0, a1, a2, a3, 1);
        break;
    default:
        ret = fs_dispatch_paths(ctx, nr, a0, a1, a2, a3, a4, &owned);
        if (owned == 0) {
            return 0;
        }
        break;
    }
    *out_ret = ret;
    return 1;
}
