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

#include "dbt/dbt.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/syscall_nr.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"
#include "vm/vm32.h"

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define DYN_PATH_MAX 4096U
/* The dyn layer and the file layer share one buffer capacity: every
 * host path buffer in syscalls_dyn.c/syscalls_file.c holds
 * PPC32_PATH_MAX bytes (see syscalls.h). */
_Static_assert(PPC32_PATH_MAX == DYN_PATH_MAX,
    "dyn/file path buffers must share one capacity");
#define DYN_RLIM_INFINITY 0xFFFFFFFFU
/* Linux statx(2) guest struct is 256 B, fixed UAPI layout (all fields
 * scalar, converted member-wise below). */
#define DYN_STATX_SIZE 256U
/* linux_dirent64 member offsets (arch-generic, same on host/guest). */
#define DYN_DENT_RECLEN_OFF 16U
#define DYN_DENT_NAME_OFF 19U

/* Device and kernel trees are host-owned: the dev, proc and sys trees
 * never materialize under the sysroot (cmd to dev-null must reach the
 * host null). proc-self synthetic paths are intercepted before this
 * helper runs, so pinning them to raw is safe here too. */
static int dyn_pinned_raw(const char *guest)
{
    if (guest == NULL || guest[0] != '/') {
        return 0;
    }
    if (strncmp(guest, "/dev/", 5U) == 0 || strcmp(guest, "/dev") == 0) {
        return 1;
    }
    if (strncmp(guest, "/proc/", 6U) == 0 || strcmp(guest, "/proc") == 0) {
        return 1;
    }
    if (strncmp(guest, "/sys/", 5U) == 0 || strcmp(guest, "/sys") == 0) {
        return 1;
    }
    return 0;
}

static void dyn_copy_raw(const char *guest, char *out)
{
    size_t i;

    for (i = 0U; guest[i] != '\0'; i++) {
        out[i] = guest[i];
    }
    out[i] = '\0';
}

/* True when the parent directory of the sysroot candidate exists:
 * /sysroot/a/b (missing) still stays under the sysroot when
 * /sysroot/a exists (git index.lock, creating opens), so a file
 * created in /var/tmp/x is unlinked/renamed at the same host path.
 * Returns 1 to stay, 0 to fall back to raw. */
static int dyn_parent_present(const char *sysroot_path)
{
    char parent[DYN_PATH_MAX];
    size_t n;
    size_t slash = 0U;
    size_t i;

    n = strlen(sysroot_path);
    for (i = 0U; i < n; i++) {
        if (sysroot_path[i] == '/') {
            slash = i;
        }
    }
    if (slash == 0U || slash + 1U >= sizeof parent) {
        return 0;
    }
    memcpy(parent, sysroot_path, slash);
    parent[slash] = '\0';
    if (parent[0] == '\0') {
        return 0;
    }
    return (access(parent, F_OK) == 0) ? 1 : 0;
}

/* Resolve a guest path VA to a host path (sysroot for absolute guest
 * paths, plain copy otherwise). Plain reads keep exists-or-raw
 * fallback: the sysroot candidate is used only when it exists
 * (lstat, so dangling symlinks still resolve in place); otherwise the
 * raw host path is used, so /etc/passwd, /usr/bin and
 * /usr/share/zoneinfo resolve under partial sysroots (qemu -L
 * parity). Pinned /dev|/proc|/sys always use raw. Returns 0 with
 * `out` filled, or a negative errno. */
long ppc32_path_resolve(ppc32_ctx_t *ctx, uint32_t path_va,
    char *out)
{
    char guest[DYN_PATH_MAX];
    struct stat st;

    if (ppc32_copyin_str(ctx, path_va, guest, sizeof guest) != 0) {
        return -EFAULT;
    }
    if (guest[0] != '/' || dyn_pinned_raw(guest)) {
        dyn_copy_raw(guest, out);
        return 0;
    }
    if (ppc32_sysroot_path(ctx, guest, out, DYN_PATH_MAX) != 0) {
        return -ENAMETOOLONG;
    }
    if (lstat(out, &st) != 0) {
        dyn_copy_raw(guest, out);
    }
    return 0;
}

/* Mutation-side resolution shared by creating opens (O_CREAT/O_TMPFILE)
 * and every filesystem mutation (unlink*, rmdir, mkdir*, rename*,
 * link*, symlink*, mknod*): the guest path stays under the sysroot
 * whenever its parent directory exists there, else the raw host path
 * is used. One rule for both directions, so a file created at
 * /sysroot/... is always unlinked/renamed at the exact same host
 * location. Pinned trees always go raw. */
long ppc32_path_resolve_mut(ppc32_ctx_t *ctx, uint32_t path_va,
    char *out)
{
    char guest[DYN_PATH_MAX];

    if (ppc32_copyin_str(ctx, path_va, guest, sizeof guest) != 0) {
        return -EFAULT;
    }
    if (guest[0] != '/' || dyn_pinned_raw(guest)) {
        dyn_copy_raw(guest, out);
        return 0;
    }
    if (ctx->sysroot == NULL || ctx->sysroot[0] == '\0') {
        dyn_copy_raw(guest, out);
        return 0;
    }
    if (ppc32_sysroot_path(ctx, guest, out, DYN_PATH_MAX) != 0) {
        return -ENAMETOOLONG;
    }
    if (access(out, F_OK) != 0 && !dyn_parent_present(out)) {
        dyn_copy_raw(guest, out);
    }
    return 0;
}

static long dyn_access(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char host[DYN_PATH_MAX];
    long rc = ppc32_path_resolve(ctx, path_va, host);

    if (rc != 0) {
        return rc;
    }
    /* R_OK/W_OK/X_OK/F_OK are Linux-generic: pass through. */
    if (access(host, (int)mode) != 0) {
        return -(long)errno;
    }
    return 0;
}

/* P32-R13-2: BE image helpers writing into a stack buffer (never
 * directly to guest memory). Shared by the Linux and fallback writers. */
static void dyn_buf16(uint8_t *b, uint32_t off, uint16_t v)
{
    uint16_t w = ppc32_be16(v);

    memcpy(b + off, &w, sizeof w);
}

static void dyn_buf32(uint8_t *b, uint32_t off, uint32_t v)
{
    uint32_t w = ppc32_be32(v);

    memcpy(b + off, &w, sizeof w);
}

static void dyn_buf64(uint8_t *b, uint32_t off, uint64_t v)
{
    uint64_t w = ppc32_be64(v);

    memcpy(b + off, &w, sizeof w);
}

#ifdef __linux__
/* Verify the host statx shape once: the member-wise converter below
 * addresses the 256 B UAPI layout by offset. */
_Static_assert(sizeof(struct statx) == DYN_STATX_SIZE,
    "host struct statx must be the 256 B UAPI layout");

static long dyn_put_statx(ppc32_ctx_t *ctx, uint32_t va,
    const struct statx *hs)
{
    uint8_t buf[DYN_STATX_SIZE];
    uint64_t mnt_id;

    memset(buf, 0, sizeof buf);
    memcpy(&mnt_id, (const unsigned char *)hs + 144U, sizeof mnt_id);
    dyn_buf32(buf, 0U, hs->stx_mask);
    dyn_buf32(buf, 4U, hs->stx_blksize);
    dyn_buf64(buf, 8U, hs->stx_attributes);
    dyn_buf32(buf, 16U, hs->stx_nlink);
    dyn_buf32(buf, 20U, hs->stx_uid);
    dyn_buf32(buf, 24U, hs->stx_gid);
    dyn_buf16(buf, 28U, hs->stx_mode);
    dyn_buf64(buf, 32U, hs->stx_ino);
    dyn_buf64(buf, 40U, hs->stx_size);
    dyn_buf64(buf, 48U, hs->stx_blocks);
    dyn_buf64(buf, 56U, hs->stx_attributes_mask);
    dyn_buf64(buf, 64U, (uint64_t)hs->stx_atime.tv_sec);
    dyn_buf32(buf, 72U, hs->stx_atime.tv_nsec);
    dyn_buf64(buf, 80U, (uint64_t)hs->stx_btime.tv_sec);
    dyn_buf32(buf, 88U, hs->stx_btime.tv_nsec);
    dyn_buf64(buf, 96U, (uint64_t)hs->stx_ctime.tv_sec);
    dyn_buf32(buf, 104U, hs->stx_ctime.tv_nsec);
    dyn_buf64(buf, 112U, (uint64_t)hs->stx_mtime.tv_sec);
    dyn_buf32(buf, 120U, hs->stx_mtime.tv_nsec);
    dyn_buf32(buf, 128U, hs->stx_rdev_major);
    dyn_buf32(buf, 132U, hs->stx_rdev_minor);
    dyn_buf32(buf, 136U, hs->stx_dev_major);
    dyn_buf32(buf, 140U, hs->stx_dev_minor);
    dyn_buf64(buf, 144U, mnt_id);
    /* P32-R13-2: checked write only (mapping + PROT_WRITE verified
     * before any guest byte changes; invalidates LL/SMC on success). */
    if (ppc32_vm_copyout_safe(ctx, va, buf, DYN_STATX_SIZE) != 0) {
        return -EFAULT;
    }
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
        {
            struct stat stb;

            if (lstat(host, &stb) != 0) {
                for (i = 0U; guest[i] != '\0'; i++) {
                    if (i + 1U >= sizeof host) {
                        return -ENAMETOOLONG;
                    }
                    host[i] = guest[i];
                }
                host[i] = '\0';
            }
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

/* Publish landed dirents: evict overlapping blocks, kill LL/SC, fan
 * out to staged aliases and shared files (same tail as dyn_getcwd). */
static void dyn_dents_landed(ppc32_ctx_t *ctx, uint32_t base, uint32_t n)
{
    ppc32_smc_store(ctx, base, n, NULL);
    vm32_store_invalidate_range(base, n);
    vm_file_shared_cohere_store(ctx, base, n);
}

/* Host getdents64 entries are LE; the guest linux_dirent64 has the
 * identical layout but big-endian scalars. The host chunk buffer is a
 * per-call stack array (no shared static: concurrent readers must not
 * share state); each entry is staged in a per-entry buffer and
 * published with one safe copyout, never raw guest stores. */
static long dyn_getdents64(ppc32_ctx_t *ctx, uint32_t fd, uint32_t dirp_va,
    uint32_t count)
{
    uint8_t host[8192U];
    uint32_t done = 0U;

    if (count == 0U) {
        return -EINVAL;
    }
    if (!ppc32_range_ok(dirp_va, count)) {
        return -EFAULT;
    }
    if (!ppc32_vm_range_prot_ok(ctx, dirp_va, count, 2U)) {
        return -EFAULT;
    }
    /* Guest counts exceed the staging buffer (BusyBox passes 32K):
     * refill per chunk; the fd position advances across host calls. */
    while (done < count) {
        uint32_t want = count - done;
        uint32_t off = 0U;
        long n;

        if (want > sizeof host) {
            want = sizeof host;
        }
        n = syscall(SYS_getdents64, (int)fd, host, (size_t)want);
        if (n < 0) {
            if (done > 0U) {
                dyn_dents_landed(ctx, dirp_va, done);
            }
            return done > 0U ? (long)done : -(long)errno;
        }
        if (n == 0) {
            break;
        }
        while (off + DYN_DENT_NAME_OFF <= (uint32_t)n) {
            uint64_t ino = 0ULL;
            uint64_t d_off = 0ULL;
            uint16_t reclen = 0U;
            uint8_t *ent;
            uint64_t be;
            uint32_t k;

            memcpy(&ino, host + off, sizeof ino);
            memcpy(&d_off, host + off + 8U, sizeof d_off);
            memcpy(&reclen, host + off + DYN_DENT_RECLEN_OFF,
                sizeof reclen);
            if (reclen < DYN_DENT_NAME_OFF + 1U ||
                off + reclen > (uint32_t)n ||
                done + reclen > count) {
                break;
            }
            ent = (uint8_t *)malloc(reclen);
            if (ent == NULL) {
                if (done > 0U) {
                    dyn_dents_landed(ctx, dirp_va, done);
                    return (long)done;
                }
                return -ENOMEM;
            }
            be = ppc32_be64(ino);
            memcpy(ent, &be, sizeof be);
            be = ppc32_be64(d_off);
            memcpy(ent + 8U, &be, sizeof be);
            ent[DYN_DENT_RECLEN_OFF] = (uint8_t)((reclen >> 8) & 0xFFU);
            ent[DYN_DENT_RECLEN_OFF + 1U] = (uint8_t)(reclen & 0xFFU);
            /* Type byte + name copy raw (single bytes have no
             * endianness). */
            for (k = DYN_DENT_RECLEN_OFF + 2U; k < (uint32_t)reclen;
                k++) {
                ent[k] = host[off + k];
            }
            if (ppc32_vm_copyout_safe(ctx, dirp_va + done, ent,
                    reclen) != 0) {
                free(ent);
                if (done > 0U) {
                    dyn_dents_landed(ctx, dirp_va, done);
                    return (long)done;
                }
                return -EFAULT;
            }
            free(ent);
            off += (uint32_t)reclen;
            done += (uint32_t)reclen;
        }
        if ((long)off < n) {
            break;
        }
    }
    if (done > 0U) {
        dyn_dents_landed(ctx, dirp_va, done);
    }
    return (long)done;
}
#else
/* Guest Linux AT_* bits (host <fcntl.h> may lack them, e.g. macOS has
 * no AT_EMPTY_PATH): test the guest value, pass the host macro. */
#define DYN_AT_EMPTY_PATH 0x1000U
#define DYN_AT_NOFOLLOW 0x100U
#define DYN_STATX_BASIC 0x7FFU

/* Non-Linux fallback: synthesize the 256 B statx image from struct stat
 * (ppc64rt x_fill_statx parity: mask reports exactly the basic stats,
 * dev split uses the Linux makedev encoding). The guest loader only
 * needs mode/size/type, but the full basic set is filled. */
static long dyn_put_stat_fallback(ppc32_ctx_t *ctx, uint32_t va,
    const struct stat *hs)
{
    int64_t sec;
    uint32_t nsec;
    uint64_t dev;
    uint32_t major;
    uint32_t minor;
    uint8_t buf[DYN_STATX_SIZE];

    memset(buf, 0, sizeof buf);
    dyn_buf32(buf, 0U, DYN_STATX_BASIC);
    dyn_buf32(buf, 4U, (uint32_t)hs->st_blksize);
    dyn_buf64(buf, 8U, 0ULL);
    dyn_buf32(buf, 16U, (uint32_t)hs->st_nlink);
    dyn_buf32(buf, 20U, (uint32_t)hs->st_uid);
    dyn_buf32(buf, 24U, (uint32_t)hs->st_gid);
    dyn_buf16(buf, 28U, (uint16_t)hs->st_mode);
    dyn_buf64(buf, 32U, (uint64_t)hs->st_ino);
    dyn_buf64(buf, 40U, (uint64_t)hs->st_size);
    dyn_buf64(buf, 48U, (uint64_t)hs->st_blocks);
    dyn_buf64(buf, 56U, 0ULL);
    /* P32-R13-9: atime/mtime/ctime via the shared convert helper;
     * btime stays local (Linux statx callers get zero here). */
    {
        int64_t at_s;
        int64_t mt_s;
        int64_t ct_s;
        uint32_t at_n;
        uint32_t mt_n;
        uint32_t ct_n;

        ppc32_host_stat_times(hs, &at_s, &at_n, &mt_s, &mt_n, &ct_s, &ct_n);
        dyn_buf64(buf, 64U, (uint64_t)at_s);
        dyn_buf32(buf, 72U, at_n);
        dyn_buf64(buf, 96U, (uint64_t)ct_s);
        dyn_buf32(buf, 104U, ct_n);
        dyn_buf64(buf, 112U, (uint64_t)mt_s);
        dyn_buf32(buf, 120U, mt_n);
    }
#if defined(__linux__)
    sec = 0;
    nsec = 0U;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    sec = (int64_t)hs->st_birthtimespec.tv_sec;
    nsec = (uint32_t)hs->st_birthtimespec.tv_nsec;
#else
    sec = 0;
    nsec = 0U;
#endif
    dyn_buf64(buf, 80U, (uint64_t)sec);
    dyn_buf32(buf, 88U, nsec);
    dev = (uint64_t)hs->st_rdev;
    major = (uint32_t)(((dev >> 8) & 0xFFFULL) | ((dev >> 32) & 0xFFFFF000ULL));
    minor = (uint32_t)((dev & 0xFFULL) | ((dev >> 12) & 0xFFFFFF00ULL));
    dyn_buf32(buf, 128U, major);
    dyn_buf32(buf, 132U, minor);
    dev = (uint64_t)hs->st_dev;
    major = (uint32_t)(((dev >> 8) & 0xFFFULL) | ((dev >> 32) & 0xFFFFF000ULL));
    minor = (uint32_t)((dev & 0xFFULL) | ((dev >> 12) & 0xFFFFFF00ULL));
    dyn_buf32(buf, 136U, major);
    dyn_buf32(buf, 140U, minor);
    dyn_buf64(buf, 144U, 0ULL);
    if (ppc32_vm_copyout_safe(ctx, va, buf, DYN_STATX_SIZE) != 0) {
        return -EFAULT;
    }
    return 0;
}

static long dyn_statx(ppc32_ctx_t *ctx, uint32_t dfd_va, uint32_t path_va,
    uint32_t flags, uint32_t mask, uint32_t buf_va)
{
    char host[DYN_PATH_MAX];
    struct stat hs;
    int nofollow;

    (void)mask;
    /* AT_EMPTY_PATH re-opens the dfd itself (ld.so stats its open
     * libc fd with an empty path): fstat the host fd directly. */
    if ((flags & DYN_AT_EMPTY_PATH) != 0U) {
        if (fstat((int)dfd_va, &hs) != 0) {
            return -(long)errno;
        }
        return dyn_put_stat_fallback(ctx, buf_va, &hs);
    }
    /* Absolute guest paths resolve against the sysroot; missing
     * entries fall back to the raw path (qemu -L parity). */
    {
        long rc = ppc32_path_resolve(ctx, path_va, host);

        if (rc != 0) {
            return rc;
        }
    }
    nofollow = (flags & DYN_AT_NOFOLLOW) != 0U ? AT_SYMLINK_NOFOLLOW : 0;
    if (fstatat(AT_FDCWD, host, &hs, nofollow) != 0) {
        return -(long)errno;
    }
    return dyn_put_stat_fallback(ctx, buf_va, &hs);
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
    const char *out = host;

    if (size == 0U || !ppc32_range_ok(buf_va, size)) {
        return -EFAULT;
    }
    if (!ppc32_vm_range_prot_ok(ctx, buf_va, size, 2U)) {
        return -EFAULT;
    }
    if (getcwd(host, sizeof host) == NULL) {
        return -(long)errno;
    }
    /* The guest namespace roots at the sysroot: a host cwd beneath it
     * is reported stripped ("/sysroot/tmp/x" -> "/tmp/x") so absolute
     * path round-trips (git's $cwd/.git, make's $(CURDIR)) re-resolve
     * under the sysroot instead of double-prefixing to
     * "/sysroot/sysroot/...". A cwd outside the sysroot passes through
     * (qemu -L parity for reads). The sysroot is canonicalized via
     * realpath so relative/symlinked/trailing-slash forms still match;
     * realpath failure falls back to the raw configured string. */
    if (ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char canon[DYN_PATH_MAX];
        const char *root = ctx->sysroot;
        size_t n;

        if (realpath(ctx->sysroot, canon) != NULL) {
            root = canon;
        }
        n = strlen(root);
        while (n > 1U && root[n - 1U] == '/') {
            n--;
        }
        if (strncmp(host, root, n) == 0 &&
            (host[n] == '/' || host[n] == '\0')) {
            out = (host[n] == '\0') ? "/" : host + n;
        }
    }
    {
        size_t len = strlen(out) + 1U;

        if (len > (size_t)size) {
            return -ERANGE;
        }
        if (ppc32_vm_copyout_safe(ctx, buf_va, out, len) != 0) {
            return -EFAULT;
        }
        ppc32_smc_store(ctx, buf_va, len, NULL);
        vm32_store_invalidate_range(buf_va, (uint32_t)len);
        vm_file_shared_cohere_store(ctx, buf_va, (uint32_t)len);
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
