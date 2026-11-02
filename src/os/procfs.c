/*
 * src/os/procfs.c — Synthetic /proc/self/... content builders for ppc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 5, lane L5a: content for /proc/self/{exe,maps,cmdline,stat,auxv}
 * from translator state. cmdline joins the guest argv with NULs, maps
 * renders one line per tracked region, stat is a minimal single-line
 * status, auxv re-emits the exact auxv bytes handed to the guest
 * (big-endian on the wire). Content files are served on a seekable
 * anonymous fd (memfd on Linux, unlinked mkstemp fallback); exe opens
 * the guest executable itself so reads see ELF bytes, while readlink
 * reports the guest path (symlink semantics).
 */

#define _GNU_SOURCE
#include "os/procfs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/convert.h"
#include "rt32/ppc32.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define PROCFS_PATH_MAX 4096U
#define PROCFS_BIG_MAX (256U * 1024U)
#define PROCFS_SMALL_MAX 4096U
#define PROCFS_COMM_MAX 64U

int ppc32_procfs_kind(const char *path)
{
    if (path == NULL) {
        return PPC32_PROCFS_NONE;
    }
    if (strcmp(path, "/proc/self/exe") == 0) {
        return PPC32_PROCFS_EXE;
    }
    if (strcmp(path, "/proc/self/maps") == 0) {
        return PPC32_PROCFS_MAPS;
    }
    if (strcmp(path, "/proc/self/cmdline") == 0) {
        return PPC32_PROCFS_CMDLINE;
    }
    if (strcmp(path, "/proc/self/stat") == 0) {
        return PPC32_PROCFS_STAT;
    }
    if (strcmp(path, "/proc/self/auxv") == 0) {
        return PPC32_PROCFS_AUXV;
    }
    return PPC32_PROCFS_NONE;
}

/* Guest argv joined with NUL separators (Linux cmdline layout). */
static long build_cmdline(const ppc32_ctx_t *ctx, char *buf, size_t bufsz,
    size_t *out_len)
{
    size_t total = 0U;
    int i;

    if (ctx == NULL || ctx->guest_argv == NULL || ctx->guest_argc < 1) {
        return -ENOENT;
    }
    for (i = 0; i < ctx->guest_argc; i++) {
        const char *a = ctx->guest_argv[i];
        size_t n;

        if (a == NULL) {
            break;
        }
        n = strlen(a) + 1U;
        if (total + n > bufsz) {
            return -ENAMETOOLONG;
        }
        memcpy(buf + total, a, n);
        total += n;
    }
    *out_len = total;
    return 0;
}

/* One Linux-style maps line per tracked region. Offset/dev/inode are
 * synthetic (0, 00:00, 0); perms derive from the region prot bits. */
static long build_maps(const ppc32_ctx_t *ctx, char *buf, size_t bufsz,
    size_t *out_len)
{
    size_t total = 0U;
    size_t i;
    size_t count;

    if (ctx == NULL) {
        return -EFAULT;
    }
    count = ctx->region_count;
    if (count > PPC32_MAX_REGIONS) {
        count = PPC32_MAX_REGIONS;
    }
    for (i = 0U; i < count; i++) {
        const ppc32_region_t *r = &ctx->regions[i];
        char perms[5];
        int n;

        if (r->end <= r->start) {
            continue;
        }
        perms[0] = ((r->prot & (uint32_t)PROT_READ) != 0U) ? 'r' : '-';
        perms[1] = ((r->prot & (uint32_t)PROT_WRITE) != 0U) ? 'w' : '-';
        perms[2] = ((r->prot & (uint32_t)PROT_EXEC) != 0U) ? 'x' : '-';
        perms[3] = 'p';
        perms[4] = '\0';
        if (r->name[0] != '\0') {
            n = snprintf(buf + total, bufsz - total,
                "%08x-%08x %s %08x 00:00 0 %s\n",
                (unsigned int)r->start, (unsigned int)r->end, perms,
                0U, r->name);
        } else {
            n = snprintf(buf + total, bufsz - total,
                "%08x-%08x %s %08x 00:00 0\n",
                (unsigned int)r->start, (unsigned int)r->end, perms,
                0U);
        }
        if (n < 0) {
            return -EIO;
        }
        if ((size_t)n >= bufsz - total) {
            return -ENAMETOOLONG;
        }
        total += (size_t)n;
    }
    *out_len = total;
    return 0;
}

/* Minimal single-line stat: pid (comm) state plus zeroed numeric tail.
 * Only the shape is emulated; counters are not tracked. */
static long build_stat(const ppc32_ctx_t *ctx, char *buf, size_t bufsz,
    size_t *out_len)
{
    uint32_t pid;
    const char *src = NULL;
    const char *base;
    char comm[PROCFS_COMM_MAX];
    size_t ci = 0U;
    size_t bi;
    int n;

    if (ctx == NULL) {
        return -EFAULT;
    }
    pid = (ctx->guest_pid != 0U) ? ctx->guest_pid : (uint32_t)getpid();
    if (ctx->exec_path != NULL) {
        src = ctx->exec_path;
    } else if (ctx->guest_argv != NULL && ctx->guest_argc > 0) {
        src = ctx->guest_argv[0];
    }
    base = (src != NULL) ? src : "ppc32rt";
    for (bi = 0U; base[bi] != '\0'; bi++) {
        /* Terminal token: the last path component. */
        if (base[bi] == '/') {
            ci = 0U;
            continue;
        }
        if (ci + 1U < sizeof comm) {
            char c = base[bi];

            if (c == ')' || c == '\n') {
                c = '?';
            }
            comm[ci] = c;
            ci++;
        }
    }
    comm[ci] = '\0';
    if (ci == 0U) {
        comm[0] = '?';
        comm[1] = '\0';
    }
    n = snprintf(buf, bufsz,
        "%u (%s) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        (unsigned int)pid, comm);
    if (n < 0) {
        return -EIO;
    }
    if ((size_t)n >= bufsz) {
        return -ENAMETOOLONG;
    }
    *out_len = (size_t)n;
    return 0;
}

/* The exact auxv words handed to the guest, re-emitted big-endian. */
static long build_auxv(const ppc32_ctx_t *ctx, char *buf, size_t bufsz,
    size_t *out_len)
{
    size_t i;
    size_t words;

    if (ctx == NULL || ctx->auxv_bytes == 0U) {
        return -ENOENT;
    }
    if ((ctx->auxv_bytes % 8U) != 0U) {
        return -EIO;
    }
    if (ctx->auxv_bytes > bufsz) {
        return -ENAMETOOLONG;
    }
    words = ctx->auxv_bytes / sizeof(uint32_t);
    if (words > sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0])) {
        return -EIO;
    }
    for (i = 0U; i < words; i++) {
        uint32_t w = ctx->auxv_data[i];

        buf[4U * i]     = (char)(w >> 24);
        buf[4U * i + 1] = (char)((w >> 16) & 0xFFU);
        buf[4U * i + 2] = (char)((w >> 8) & 0xFFU);
        buf[4U * i + 3] = (char)(w & 0xFFU);
    }
    *out_len = ctx->auxv_bytes;
    return 0;
}

/* Serve a byte string on a seekable anonymous fd positioned at 0. */
static int serve_bytes(const char *tag, const void *data, size_t len)
{
#ifdef __linux__
    {
        int fd = memfd_create(tag, MFD_CLOEXEC);

        if (fd >= 0) {
            const char *p = (const char *)data;
            size_t done = 0U;

            while (done < len) {
                ssize_t n = write(fd, p + done, len - done);

                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    {
                        int e = errno;

                        close(fd);
                        return -e;
                    }
                }
                done += (size_t)n;
            }
            if (lseek(fd, 0, SEEK_SET) != 0) {
                int e = errno;

                close(fd);
                return -e;
            }
            return fd;
        }
    }
#else
    (void)tag;
#endif
    {
        char tmpl[] = "/tmp/.ppc32rt-procfs-XXXXXX";
        int fd = mkstemp(tmpl);
        const char *p = (const char *)data;
        size_t done = 0U;

        if (fd < 0) {
            return -errno;
        }
        unlink(tmpl);
        while (done < len) {
            ssize_t n = write(fd, p + done, len - done);

            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                {
                    int e = errno;

                    close(fd);
                    return -e;
                }
            }
            done += (size_t)n;
        }
        if (lseek(fd, 0, SEEK_SET) != 0) {
            int e = errno;

            close(fd);
            return -e;
        }
        return fd;
    }
}

static const char *guest_exec_path(const ppc32_ctx_t *ctx)
{
    if (ctx->exec_path != NULL) {
        return ctx->exec_path;
    }
    if (ctx->guest_argv != NULL && ctx->guest_argc > 0) {
        return ctx->guest_argv[0];
    }
    return NULL;
}

int ppc32_procfs_open(ppc32_ctx_t *ctx, const char *path)
{
    int kind;
    size_t cap;
    char *buf;
    long rc;
    size_t len = 0U;
    int fd;

    if (ctx == NULL || path == NULL) {
        return -EFAULT;
    }
    kind = ppc32_procfs_kind(path);
    if (kind == PPC32_PROCFS_NONE) {
        return -ENOENT;
    }
    if (kind == PPC32_PROCFS_EXE) {
        const char *ep = guest_exec_path(ctx);

        if (ep == NULL) {
            return -ENOENT;
        }
        fd = ppc32_open_guest_ro(ctx, ep);
        if (fd < 0) {
            return -errno;
        }
        return fd;
    }
    cap = ((kind == PPC32_PROCFS_MAPS) || (kind == PPC32_PROCFS_CMDLINE)) ?
        PROCFS_BIG_MAX : PROCFS_SMALL_MAX;
    buf = (char *)malloc(cap);
    if (buf == NULL) {
        return -ENOMEM;
    }
    switch (kind) {
    case PPC32_PROCFS_MAPS:
        ppc32_vm_sync_ctx(ctx);
        rc = build_maps(ctx, buf, cap, &len);
        break;
    case PPC32_PROCFS_CMDLINE:
        rc = build_cmdline(ctx, buf, cap, &len);
        break;
    case PPC32_PROCFS_STAT:
        rc = build_stat(ctx, buf, cap, &len);
        break;
    default:
        rc = build_auxv(ctx, buf, cap, &len);
        break;
    }
    if (rc != 0) {
        free(buf);
        return (int)rc;
    }
    fd = serve_bytes("ppc32rt-procfs", buf, len);
    free(buf);
    return fd;
}

long ppc32_procfs_readlinkat(ppc32_ctx_t *ctx, uint32_t dfd_va,
    uint32_t path_va, uint32_t buf_va, uint32_t bufsiz)
{
    char path[PROCFS_PATH_MAX];
    char rel[PROCFS_PATH_MAX + 32U];
    char tmp[PROCFS_PATH_MAX];
    size_t want;
    ssize_t n;
    int m;

    if (ctx == NULL) {
        return -EFAULT;
    }
    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if (bufsiz == 0U) {
        return -EINVAL;
    }
    /* Absolute paths and AT_FDCWD share the readlink core. */
    if (path[0] == '/' || dfd_va == (uint32_t)(int32_t)-100) {
        return ppc32_procfs_readlink(ctx, path_va, buf_va, bufsiz);
    }
    /* dirfd-relative: open O_PATH|O_NOFOLLOW (no final-symlink
     * traversal), then read the /proc/self/fd link of the new fd.
     * O_PATH is Linux-only; elsewhere report ENOSYS for this form
     * (absolute paths and AT_FDCWD above stay portable). */
#ifdef __linux__
    {
        int fd = openat((int)dfd_va, path,
            O_PATH | O_NOFOLLOW | O_CLOEXEC);

        if (fd < 0) {
            return -(long)errno;
        }
        m = snprintf(rel, sizeof rel, "/proc/self/fd/%d", fd);
        if (m < 0 || (size_t)m >= sizeof rel) {
            close(fd);
            return -ENAMETOOLONG;
        }
        want = ((size_t)bufsiz < sizeof tmp) ? (size_t)bufsiz :
            sizeof tmp;
        n = readlink(rel, tmp, want);
        close(fd);
        if (n < 0) {
            return -(long)errno;
        }
        if (ppc32_copyout(ctx, buf_va, tmp, (size_t)n) != 0) {
            return -EFAULT;
        }
        return (long)n;
    }
#else
    (void)m;
    (void)n;
    (void)rel;
    (void)tmp;
    (void)want;
    return -ENOSYS;
#endif
}

long ppc32_procfs_readlink(ppc32_ctx_t *ctx, uint32_t path_va,
    uint32_t buf_va, uint32_t bufsiz)
{
    char path[PROCFS_PATH_MAX];
    int kind;

    if (ctx == NULL) {
        return -EFAULT;
    }
    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if (bufsiz == 0U) {
        return -EINVAL;
    }
    kind = ppc32_procfs_kind(path);
    if (kind == PPC32_PROCFS_EXE) {
        const char *ep = guest_exec_path(ctx);
        size_t n;

        if (ep == NULL) {
            return -ENOENT;
        }
        /* Linux readlink: truncated to bufsiz, no NUL terminator. */
        n = strlen(ep);
        if (n > (size_t)bufsiz) {
            n = (size_t)bufsiz;
        }
        if (ppc32_copyout(ctx, buf_va, ep, n) != 0) {
            return -EFAULT;
        }
        return (long)n;
    }
    if (kind != PPC32_PROCFS_NONE) {
        return -EINVAL;
    }
    {
        char tmp[PROCFS_PATH_MAX];
        size_t want = ((size_t)bufsiz < sizeof tmp) ? (size_t)bufsiz :
            sizeof tmp;
        ssize_t n = readlink(path, tmp, want);

        if (n < 0) {
            return -(long)errno;
        }
        if (ppc32_copyout(ctx, buf_va, tmp, (size_t)n) != 0) {
            return -EFAULT;
        }
        return (long)n;
    }
}
