/*
 * src/os/proc_fork.c — clone/vfork process-fork path with VFORK sync
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Process-fork side of clone(2) when CLONE_THREAD is clear (posix_spawn
 * uses CLONE_VM|CLONE_VFORK|SIGCHLD without CLONE_THREAD) plus the
 * vfork(2) parent/child rendezvous. A VFORK pipe (both ends CLOEXEC,
 * moved above low guest fds) is created before fork: the child closes
 * the read end and keeps the write end open so execve (CLOEXEC) or
 * _exit closes it, while the parent closes the write end and blocks
 * reading one byte until the child execves or exits. Child register
 * setup (SP/TLS/CLEARTID/SETTID) mirrors the thread-clone path.
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if !defined(__APPLE__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "os/convert.h"
#include "os/proc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os/threads.h"
#include "rt32/ppc32.h"
#include "vm/vm32.h"

/* execve vector bounds: Linux MAX_ARG_STRLEN (128 KiB per string) and
 * ARG_MAX (2 MiB of string+pointer bytes); the pointer vector grows
 * from 64 slots (no VLA). Overlong input fails with -E2BIG. */
#define PROC_FORK_MAX_STR 131072U
#define PROC_FORK_ARG_TOTAL (2U * 1024U * 1024U)
#define PROC_FORK_VEC_INIT 64U

/* Pipe fds live above guest low fds so dup2/close in the child cannot
 * collide with the rendezvous. */
#define PROC_FORK_HIGH_FD 256
/* The CLONE_VFORK shared-window write end lives higher still (512)
 * so guest dup2 churn around the low fds never seals it early. */
#define PROC_FORK_VF_FD 512
/* Parent-stack window around r1 snapshotted before a COW fork (64 KiB:
 * posix_spawn writes args->err into the parent frame before _exit). */
#define PROC_FORK_VF_WINDOW 65536U

/* Child side of a CLONE_VFORK shared window: the snapshot, its base
 * and length, and the pipe write end. Set in the child only (the
 * parent keeps its ends in locals); exit/exit_group in the child
 * diffs the window into the pipe, execve drops it silently. */
typedef struct proc_vf_chan {
    int fd;
    uint32_t va;
    uint32_t len;
    uint8_t *snap;
} proc_vf_chan_t;

static proc_vf_chan_t g_vf = { -1, 0U, 0U, NULL };

static void fork_mark_cloexec(int fd);

static bool vf_write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;

    while (n > 0U) {
        ssize_t w = write(fd, p, n);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return false;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return true;
}

static bool vf_read_all(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;

    while (n > 0U) {
        ssize_t r = read(fd, p, n);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return false;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    return true;
}

/* Forget the channel without diffing (execve success: the new image
 * discards the old stack). Safe when inactive. */
void ppc32_proc_vfork_drop(void)
{
    if (g_vf.fd >= 0) {
        (void)close(g_vf.fd);
        g_vf.fd = -1;
    }
    free(g_vf.snap);
    g_vf.snap = NULL;
    g_vf.va = 0U;
    g_vf.len = 0U;
}

/* Child exit (exit/exit_group) without a prior execve: diff the live
 * window against the pre-fork snapshot and send (va, len, bytes)
 * records, then close the channel so the parent sees EOF. Always
 * closes and clears when active, even when the diff cannot be read
 * (the parent must never hang). No-op in the parent. */
void ppc32_proc_vfork_release(ppc32_ctx_t *ctx)
{
    uint8_t *cur = NULL;

    if (ctx == NULL || g_vf.fd < 0) {
        return;
    }
    if (g_vf.snap != NULL && g_vf.len != 0U) {
        cur = (uint8_t *)malloc(g_vf.len);
        if (cur != NULL &&
            ppc32_vm_copyin_safe(ctx, g_vf.va, cur, g_vf.len) == 0) {
            uint32_t i = 0U;

            while (i < g_vf.len) {
                uint32_t end;
                uint8_t hdr[8];
                uint32_t va;

                if (cur[i] == g_vf.snap[i]) {
                    i++;
                    continue;
                }
                end = i + 1U;
                while (end < g_vf.len && cur[end] != g_vf.snap[end]) {
                    end++;
                }
                va = g_vf.va + i;
                hdr[0] = (uint8_t)va;
                hdr[1] = (uint8_t)(va >> 8U);
                hdr[2] = (uint8_t)(va >> 16U);
                hdr[3] = (uint8_t)(va >> 24U);
                hdr[4] = (uint8_t)(end - i);
                hdr[5] = (uint8_t)((end - i) >> 8U);
                hdr[6] = (uint8_t)((end - i) >> 16U);
                hdr[7] = (uint8_t)((end - i) >> 24U);
                if (!vf_write_all(g_vf.fd, hdr, sizeof hdr) ||
                    !vf_write_all(g_vf.fd, cur + i, end - i)) {
                    break;
                }
                i = end;
            }
        }
        free(cur);
    }
    ppc32_proc_vfork_drop();
}

/* Snapshot up to 64 KiB of contiguous mapped RW guest pages around
 * r1 (starting 16 KiB below r1's page, clamped to the run containing
 * r1). Returns 1 with *out_snap owned by the caller, 0 with NULL
 * (no usable window: plain rendezvous instead). */
static int vf_snap_begin(ppc32_ctx_t *ctx, uint32_t *out_va,
    uint32_t *out_len, uint8_t **out_snap)
{
    uint32_t r1;
    uint32_t start;
    uint64_t end64;
    uint32_t rpage;
    uint32_t a;
    uint32_t b;
    uint8_t *snap;

    *out_va = 0U;
    *out_len = 0U;
    *out_snap = NULL;
    if (ctx == NULL || !ctx->vm_ready) {
        return 0;
    }
    r1 = ctx->gpr[PPC32_REG_SP];
    start = r1 & ~4095U;
    if (r1 >= 16384U) {
        start -= 16384U;
    }
    end64 = (uint64_t)start + (uint64_t)PROC_FORK_VF_WINDOW;
    if (end64 > 0x100000000ULL) {
        end64 = 0x100000000ULL;
    }
    rpage = r1 & ~4095U;
    if (!ppc32_vm_range_prot_ok(ctx, rpage, 4096U, 2U)) {
        return 0;
    }
    a = rpage;
    while (a > start &&
        ppc32_vm_range_prot_ok(ctx, a - 4096U, 4096U, 2U)) {
        a -= 4096U;
    }
    b = rpage;
    while ((uint64_t)b + 4096ULL < end64 &&
        ppc32_vm_range_prot_ok(ctx, b + 4096U, 4096U, 2U)) {
        b += 4096U;
    }
    b += 4096U;
    snap = (uint8_t *)malloc((size_t)(b - a));
    if (snap == NULL) {
        return 0;
    }
    if (ppc32_vm_copyin_safe(ctx, a, snap, (size_t)(b - a)) != 0) {
        free(snap);
        return 0;
    }
    *out_va = a;
    *out_len = b - a;
    *out_snap = snap;
    return 1;
}

/* Move the write end above guest low fds (512, CLOEXEC). Falls back
 * to the original fd with CLOEXEC when the dup is unavailable. */
static int vf_high_fd(int fd)
{
    int nfd = -1;

    if (fd < 0) {
        return fd;
    }
#ifdef F_DUPFD_CLOEXEC
    nfd = fcntl(fd, F_DUPFD_CLOEXEC, PROC_FORK_VF_FD);
    if (nfd >= 0) {
        (void)close(fd);
        return nfd;
    }
#endif
    if (fd >= PROC_FORK_VF_FD) {
        fork_mark_cloexec(fd);
        return fd;
    }
#ifdef F_DUPFD
    nfd = fcntl(fd, F_DUPFD, PROC_FORK_VF_FD);
    if (nfd >= 0) {
        (void)close(fd);
        fork_mark_cloexec(nfd);
        return nfd;
    }
#endif
    fork_mark_cloexec(fd);
    return fd;
}

/* Parent: read (va, len, bytes) records until EOF and copy them into
 * guest memory, then close the read end. EINTR retries; a short read
 * is EOF. */
static void vf_wait_replay(ppc32_ctx_t *ctx, int rfd)
{
    uint8_t *buf = NULL;

    if (rfd < 0) {
        return;
    }
    buf = (uint8_t *)malloc(PROC_FORK_VF_WINDOW);
    if (buf == NULL) {
        for (;;) {
            char b;
            ssize_t n = read(rfd, &b, 1U);

            if (n >= 0) {
                if (n == 0) {
                    break;
                }
                continue;
            }
            if (errno != EINTR) {
                break;
            }
        }
        (void)close(rfd);
        return;
    }
    for (;;) {
        uint8_t hdr[8];
        uint32_t va;
        uint32_t n;
        ssize_t r;
        size_t got = 0U;

        for (got = 0U; got < sizeof hdr;) {
            r = read(rfd, hdr + got, sizeof hdr - got);
            if (r == 0) {
                goto done;
            }
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                goto done;
            }
            got += (size_t)r;
        }
        va = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8U) |
            ((uint32_t)hdr[2] << 16U) | ((uint32_t)hdr[3] << 24U);
        n = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8U) |
            ((uint32_t)hdr[6] << 16U) | ((uint32_t)hdr[7] << 24U);
        if (n == 0U || n > PROC_FORK_VF_WINDOW ||
            !vf_read_all(rfd, buf, n)) {
            break;
        }
        if (ctx != NULL) {
            (void)ppc32_vm_copyout_safe(ctx, va, buf, n);
        }
    }
done:
    free(buf);
    (void)close(rfd);
}

void ppc32_proc_free_vec(char **vec, uint32_t count)
{
    uint32_t i;

    if (vec == NULL) {
        return;
    }
    for (i = 0U; i < count; i++) {
        free(vec[i]);
    }
    free(vec);
}

long ppc32_proc_copy_vec(ppc32_ctx_t *ctx, uint32_t vec_va, char ***out,
    uint32_t *out_count)
{
    char **vec;
    char *tmp;
    uint32_t cap = PROC_FORK_VEC_INIT;
    uint32_t n = 0U;
    size_t total = 0U;
    long rc = 0L;

    tmp = (char *)malloc((size_t)PROC_FORK_MAX_STR + 1U);
    if (tmp == NULL) {
        return -ENOMEM;
    }
    vec = (char **)calloc((size_t)cap + 1U, sizeof(char *));
    if (vec == NULL) {
        free(tmp);
        return -ENOMEM;
    }
    if (vec_va == 0U) {
        free(tmp);
        *out = vec;
        *out_count = 0U;
        return 0;
    }
    for (;;) {
        uint32_t str_va;
        size_t len;
        char *dup;

        if (!ppc32_range_ok(vec_va + n * 4U, 4U) ||
            !ppc32_vm_range_prot_ok(ctx, vec_va + n * 4U, 4U, 1U)) {
            rc = -EFAULT;
            break;
        }
        str_va = ppc32_ld32be(ctx, vec_va + n * 4U);
        if (str_va == 0U) {
            break;
        }
        rc = (long)ppc32_copyin_str(ctx, str_va, tmp,
            (size_t)PROC_FORK_MAX_STR + 1U);
        if (rc == (long)-ENAMETOOLONG) {
            rc = -E2BIG;
            break;
        }
        if (rc != 0L) {
            rc = -EFAULT;
            break;
        }
        len = strlen(tmp) + 1U;
        total += len + sizeof(char *);
        if (total > (size_t)PROC_FORK_ARG_TOTAL) {
            rc = -E2BIG;
            break;
        }
        if (n >= cap) {
            char **nv;
            uint32_t ncap = cap * 2U;

            if (ncap <= cap) {
                rc = -ENOMEM;
                break;
            }
            nv = (char **)realloc(vec,
                ((size_t)ncap + 1U) * sizeof(char *));
            if (nv == NULL) {
                rc = -ENOMEM;
                break;
            }
            memset(nv + cap, 0, ((size_t)ncap - cap + 1U) * sizeof(char *));
            vec = nv;
            cap = ncap;
        }
        dup = (char *)malloc(len);
        if (dup == NULL) {
            rc = -ENOMEM;
            break;
        }
        memcpy(dup, tmp, len);
        vec[n] = dup;
        n++;
    }
    free(tmp);
    if (rc != 0L) {
        ppc32_proc_free_vec(vec, n);
        return rc;
    }
    vec[n] = NULL;
    *out = vec;
    *out_count = n;
    return 0;
}

static int fork_high_fd(int fd)
{
    int nfd;

    if (fd < 0 || fd >= PROC_FORK_HIGH_FD) {
        return fd;
    }
#ifdef F_DUPFD
    nfd = fcntl(fd, F_DUPFD, PROC_FORK_HIGH_FD);
    if (nfd < 0) {
        return fd;
    }
    (void)close(fd);
    return nfd;
#else
    return fd;
#endif
}

static void fork_mark_cloexec(int fd)
{
    int fl;

    if (fd < 0) {
        return;
    }
    fl = fcntl(fd, F_GETFD);
    if (fl >= 0) {
        (void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
    }
}

/* Create a CLOEXEC rendezvous pipe moved above low fds. Returns 0 or
 * a negative errno; on success both pf[] entries are >= 0. */
static long fork_pipe_open(int pf[2])
{
    int raw[2];

    pf[0] = -1;
    pf[1] = -1;
    if (pipe(raw) != 0) {
        return -(long)errno;
    }
    raw[0] = fork_high_fd(raw[0]);
    raw[1] = fork_high_fd(raw[1]);
    fork_mark_cloexec(raw[0]);
    fork_mark_cloexec(raw[1]);
    if (raw[0] < 0 || raw[1] < 0) {
        if (raw[0] >= 0) {
            (void)close(raw[0]);
        }
        if (raw[1] >= 0) {
            (void)close(raw[1]);
        }
        return -EMFILE;
    }
    pf[0] = raw[0];
    pf[1] = raw[1];
    return 0;
}

/* vfork(2) with parent/child rendezvous: the parent blocks until the
 * child execves (CLOEXEC closes the write end) or exits. */
long ppc32_proc_vfork_sync(ppc32_ctx_t *ctx)
{
    int pf[2];
    long pid;
    long rc;

    if (ctx == NULL) {
        return -EFAULT;
    }
    rc = fork_pipe_open(pf);
    if (rc != 0L) {
        return rc;
    }
    pid = ppc32_proc_fork(ctx);
    if (pid < 0L) {
        (void)close(pf[0]);
        (void)close(pf[1]);
        return pid;
    }
    if (pid == 0L) {
        (void)close(pf[0]);
        return 0L;
    }
    (void)close(pf[1]);
    for (;;) {
        char b;
        ssize_t n = read(pf[0], &b, 1U);

        if (n >= 0) {
            break;
        }
        if (errno != EINTR) {
            break;
        }
    }
    (void)close(pf[0]);
    return pid;
}

/* Clone-without-THREAD process fork (posix_spawn: CLONE_VM|CLONE_VFORK
 * without CLONE_THREAD). Validates the Linux SIGHAND-without-VM rule,
 * then forks; the child takes SP/TLS/CLEARTID/SETTID, the VFORK parent
 * waits on the rendezvous pipe. Returns child pid, 0 in child, or a
 * negative errno. */
long ppc32_clone_fork(ppc32_ctx_t *ctx, uint32_t flags, uint32_t stack_va,
    uint32_t parent_tid_va, uint32_t tls_va, uint32_t child_tid_va)
{
    int pf[2];
    int is_vfork;
    long pid;
    long rc;

    if (ctx == NULL) {
        return -EFAULT;
    }
    if ((flags & PPC32_CLONE_SIGHAND) != 0U &&
        (flags & PPC32_CLONE_VM) == 0U) {
        return -EINVAL;
    }
    if ((flags & PPC32_CLONE_PARENT_SETTID) != 0U &&
        parent_tid_va != 0U &&
        !ppc32_vm_range_prot_ok(ctx, parent_tid_va, 4U, 2U)) {
        return -EFAULT;
    }
    if ((flags & PPC32_CLONE_CHILD_SETTID) != 0U && child_tid_va != 0U &&
        !ppc32_vm_range_prot_ok(ctx, child_tid_va, 4U, 2U)) {
        return -EFAULT;
    }
    is_vfork = ((flags & PPC32_CLONE_VFORK) != 0U) ? 1 : 0;
    pf[0] = -1;
    pf[1] = -1;
    {
        int is_vfshare = (((flags & PPC32_CLONE_VM) != 0U) &&
            ((flags & PPC32_CLONE_VFORK) != 0U)) ? 1 : 0;
        uint32_t vf_va = 0U;
        uint32_t vf_len = 0U;
        uint8_t *vf_snap = NULL;

        if (is_vfork != 0) {
            rc = fork_pipe_open(pf);
            if (rc != 0L) {
                return rc;
            }
            /* posix_spawn (CLONE_VM|CLONE_VFORK): the child writes its
             * error report into the parent's stack frame, so snapshot
             * the window before the COW fork. */
            if (is_vfshare != 0) {
                (void)vf_snap_begin(ctx, &vf_va, &vf_len, &vf_snap);
            }
        }
        pid = ppc32_proc_fork(ctx);
        if (pid < 0L) {
            if (is_vfork != 0) {
                (void)close(pf[0]);
                (void)close(pf[1]);
            }
            free(vf_snap);
            return pid;
        }
        if (pid == 0L) {
            if (is_vfork != 0) {
                (void)close(pf[0]);
                if (is_vfshare != 0) {
                    /* High write end first: guest dup2 churn must not
                     * seal the channel before exit/execve. The pipe is
                     * still the parent's only wakeup. */
                    g_vf.fd = vf_high_fd(pf[1]);
                    g_vf.va = vf_va;
                    g_vf.len = vf_len;
                    g_vf.snap = vf_snap;
                    vf_snap = NULL;
                }
            }
            free(vf_snap);
            if (stack_va != 0U) {
                ctx->gpr[PPC32_REG_SP] = stack_va;
            }
            if ((flags & PPC32_CLONE_SETTLS) != 0U) {
                ctx->gpr[PPC32_REG_TP] = tls_va;
            }
            if ((flags & PPC32_CLONE_CHILD_CLEARTID) != 0U) {
                ctx->clear_child_tid = child_tid_va;
            } else {
                ctx->clear_child_tid = 0U;
            }
            if ((flags & PPC32_CLONE_CHILD_SETTID) != 0U &&
                child_tid_va != 0U && ppc32_range_ok(child_tid_va, 4U)) {
                ppc32_st32be(ctx, child_tid_va, ctx->guest_pid);
            }
            return 0L;
        }
        /* Parent: the snapshot copy is the child's now. */
        free(vf_snap);
        vf_snap = NULL;
        if (is_vfork != 0) {
            (void)close(pf[1]);
            if (is_vfshare != 0) {
                vf_wait_replay(ctx, pf[0]);
            } else {
                for (;;) {
                    char b;
                    ssize_t n = read(pf[0], &b, 1U);

                    if (n >= 0) {
                        break;
                    }
                    if (errno != EINTR) {
                        break;
                    }
                }
                (void)close(pf[0]);
            }
        }
    }
    if ((flags & PPC32_CLONE_PARENT_SETTID) != 0U &&
        parent_tid_va != 0U && ppc32_range_ok(parent_tid_va, 4U)) {
        ppc32_st32be(ctx, parent_tid_va, (uint32_t)pid);
    }
    return pid;
}
