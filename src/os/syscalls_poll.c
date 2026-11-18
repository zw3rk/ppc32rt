/*
 * src/os/syscalls_poll.c — select/poll family and mknodat (T1-T4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * _newselect(142), pselect6(280)/pselect6_time64(413), poll(167),
 * ppoll(281)/ppoll_time64(414) and mknodat(288). Guest fd_sets are
 * arrays of big-endian 32-bit words (bit n lives in word n/32); they
 * are converted to host fd_set bit by bit. pselect6/ppoll keep every
 * catchable async host signal blocked across the pending check, then
 * wait with a sigmask that unblocks whichever the guest tmp mask
 * leaves unblocked (make -j2 wakes only when unblocked); host SIGURG
 * stays unblocked as the sibling wake nudge. Already pending signals
 * preempt the wait with -EINTR even without a tmp mask; the pre-wait
 * mask is restored before return. On Darwin,
 * Linux POLLWRNORM/POLLWRBAND translate to/from host POLLOUT/
 * POLLWRBAND.
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "os/syscalls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/signals.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

#include "os/syscalls_poll_priv.h"

static long pl_select_masked(ppc32_ctx_t *ctx, uint32_t nfds, uint32_t rva,
    uint32_t wva, uint32_t eva, const struct timespec *to, int is_tv,
    uint32_t timeout_va, int is64, uint64_t tmp_mask, int have_tmp)
{
    fd_set s[3];
    fd_set *p[3] = {NULL, NULL, NULL};
    const uint32_t va[3] = {rva, wva, eva};
    uint8_t raw[PL_SET_BYTES];
    uint64_t old_mask = ctx->sig_mask;
    uint64_t wait_bits = old_mask;
    struct timespec orig = {0, 0};
    struct timespec start;
    int have_start = 0;
    sigset_t host_saved;
    sigset_t wait_set;
    int have_wait = 0;
    int i;
    int r = -1;
    int saved_errno = 0;

    if (nfds > PL_MAX_FDS) {
        return -EINVAL;
    }
    for (i = 0; i < 3; i++) {
        if (va[i] != 0U) {
            long rc = pl_get_set(ctx, va[i], nfds, &s[i], raw);

            if (rc != 0L) {
                return rc;
            }
            p[i] = &s[i];
        }
    }
    if (to != NULL) {
        orig = *to;
        if (clock_gettime(CLOCK_MONOTONIC, &start) == 0) {
            have_start = 1;
        }
    }
    if (have_tmp != 0) {
        /* Atomic wait: mask first, then check; exits in between stay
         * pending for pselect instead of slipping past select. */
        pl_wait_mask_install(tmp_mask, &host_saved, &wait_set);
        have_wait = 1;
        wait_bits = tmp_mask;
        ctx->sig_mask = tmp_mask;
        if (pl_deliverable(ctx, tmp_mask)) {
            pl_tmp_exit_defer(ctx, old_mask);
            pl_wait_mask_restore(&host_saved);
            return -EINTR;
        }
    } else if (pl_deliverable(ctx, wait_bits)) {
        /* No mask change, but a pending signal still preempts the
         * wait; report the full remaining timeout first. */
        if (to != NULL && timeout_va != 0U) {
            if (is_tv != 0) {
                pl_put_tv(ctx, timeout_va, &orig);
            } else {
                pl_put_ts(ctx, timeout_va, is64, &orig);
            }
        }
        return -EINTR;
    }
    for (;;) {
        if (have_wait != 0) {
            struct timespec tspec;

            if (to == NULL) {
                r = pselect((int)nfds, p[0], p[1], p[2], NULL, &wait_set);
            } else {
                pl_remaining(&orig, have_start, &start, &tspec);
                r = pselect((int)nfds, p[0], p[1], p[2], &tspec,
                    &wait_set);
            }
        } else {
            struct timeval tv;

            if (to == NULL) {
                r = select((int)nfds, p[0], p[1], p[2], NULL);
            } else {
                struct timespec tspec;

                pl_remaining(&orig, have_start, &start, &tspec);
                tv.tv_sec = tspec.tv_sec;
                tv.tv_usec = (suseconds_t)(tspec.tv_nsec / 1000L);
                r = select((int)nfds, p[0], p[1], p[2], &tv);
            }
        }
        saved_errno = errno;
        if (r >= 0) {
            break;
        }
        if (saved_errno != EINTR) {
            break;
        }
        /* Spurious host wakeup (nudge, SIGWINCH): EINTR only when
         * guest-deliverable, else wait out the remainder. */
        if (pl_deliverable(ctx, wait_bits)) {
            break;
        }
    }
    {
        if (have_wait != 0) {
            pl_wait_mask_restore(&host_saved);
        }
        if (to != NULL && timeout_va != 0U && have_start != 0) {
            struct timespec rem;

            pl_remaining(&orig, have_start, &start, &rem);
            if (is_tv != 0) {
                pl_put_tv(ctx, timeout_va, &rem);
            } else {
                pl_put_ts(ctx, timeout_va, is64, &rem);
            }
        }
        if (r < 0) {
            if (saved_errno == EINTR && have_tmp != 0 &&
                pl_deliverable(ctx, tmp_mask)) {
                /* Really interrupted for the guest: keep tmp in force
                 * for the pump (frame uc_sigmask takes old_mask). */
                pl_tmp_exit_defer(ctx, old_mask);
            } else if (have_tmp != 0) {
                ctx->sig_mask = old_mask;
            }
            return -(long)ppc32_errno_map(saved_errno);
        }
    }
    if (have_tmp != 0) {
        if (pl_deliverable(ctx, tmp_mask)) {
            pl_tmp_exit_defer(ctx, old_mask);
        } else {
            ctx->sig_mask = old_mask;
        }
    }
    for (i = 0; i < 3; i++) {
        if (p[i] != NULL &&
            pl_put_set(ctx, va[i], nfds, p[i], raw) != 0L) {
            return -EFAULT;
        }
    }
    return (long)r;
}

static long pl_poll_masked(ppc32_ctx_t *ctx, uint32_t fds_va, uint32_t nfds,
    const struct timespec *to, uint32_t timeout_va, int is64,
    uint64_t tmp_mask, int have_tmp)
{
    uint8_t stack_raw[PL_MAX_STACK_POLL * 8U];
    uint8_t *raw = stack_raw;
    struct pollfd *pf = NULL;
    struct pollfd stack_pf[PL_MAX_STACK_POLL];
    uint64_t old_mask = ctx->sig_mask;
    uint64_t wait_bits = old_mask;
    struct timespec orig = {0, 0};
    struct timespec start;
    int have_start = 0;
    sigset_t host_saved;
    sigset_t wait_set;
    int have_wait = 0;
    uint32_t i;
    int r = -1;
    int saved_errno = 0;

    if (nfds != 0U && nfds > PL_MAX_STACK_POLL) {
        struct rlimit rl;
        uint64_t lim = (uint64_t)PL_MAX_POLL_HARD;

        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < lim) {
            lim = (uint64_t)rl.rlim_cur;
        }
        if ((uint64_t)nfds > lim) {
            return -EINVAL;
        }
        raw = (uint8_t *)malloc((size_t)nfds * 8U);
        pf = (struct pollfd *)malloc((size_t)nfds * sizeof(*pf));
        if (raw == NULL || pf == NULL) {
            free(raw == stack_raw ? NULL : raw);
            free(pf);
            return -ENOMEM;
        }
    } else {
        pf = stack_pf;
    }
    if (nfds != 0U &&
        ppc32_copyin(ctx, fds_va, raw, (size_t)nfds * 8U) != 0) {
        if (raw != stack_raw) {
            free(raw);
        }
        if (pf != stack_pf) {
            free(pf);
        }
        return -EFAULT;
    }
    for (i = 0U; i < nfds; i++) {
        pf[i].fd = (int)(int32_t)pl_be32(raw + i * 8U);
        pf[i].events = (short)(((uint16_t)raw[i * 8U + 4U] << 8U) |
            raw[i * 8U + 5U]);
#ifdef __APPLE__ /* WRNORM(0x100)->POLLOUT, WRBAND(0x200)->WRBAND. */
        pf[i].events = (short)((pf[i].events & 0x00FF) |
            (((pf[i].events & 0x0100) != 0) ? POLLOUT : 0) |
            (((pf[i].events & 0x0200) != 0) ? POLLWRBAND : 0));
#endif
        pf[i].revents = 0;
    }
    if (to != NULL) {
        orig = *to;
        if (clock_gettime(CLOCK_MONOTONIC, &start) == 0) {
            have_start = 1;
        }
    }
    if (have_tmp != 0) {
        /* Atomic wait: mask first, then check; exits in between stay
         * pending for ppoll instead of slipping past poll. */
        pl_wait_mask_install(tmp_mask, &host_saved, &wait_set);
        have_wait = 1;
        wait_bits = tmp_mask;
        ctx->sig_mask = tmp_mask;
        if (pl_deliverable(ctx, tmp_mask)) {
            pl_tmp_exit_defer(ctx, old_mask);
            pl_wait_mask_restore(&host_saved);
            if (raw != stack_raw) {
                free(raw);
            }
            if (pf != stack_pf) {
                free(pf);
            }
            return -EINTR;
        }
    } else if (pl_deliverable(ctx, wait_bits)) {
        /* No mask change, but a pending signal still preempts the
         * wait; report the full remaining timeout first. */
        if (to != NULL && timeout_va != 0U) {
            pl_put_ts(ctx, timeout_va, is64, &orig);
        }
        if (raw != stack_raw) {
            free(raw);
        }
        if (pf != stack_pf) {
            free(pf);
        }
        return -EINTR;
    }
    for (;;) {
#ifdef __linux__
        if (have_wait != 0) {
            struct timespec tspec;
            const struct timespec *pts = NULL;

            if (to != NULL) {
                pl_remaining(&orig, have_start, &start, &tspec);
                pts = &tspec;
            }
            r = ppoll(pf, (nfds_t)nfds, pts, &wait_set);
        } else
#endif
#ifdef __APPLE__
        if (have_wait != 0 && pl_poll_selectable(pf, nfds)) {
            struct timespec tspec;
            const struct timespec *pts = NULL;

            if (to != NULL) {
                pl_remaining(&orig, have_start, &start, &tspec);
                pts = &tspec;
            }
            r = pl_poll_pselect(pf, nfds, pts, &wait_set);
        } else if (have_wait != 0) {
            /* Unselectable fds: poll(2) has no sigmask side, so run
             * it under the wait mask in short slices (the fallback
             * restores the slices' wakeups via deliverability). */
            r = pl_poll_fallback(pf, nfds, to != NULL ? &orig : NULL,
                have_start, &start, &wait_set, ctx, wait_bits);
        } else
#endif
        {
            struct timespec tspec;
            int timeout_ms;

            if (to == NULL) {
                timeout_ms = -1;
            } else {
                pl_remaining(&orig, have_start, &start, &tspec);
                timeout_ms = pl_ts_to_ms(&tspec);
            }
            r = poll(pf, (nfds_t)nfds, timeout_ms);
        }
        saved_errno = errno;
        if (r >= 0) {
            break;
        }
        if (saved_errno != EINTR) {
            break;
        }
        /* Spurious host wakeup: EINTR only when guest-deliverable. */
        if (pl_deliverable(ctx, wait_bits)) {
            break;
        }
    }
    {
        if (have_wait != 0) {
            pl_wait_mask_restore(&host_saved);
        }
        if (to != NULL && timeout_va != 0U && have_start != 0) {
            struct timespec rem;

            pl_remaining(&orig, have_start, &start, &rem);
            pl_put_ts(ctx, timeout_va, is64, &rem);
        }
        if (r < 0) {
            if (saved_errno == EINTR && have_tmp != 0 &&
                pl_deliverable(ctx, tmp_mask)) {
                /* Really interrupted for the guest: keep tmp in force
                 * for the pump (frame uc_sigmask takes old_mask). */
                pl_tmp_exit_defer(ctx, old_mask);
            } else if (have_tmp != 0) {
                ctx->sig_mask = old_mask;
            }
            if (raw != stack_raw) {
                free(raw);
            }
            if (pf != stack_pf) {
                free(pf);
            }
            return -(long)ppc32_errno_map(saved_errno);
        }
    }
    if (have_tmp != 0) {
        if (pl_deliverable(ctx, tmp_mask)) {
            pl_tmp_exit_defer(ctx, old_mask);
        } else {
            ctx->sig_mask = old_mask;
        }
    }
    for (i = 0U; i < nfds; i++) {
#ifdef __APPLE__ /* POLLOUT->guest WRNORM when asked; WRBAND reads 0x200. */
        uint16_t gev = (uint16_t)((raw[i * 8U + 4U] << 8U) | raw[i * 8U + 5U]);

        pf[i].revents = (short)((pf[i].revents & 0x00FF) |
            (((pf[i].revents & POLLOUT) && (gev & 0x0100U)) ? 0x0100 : 0) |
            ((pf[i].revents & POLLWRBAND) ? 0x0200 : 0));
#endif
        pl_put_be16(raw + i * 8U + 6U, (uint16_t)pf[i].revents);
    }
    if (nfds != 0U && ppc32_copyout(ctx, fds_va, raw, (size_t)nfds * 8U) != 0) {
        if (raw != stack_raw) {
            free(raw);
        }
        if (pf != stack_pf) {
            free(pf);
        }
        return -EFAULT;
    }
    if (raw != stack_raw) {
        free(raw);
    }
    if (pf != stack_pf) {
        free(pf);
    }
    return (long)r;
}

static long pl_dispatch2(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
    int *owned)
{
    struct timespec ts;
    int is64 = (nr == PL_NR_PSELECT6_64 || nr == PL_NR_PPOLL_64);
    long rc;

    *owned = 1;
    switch (nr) {
    case PL_NR_NEWSELECT: {
        uint64_t tmp = 0ULL;
        int have_tmp = 0;

        (void)tmp;
        (void)have_tmp;
        if (a4 != 0U) {
            rc = pl_get_tv(ctx, a4, &ts);
            if (rc != 0L) {
                return rc;
            }
            return pl_select_masked(ctx, a0, a1, a2, a3, &ts, 1, a4,
                0, 0ULL, 0);
        }
        return pl_select_masked(ctx, a0, a1, a2, a3, NULL, 1, 0U, 0,
            0ULL, 0);
    }
    case PL_NR_PSELECT6:
    case PL_NR_PSELECT6_64: {
        uint64_t tmp = 0ULL;
        int have_tmp = 0;

        rc = pl_pselect_mask(ctx, a5, &tmp, &have_tmp);
        if (rc != 0L) {
            return rc;
        }
        if (a4 != 0U) {
            rc = pl_get_ts(ctx, a4, is64, &ts);
            if (rc != 0L) {
                if (have_tmp != 0) {
                    ctx->sig_mask = ctx->sig_mask;
                }
                return rc;
            }
            return pl_select_masked(ctx, a0, a1, a2, a3, &ts, 0, a4,
                is64, tmp, have_tmp);
        }
        return pl_select_masked(ctx, a0, a1, a2, a3, NULL, 0, 0U, is64,
            tmp, have_tmp);
    }
    case PL_NR_POLL: {
        int32_t ms = (int32_t)a2;
        struct timespec pts;

        if (ms < 0) {
            return pl_poll_masked(ctx, a0, a1, NULL, 0U, 0, 0ULL, 0);
        }
        pts.tv_sec = (time_t)(ms / 1000);
        pts.tv_nsec = (long)(ms % 1000) * 1000000L;
        return pl_poll_masked(ctx, a0, a1, &pts, 0U, 0, 0ULL, 0);
    }
    case PL_NR_PPOLL:
    case PL_NR_PPOLL_64: {
        uint64_t tmp = 0ULL;
        int have_tmp = 0;

        rc = pl_ppoll_mask(ctx, a3, a4, &tmp, &have_tmp);
        if (rc != 0L) {
            return rc;
        }
        if (a2 == 0U) {
            return pl_poll_masked(ctx, a0, a1, NULL, 0U, is64, tmp,
                have_tmp);
        }
        rc = pl_get_ts(ctx, a2, is64, &ts);
        if (rc != 0L) {
            return rc;
        }
        return pl_poll_masked(ctx, a0, a1, &ts, a2, is64, tmp, have_tmp);
    }
    case PL_NR_MKNODAT: {
        char path[PPC32_PATH_MAX];
        int dfd = ((int32_t)a0 == PL_AT_FDCWD) ? AT_FDCWD : (int)a0;

        if (a1 == 0U) {
            return -EFAULT;
        }
        rc = ppc32_path_resolve_mut(ctx, a1, path);
        if (rc != 0L) {
            return rc;
        }
        if ((a2 & S_IFMT) == S_IFIFO) {
            return (mkfifoat(dfd, path, (mode_t)(a2 & 07777U)) == 0) ? 0L :
                -(long)ppc32_errno_map(errno);
        }
        if ((a2 & S_IFMT) == S_IFREG || (a2 & S_IFMT) == 0U) {
            int fd = openat(dfd, path, O_CREAT | O_EXCL | O_WRONLY,
                (mode_t)(a2 & 07777U));

            if (fd < 0) {
                return -(long)ppc32_errno_map(errno);
            }
            (void)close(fd);
            return 0L;
        }
        if ((a2 & S_IFMT) == S_IFSOCK) {
            if (mknodat(dfd, path, (mode_t)a2, (dev_t)0) == 0) {
                return 0L;
            }
            return -(long)ppc32_errno_map(errno);
        }
        return -EPERM;
    }
    default:
        *owned = 0;
        return 0L;
    }
}

int ppc32_poll_dispatch(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
    long *out_ret)
{
    int owned = 0;
    long ret;

    if (ctx == NULL || out_ret == NULL) {
        return 0;
    }
    ret = pl_dispatch2(ctx, nr, a0, a1, a2, a3, a4, a5, &owned);
    if (owned == 0) {
        return 0;
    }
    *out_ret = ret;
    return 1;
}


