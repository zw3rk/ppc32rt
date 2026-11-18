/*
 * src/os/syscalls_poll_priv.h — select/poll shared helpers (T1-T4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest fd_set/flag conversion, timespec/timeval validation, the
 * pselect6/ppoll sigmask readers, the wait-mask install/restore pair,
 * and the Darwin poll fallbacks. Included once by syscalls_poll.c.
 */

#ifndef PPC32RT_SYSCALLS_POLL_PRIV_H
#define PPC32RT_SYSCALLS_POLL_PRIV_H

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>

#include "os/convert.h"
#include "os/signals.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

#define PL_NR_NEWSELECT 142U
#define PL_NR_POLL 167U
#define PL_NR_MKNODAT 288U
#define PL_NR_PSELECT6 280U
#define PL_NR_PPOLL 281U
#define PL_NR_PSELECT6_64 413U
#define PL_NR_PPOLL_64 414U

#define PL_AT_FDCWD (-100)
#define PL_MAX_FDS 1024U
#define PL_SET_BYTES (PL_MAX_FDS / 8U)
#define PL_MAX_STACK_POLL 1024U
#define PL_MAX_POLL_HARD 1048576U

#define PL_SIG_KILL_BIT (1ULL << (PPC32_SIGKILL - 1))
#define PL_SIG_STOP_BIT (1ULL << (PPC32_SIGSTOP - 1))

static uint32_t pl_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) |
        ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

static void pl_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)v;
}

static void pl_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8U);
    p[1] = (uint8_t)v;
}

/* Byte holding guest fd `n` in a big-endian 32-bit word array. */
static size_t pl_byte(uint32_t n)
{
    return (size_t)(n / 32U) * 4U + 3U - (size_t)((n % 32U) / 8U);
}

/* Guest set -> host fd_set. A zero `va` leaves the set absent. */
static long pl_get_set(ppc32_ctx_t *ctx, uint32_t va, uint32_t nfds,
    fd_set *out, uint8_t *raw)
{
    size_t bytes = (size_t)((nfds + 31U) / 32U) * 4U;
    uint32_t n;

    FD_ZERO(out);
    memset(raw, 0, PL_SET_BYTES);
    if (ppc32_copyin(ctx, va, raw, bytes) != 0) {
        return -EFAULT;
    }
    for (n = 0U; n < nfds; n++) {
        if ((raw[pl_byte(n)] >> (n % 8U)) & 1U) {
            FD_SET((int)n, out);
        }
    }
    return 0L;
}

static long pl_put_set(ppc32_ctx_t *ctx, uint32_t va, uint32_t nfds,
    const fd_set *in, uint8_t *raw)
{
    size_t bytes = (size_t)((nfds + 31U) / 32U) * 4U;
    uint32_t n;

    memset(raw, 0, PL_SET_BYTES);
    for (n = 0U; n < nfds; n++) {
        if (FD_ISSET((int)n, in)) {
            raw[pl_byte(n)] |= (uint8_t)(1U << (n % 8U));
        }
    }
    return (ppc32_copyout(ctx, va, raw, bytes) == 0) ? 0L : -EFAULT;
}

/* Read a guest timespec with kernel validation (tv_sec<0, nsec<0 or
 * >=1e9 -> -EINVAL; time64 high nsec word must be zero). */
static long pl_get_ts(ppc32_ctx_t *ctx, uint32_t va, int is64,
    struct timespec *ts)
{
    uint8_t b[16];
    size_t w = is64 ? 8U : 4U;

    if (ppc32_copyin(ctx, va, b, 2U * w) != 0) {
        return -EFAULT;
    }
    if (is64) {
        int64_t sec = (int64_t)(((uint64_t)pl_be32(b) << 32U) |
            pl_be32(b + 4));
        uint32_t nsec_hi = pl_be32(b + 8);
        int32_t nsec_lo = (int32_t)pl_be32(b + 12);

        if (sec < 0 || nsec_hi != 0U || nsec_lo < 0 ||
            nsec_lo >= 1000000000) {
            return -EINVAL;
        }
        ts->tv_sec = (time_t)sec;
        ts->tv_nsec = (long)nsec_lo;
    } else {
        int32_t sec = (int32_t)pl_be32(b);
        int32_t nsec = (int32_t)pl_be32(b + 4);

        if (sec < 0 || nsec < 0 || nsec >= 1000000000) {
            return -EINVAL;
        }
        ts->tv_sec = (time_t)sec;
        ts->tv_nsec = (long)nsec;
    }
    return 0L;
}

static void pl_put_ts(ppc32_ctx_t *ctx, uint32_t va, int is64,
    const struct timespec *ts)
{
    uint8_t b[16];

    if (is64) {
        uint64_t sec = (uint64_t)(int64_t)ts->tv_sec;
        uint32_t nsec = (uint32_t)ts->tv_nsec;

        pl_put_be32(b, (uint32_t)(sec >> 32U));
        pl_put_be32(b + 4, (uint32_t)sec);
        pl_put_be32(b + 8, 0U);
        pl_put_be32(b + 12, nsec);
        (void)ppc32_copyout(ctx, va, b, sizeof b);
    } else {
        pl_put_be32(b, (uint32_t)(int32_t)ts->tv_sec);
        pl_put_be32(b + 4, (uint32_t)ts->tv_nsec);
        (void)ppc32_copyout(ctx, va, b, 8U);
    }
}

/* Read a guest timeval with validation (usec in [0,1e6) else -EINVAL). */
static long pl_get_tv(ppc32_ctx_t *ctx, uint32_t va, struct timespec *ts)
{
    uint8_t b[8];
    int32_t sec;
    int32_t usec;
    int64_t tot;
    int64_t rem;

    if (ppc32_copyin(ctx, va, b, sizeof b) != 0) {
        return -EFAULT;
    }
    sec = (int32_t)pl_be32(b);
    usec = (int32_t)pl_be32(b + 4);
    /* Linux kern_select rejects only negative fields and folds
     * tv_usec >= 1000000 into tv_sec instead of failing. */
    if (sec < 0 || usec < 0) {
        return -EINVAL;
    }
    /* int64 math: sec near INT32_MAX plus folded usec would overflow
     * a 32-bit accumulator (signed UB). */
    tot = (int64_t)sec + (int64_t)usec / 1000000LL;
    rem = (int64_t)usec % 1000000LL;
    ts->tv_sec = (time_t)tot;
    ts->tv_nsec = (long)rem * 1000L;
    return 0L;
}

static void pl_put_tv(ppc32_ctx_t *ctx, uint32_t va,
    const struct timespec *ts)
{
    uint8_t b[8];

    pl_put_be32(b, (uint32_t)(int32_t)ts->tv_sec);
    pl_put_be32(b + 4, (uint32_t)(ts->tv_nsec / 1000L));
    (void)ppc32_copyout(ctx, va, b, sizeof b);
}

static int pl_ts_to_ms(const struct timespec *ts)
{
    /* Clamp huge tv_sec before multiplying so the 64-bit product never
     * overflows or wraps negative (time64 "effectively infinite"). */
    if (ts->tv_sec > (time_t)2147483) {
        return 0x7fffffff;
    }
    if (ts->tv_sec < (time_t)0) {
        return 0;
    }
    {
        long long ms = (long long)ts->tv_sec * 1000LL +
            (ts->tv_nsec + 999999L) / 1000000L;

        return (ms > 0x7fffffffLL) ? 0x7fffffff : (int)ms;
    }
}

/* Read the pselect6 sigmask argpack at `va`: {be32 mask_va, be32 size}.
 * Validates size==8, reads the BE64 guest set into *out. Returns 0 with
 * *has==0 when no mask change, or a negative errno. */
static long pl_pselect_mask(ppc32_ctx_t *ctx, uint32_t va, uint64_t *out,
    int *has)
{
    uint32_t mask_va;
    uint32_t size;
    uint8_t b[8];

    *has = 0;
    if (va == 0U) {
        return 0L;
    }
    {
        uint8_t ap[8];

        if (ppc32_copyin(ctx, va, ap, sizeof ap) != 0) {
            return -EFAULT;
        }
        mask_va = pl_be32(ap);
        size = pl_be32(ap + 4);
    }
    /* Linux set_user_sigmask: a NULL mask ignores a bogus size. */
    if (mask_va == 0U) {
        return 0L;
    }
    if (size != 8U) {
        return -EINVAL;
    }
    if (ppc32_copyin(ctx, mask_va, b, sizeof b) != 0) {
        return -EFAULT;
    }
    *out = ((uint64_t)pl_be32(b + 4) << 32U) | (uint64_t)pl_be32(b);
    *out &= ~(PL_SIG_KILL_BIT | PL_SIG_STOP_BIT);
    *has = 1;
    return 0L;
}

/* Read the ppoll sigmask at mask_va/size. NULL mask means no change. */
static long pl_ppoll_mask(ppc32_ctx_t *ctx, uint32_t mask_va, uint32_t size,
    uint64_t *out, int *has)
{
    uint8_t b[8];

    *has = 0;
    if (mask_va == 0U) {
        return 0L;
    }
    if (size != 8U) {
        return -EINVAL;
    }
    if (ppc32_copyin(ctx, mask_va, b, sizeof b) != 0) {
        return -EFAULT;
    }
    *out = ((uint64_t)pl_be32(b + 4) << 32U) | (uint64_t)pl_be32(b);
    *out &= ~(PL_SIG_KILL_BIT | PL_SIG_STOP_BIT);
    *has = 1;
    return 0L;
}

/* Remaining wait time: orig minus elapsed since start (zeroed once the
 * deadline passes; orig again when the clock is unavailable). */
static void pl_remaining(const struct timespec *orig, int have_start,
    const struct timespec *start, struct timespec *out)
{
    if (have_start != 0) {
        struct timespec now;

        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            long long rem_ns = (long long)orig->tv_sec * 1000000000LL +
                (long long)orig->tv_nsec -
                ((long long)(now.tv_sec - start->tv_sec) * 1000000000LL +
                    (long long)(now.tv_nsec - start->tv_nsec));

            if (rem_ns < 0LL) {
                rem_ns = 0LL;
            }
            out->tv_sec = (time_t)(rem_ns / 1000000000LL);
            out->tv_nsec = (long)(rem_ns % 1000000000LL);
            return;
        }
    }
    *out = *orig;
}

/* True when a guest signal is pending and deliverable under mask. */
static int pl_deliverable(ppc32_ctx_t *ctx, uint64_t mask)
{
    uint64_t pend = __atomic_load_n(&ctx->pending_signals, __ATOMIC_ACQUIRE);

    return ((pend & ~mask) != 0ULL) ? 1 : 0;
}

/* Keep tmp in force for the tail pump; stash the pre-wait mask for the
 * frame's uc_sigmask (restored by the pump when no handler runs). */
static void pl_tmp_exit_defer(ppc32_ctx_t *ctx, uint64_t old_mask)
{
    ctx->saved_sigmask = old_mask;
    ctx->has_saved_sigmask = true;
}

/* Catchable async guest signals and their host numbers. Linux numbers
 * match the guest; Darwin remaps USR1/CHLD/CONT/TSTP. Sync faults
 * (ILL/TRAP/ABRT/BUS/FPE/SEGV) and SIGUSR2 are never in this table:
 * blocking them would wedge fault delivery or the reserved nudge.
 * Host SIGURG is likewise excluded: it is the cross-thread wake nudge
 * (ppc32_thread_signal), which must stay unblocked even when the guest
 * blocks SIGURG, or a sibling tgkill wake is swallowed. */
typedef struct {
    uint64_t guest_bit;
    int host_sig;
} pl_sigmap_t;

#ifdef __APPLE__
#define PLH_USR1 30
#define PLH_CHLD 20
#define PLH_CONT 19
#define PLH_TSTP 18
#define PLH_URG 16
#else
#define PLH_USR1 10
#define PLH_CHLD 17
#define PLH_CONT 18
#define PLH_TSTP 20
#define PLH_URG 23
#endif

static const pl_sigmap_t pl_async_sigs[] = {
    {1ULL << (PPC32_SIGHUP - 1), SIGHUP},
    {1ULL << (PPC32_SIGINT - 1), SIGINT},
    {1ULL << (PPC32_SIGQUIT - 1), SIGQUIT},
    {1ULL << (PPC32_SIGUSR1 - 1), PLH_USR1},
    {1ULL << (PPC32_SIGALRM - 1), SIGALRM},
    {1ULL << (PPC32_SIGTERM - 1), SIGTERM},
    {1ULL << (PPC32_SIGCHLD - 1), PLH_CHLD},
    {1ULL << (PPC32_SIGCONT - 1), PLH_CONT},
    {1ULL << (PPC32_SIGTSTP - 1), PLH_TSTP},
    {1ULL << (PPC32_SIGTTIN - 1), SIGTTIN},
    {1ULL << (PPC32_SIGTTOU - 1), SIGTTOU},
    {1ULL << (PPC32_SIGXCPU - 1), SIGXCPU},
    {1ULL << (PPC32_SIGXFSZ - 1), SIGXFSZ},
    {1ULL << (PPC32_SIGVTALRM - 1), SIGVTALRM},
    {1ULL << (PPC32_SIGPROF - 1), SIGPROF},
    {1ULL << (PPC32_SIGWINCH - 1), SIGWINCH},
};

#define PL_NASYNC (sizeof pl_async_sigs / sizeof pl_async_sigs[0])

/* Every catchable async host signal stays blocked across the
 * pl_deliverable check; the wait set then unblocks whichever the guest
 * tmp mask leaves unblocked, so only those can wake the wait. Host
 * SIGURG is always unblocked: it carries the sibling wake nudge. */
static void pl_wait_mask_install(uint64_t tmp_mask, sigset_t *saved,
    sigset_t *wait_mask)
{
    size_t i;

    (void)pthread_sigmask(SIG_BLOCK, NULL, saved);
    *wait_mask = *saved;
    for (i = 0U; i < PL_NASYNC; i++) {
        (void)sigaddset(wait_mask, pl_async_sigs[i].host_sig);
    }
    (void)pthread_sigmask(SIG_SETMASK, wait_mask, NULL);
    for (i = 0U; i < PL_NASYNC; i++) {
        if ((tmp_mask & pl_async_sigs[i].guest_bit) == 0ULL) {
            (void)sigdelset(wait_mask, pl_async_sigs[i].host_sig);
        }
    }
    /* A genuine host SIGURG under a blocked guest SIGURG is not guest-
     * deliverable, so the EINTR retry loop transparently re-waits. */
    (void)sigdelset(wait_mask, PLH_URG);
}

static void pl_wait_mask_restore(const sigset_t *saved)
{
    (void)pthread_sigmask(SIG_SETMASK, saved, NULL);
}

#ifdef __APPLE__
/* True when every polled fd fits an fd_set (negative fds are skipped by
 * poll and need no set slot). */
static int pl_poll_selectable(const struct pollfd *pf, uint32_t nfds)
{
    uint32_t i;

    for (i = 0U; i < nfds; i++) {
        if (pf[i].fd < 0) {
            continue;
        }
        if (pf[i].fd >= FD_SETSIZE) {
            return 0;
        }
    }
    return 1;
}

/* ppoll emulation over pselect (Darwin has no ppoll(2)): IN -> read,
 * OUT -> write, PRI -> except; hangups/errors surface as readable
 * (POLLIN; Linux would add POLLHUP/POLLERR). Unselectable fds must not
 * reach here (see pl_poll_selectable). */
static int pl_poll_pselect(struct pollfd *pf, uint32_t nfds,
    const struct timespec *to, const sigset_t *wait_mask)
{
    fd_set rs;
    fd_set ws;
    fd_set es;
    int maxfd = -1;
    uint32_t i;
    int r;

    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    for (i = 0U; i < nfds; i++) {
        int fd = pf[i].fd;

        pf[i].revents = 0;
        if (fd < 0) {
            continue;
        }
        if ((pf[i].events & POLLIN) != 0) {
            FD_SET(fd, &rs);
        }
        if ((pf[i].events & POLLOUT) != 0) {
            FD_SET(fd, &ws);
        }
        if ((pf[i].events & POLLPRI) != 0) {
            FD_SET(fd, &es);
        }
        if (fd > maxfd) {
            maxfd = fd;
        }
    }
    r = (maxfd < 0) ? pselect(0, NULL, NULL, NULL, to, wait_mask) :
        pselect(maxfd + 1, &rs, &ws, &es, to, wait_mask);
    if (r > 0) {
        for (i = 0U; i < nfds; i++) {
            int fd = pf[i].fd;
            short rev = 0;

            if (fd < 0) {
                continue;
            }
            if (FD_ISSET(fd, &rs)) {
                rev |= POLLIN;
            }
            if (FD_ISSET(fd, &ws)) {
                rev |= POLLOUT;
            }
            if (FD_ISSET(fd, &es)) {
                rev |= POLLPRI;
            }
            pf[i].revents = rev;
        }
    }
    return r;
}

/* Unselectable-fd fallback: poll(2) takes no sigmask, so run the wait
 * under the wait mask in <= 50 ms slices, re-checking deliverability
 * each slice so guest-unblocked signals still wake the wait. Returns
 * like poll (0 on expiry, -1 with errno on error/interrupt). */
static int pl_poll_fallback(struct pollfd *pf, uint32_t nfds,
    const struct timespec *orig, int have_start,
    const struct timespec *start, const sigset_t *wait_mask,
    ppc32_ctx_t *ctx, uint64_t wait_bits)
{
    for (;;) {
        struct timespec rem;
        int ms;
        int r;

        if (orig != NULL) {
            pl_remaining(orig, have_start, start, &rem);
            if (rem.tv_sec == 0 && rem.tv_nsec == 0) {
                return 0;
            }
            ms = pl_ts_to_ms(&rem);
        } else {
            ms = 50;
        }
        if (ms > 50) {
            ms = 50;
        }
        (void)pthread_sigmask(SIG_SETMASK, wait_mask, NULL);
        r = poll(pf, (nfds_t)nfds, ms);
        if (r > 0) {
            return r;
        }
        if (r < 0 && errno != EINTR) {
            return -1;
        }
        if (pl_deliverable(ctx, wait_bits)) {
            errno = EINTR;
            return -1;
        }
        if (r < 0) {
            continue;
        }
        if (orig != NULL) {
            pl_remaining(orig, have_start, start, &rem);
            if (rem.tv_sec == 0 && rem.tv_nsec == 0) {
                return 0;
            }
        }
    }
}
#endif

#endif /* PPC32RT_SYSCALLS_POLL_PRIV_H */
