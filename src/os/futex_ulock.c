/*
 * src/os/futex_ulock.c — Non-Linux futex emulation via Darwin __ulock
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Backend-contract futex waits/wakes for hosts without futex(2)
 * (mirrors ppc64rt src/os/backend_futex.c): Linux uses the futex
 * syscall (threads.c futex_host); Darwin sleeps via __ulock_wait2 and
 * wakes via __ulock_wake. Only the full 32-bit mask applies (__ulock
 * has no bitset select); requeue is a documented wake-only fallback
 * since waiters cannot move atomically (a later wake collects them).
 *
 * Returns guest-visible Linux errno negatives (EAGAIN 11, ETIMEDOUT
 * 110 differ from the Darwin host values, so they are spelled out).
 */

#define _POSIX_C_SOURCE 200809L

#include "os/threads.h"

#include <errno.h>
#include <stdint.h>
#include <time.h>

/* Guest-visible Linux errno numbers (host values differ on Darwin). */
#define UL_LINUX_EAGAIN 11
#define UL_LINUX_ETIMEDOUT 110
#define UL_LINUX_EINVAL 22

#if defined(__APPLE__)
extern int __ulock_wait2(uint32_t operation, void *addr, uint64_t value,
    uint64_t timeout_ns, uint64_t value2);
extern int __ulock_wake(uint32_t operation, void *addr,
    uint64_t wake_value);

enum {
    ULOCK_COMPARE_AND_WAIT = 1,
    ULOCK_WAKE_ALL = 0x00000100
};

static long ul_errno(void)
{
    if (errno == ETIMEDOUT) {
        return -UL_LINUX_ETIMEDOUT;
    }
    if (errno == EAGAIN) {
        return -UL_LINUX_EAGAIN;
    }
    if (errno == EINTR) {
        return -(long)EINTR;
    }
    if (errno == EFAULT) {
        return -(long)EFAULT;
    }
    return -UL_LINUX_EINVAL;
}
#endif

/* Emulated futex op (same arg shape as threads.c futex_host): uaddr is
 * the pinned host word, op carries PRIVATE/CLOCK bits plus the low cmd
 * nibble (WAIT 0, WAKE 1, REQUEUE 3, CMP_REQUEUE 4), val is the
 * host-endian comparand for WAIT/CMP_REQUEUE and the count otherwise,
 * timeout a relative bound for WAIT, uaddr2/val3 the requeue target
 * and CMP comparand. */
long ppc32_futex_emul(int32_t *uaddr, uint32_t op, int32_t val,
    const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
#if defined(__APPLE__)
    uint32_t cmd = op & 15U;

    if (cmd == PPC32_FUTEX_WAIT) {
        uint64_t timeout_ns = 0ULL;

        if (uaddr == NULL) {
            return -UL_LINUX_EINVAL;
        }
        if ((uint32_t)*uaddr != (uint32_t)val) {
            return -UL_LINUX_EAGAIN;
        }
        if (timeout != NULL) {
            if (timeout->tv_sec < 0 ||
                timeout->tv_nsec < 0L ||
                timeout->tv_nsec >= 1000000000L) {
                return -UL_LINUX_EINVAL;
            }
            timeout_ns = (uint64_t)timeout->tv_sec * 1000000000ULL +
                (uint64_t)timeout->tv_nsec;
        }
        if (__ulock_wait2((uint32_t)ULOCK_COMPARE_AND_WAIT,
                (void *)uaddr, (uint64_t)(uint32_t)val, timeout_ns,
                0ULL) != 0) {
            return ul_errno();
        }
        return 0L;
    }
    if (cmd == PPC32_FUTEX_WAKE) {
        uint32_t wake_op = (uint32_t)ULOCK_COMPARE_AND_WAIT;
        int64_t count = (int64_t)val;

        if (uaddr == NULL || count < 0) {
            return -UL_LINUX_EINVAL;
        }
        if (count >= 2147483647LL) {
            wake_op |= (uint32_t)ULOCK_WAKE_ALL;
        }
        if (__ulock_wake(wake_op, (void *)uaddr,
                (uint64_t)(uint32_t)count) != 0) {
            if (errno == ENOENT) {
                return 0L;
            }
            return ul_errno();
        }
        return 0L;
    }
    if (cmd == PPC32_FUTEX_REQUEUE || cmd == PPC32_FUTEX_CMP_REQUEUE) {
        long woken;

        if (uaddr == NULL || uaddr2 == NULL || val < 0) {
            return -UL_LINUX_EINVAL;
        }
        if (cmd == PPC32_FUTEX_CMP_REQUEUE &&
            (uint32_t)*uaddr != (uint32_t)val3) {
            return -UL_LINUX_EAGAIN;
        }
        woken = ppc32_futex_emul(uaddr, PPC32_FUTEX_WAKE, val, NULL,
            NULL, 0);
        return woken;
    }
    return -UL_LINUX_EINVAL;
#else
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout;
    (void)uaddr2;
    (void)val3;
    return -(long)ENOSYS;
#endif
}
