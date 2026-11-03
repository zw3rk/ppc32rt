/*
 * src/os/convert.c — Big-endian guest struct conversion for ppc32rt (Phase 2, L2a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements src/os/convert.h: range-checked raw copies plus memcpy-based
 * big-endian scalar access and host<->guest struct writers. Multi-byte
 * fields always pass through ppc32_be16/32/64; char arrays (c_cc, paths)
 * are byte streams. Host 64-bit values that do not fit the 32-bit guest
 * fields (dev, ino, time) truncate with the documented wrap behavior.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/convert.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "rt32/ppc32.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>

/* See convert.h: drop the host st_atime aliases so the guest struct
 * spellings survive. Host times go through stat_sec/stat_nsec below. */
#undef st_atime
#undef st_mtime
#undef st_ctime

/* Nanosecond fields exist as st_atim.tv_nsec et al. on Linux (the only
 * runtime target); other hosts get zero (they only syntax-check). */
static uint32_t stat_nsec_at(const struct stat *hs)
{
#ifdef __linux__
    return (uint32_t)hs->st_atim.tv_nsec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    return (uint32_t)hs->st_atimespec.tv_nsec;
#else
    (void)hs;
    return 0U;
#endif
}

static uint32_t stat_nsec_mt(const struct stat *hs)
{
#ifdef __linux__
    return (uint32_t)hs->st_mtim.tv_nsec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    return (uint32_t)hs->st_mtimespec.tv_nsec;
#else
    (void)hs;
    return 0U;
#endif
}

static uint32_t stat_nsec_ct(const struct stat *hs)
{
#ifdef __linux__
    return (uint32_t)hs->st_ctim.tv_nsec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    return (uint32_t)hs->st_ctimespec.tv_nsec;
#else
    (void)hs;
    return 0U;
#endif
}

/* Host seconds: st_atim.tv_sec on Linux, plain st_atime elsewhere. */
static int32_t stat_sec_at(const struct stat *hs)
{
#ifdef __linux__
    return (int32_t)hs->st_atim.tv_sec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    return (int32_t)hs->st_atimespec.tv_sec;
#else
    return (int32_t)hs->st_atime;
#endif
}

static int32_t stat_sec_mt(const struct stat *hs)
{
#ifdef __linux__
    return (int32_t)hs->st_mtim.tv_sec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    return (int32_t)hs->st_mtimespec.tv_sec;
#else
    return (int32_t)hs->st_mtime;
#endif
}

static int32_t stat_sec_ct(const struct stat *hs)
{
#ifdef __linux__
    return (int32_t)hs->st_ctim.tv_sec;
#elif defined(__APPLE__) && defined(_DARWIN_C_SOURCE)
    return (int32_t)hs->st_ctimespec.tv_sec;
#else
    return (int32_t)hs->st_ctime;
#endif
}

int ppc32_range_ok(uint32_t va, size_t len)
{
    uint64_t end;

    if (len == 0U) {
        return 1;
    }
    if (va < PPC32_LOW_GUARD_SIZE) {
        return 0;
    }
    end = (uint64_t)va + (uint64_t)len;
    if (end > 0x100000000ULL) {
        return 0;
    }
    return 1;
}

/* P32-R4-11: byte-stream copies enforce guest sub-page permissions
 * through the permission-aware helpers (an accessible A2 host-page
 * neighbor cannot launder a read-only or unmapped target). Copyout
 * additionally invalidates overlapping LL/SC reservations and fans
 * out to staged shared-file aliases (P32-R4-12). */
int ppc32_copyin(const ppc32_ctx_t *ctx, uint32_t va, void *dst, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    if (dst == NULL) {
        return -EFAULT;
    }
    return ppc32_vm_copyin_safe(ctx, va, dst, len);
}

int ppc32_copyout(const ppc32_ctx_t *ctx, uint32_t va, const void *src, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    if (src == NULL) {
        return -EFAULT;
    }
    return ppc32_vm_copyout_safe(ctx, va, src, len);
}

int ppc32_copyin_str(const ppc32_ctx_t *ctx, uint32_t va, char *dst, size_t dstsz)
{
    size_t i;

    if (dst == NULL || dstsz == 0U) {
        return -EFAULT;
    }
    if (va < PPC32_LOW_GUARD_SIZE) {
        return -EFAULT;
    }
    for (i = 0U; i < dstsz; i++) {
        uint64_t addr = (uint64_t)va + (uint64_t)i;
        const char *p;

        if (addr >= 0x100000000ULL) {
            return -EFAULT;
        }
        p = (const char *)ppc32_guest_ptr(ctx, (uint32_t)addr);
        dst[i] = *p;
        if (*p == '\0') {
            return 0;
        }
    }
    dst[dstsz - 1U] = '\0';
    return -ENAMETOOLONG;
}

uint16_t ppc32_ld16be(const ppc32_ctx_t *ctx, uint32_t va)
{
    uint16_t w;

    memcpy(&w, ppc32_guest_ptr(ctx, va), sizeof w);
    return ppc32_be16(w);
}

uint32_t ppc32_ld32be(const ppc32_ctx_t *ctx, uint32_t va)
{
    uint32_t w;

    memcpy(&w, ppc32_guest_ptr(ctx, va), sizeof w);
    return ppc32_be32(w);
}

uint64_t ppc32_ld64be(const ppc32_ctx_t *ctx, uint32_t va)
{
    uint64_t w;

    memcpy(&w, ppc32_guest_ptr(ctx, va), sizeof w);
    return ppc32_be64(w);
}

void ppc32_st16be(const ppc32_ctx_t *ctx, uint32_t va, uint16_t v)
{
    uint16_t w = ppc32_be16(v);

    memcpy(ppc32_guest_ptr(ctx, va), &w, sizeof w);
}

void ppc32_st32be(const ppc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint32_t w = ppc32_be32(v);

    memcpy(ppc32_guest_ptr(ctx, va), &w, sizeof w);
}

void ppc32_st64be(const ppc32_ctx_t *ctx, uint32_t va, uint64_t v)
{
    uint64_t w = ppc32_be64(v);

    memcpy(ppc32_guest_ptr(ctx, va), &w, sizeof w);
}

int ppc32_put_stat(const ppc32_ctx_t *ctx, uint32_t va, const struct stat *hs)
{
    ppc32_stat_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memset(&gs, 0, sizeof gs);
    gs.st_dev = ppc32_be32((uint32_t)hs->st_dev);
    gs.st_ino = ppc32_be32((uint32_t)hs->st_ino);
    gs.st_mode = ppc32_be32((uint32_t)hs->st_mode);
    gs.st_nlink = ppc32_be16((uint16_t)hs->st_nlink);
    gs.st_uid = ppc32_be32((uint32_t)hs->st_uid);
    gs.st_gid = ppc32_be32((uint32_t)hs->st_gid);
    gs.st_rdev = ppc32_be32((uint32_t)hs->st_rdev);
    gs.st_size = (int32_t)ppc32_be32((uint32_t)hs->st_size);
    gs.st_blksize = ppc32_be32((uint32_t)hs->st_blksize);
    gs.st_blocks = ppc32_be32((uint32_t)hs->st_blocks);
    gs.st_atime = (int32_t)ppc32_be32((uint32_t)stat_sec_at(hs));
    gs.st_atime_nsec = ppc32_be32((uint32_t)stat_nsec_at(hs));
    gs.st_mtime = (int32_t)ppc32_be32((uint32_t)stat_sec_mt(hs));
    gs.st_mtime_nsec = ppc32_be32((uint32_t)stat_nsec_mt(hs));
    gs.st_ctime = (int32_t)ppc32_be32((uint32_t)stat_sec_ct(hs));
    gs.st_ctime_nsec = ppc32_be32((uint32_t)stat_nsec_ct(hs));
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_put_stat64(const ppc32_ctx_t *ctx, uint32_t va, const struct stat *hs)
{
    ppc32_stat64_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memset(&gs, 0, sizeof gs);
    gs.st_dev = ppc32_be64((uint64_t)hs->st_dev);
    gs.st_ino = ppc32_be64((uint64_t)hs->st_ino);
    gs.st_mode = ppc32_be32((uint32_t)hs->st_mode);
    gs.st_nlink = ppc32_be32((uint32_t)hs->st_nlink);
    gs.st_uid = ppc32_be32((uint32_t)hs->st_uid);
    gs.st_gid = ppc32_be32((uint32_t)hs->st_gid);
    gs.st_rdev = ppc32_be64((uint64_t)hs->st_rdev);
    gs.st_size = (int64_t)ppc32_be64((uint64_t)hs->st_size);
    gs.st_blksize = (int32_t)ppc32_be32((uint32_t)hs->st_blksize);
    gs.st_blocks = (int64_t)ppc32_be64((uint64_t)hs->st_blocks);
    gs.st_atime = (int32_t)ppc32_be32((uint32_t)stat_sec_at(hs));
    gs.st_atime_nsec = ppc32_be32((uint32_t)stat_nsec_at(hs));
    gs.st_mtime = (int32_t)ppc32_be32((uint32_t)stat_sec_mt(hs));
    gs.st_mtime_nsec = ppc32_be32((uint32_t)stat_nsec_mt(hs));
    gs.st_ctime = (int32_t)ppc32_be32((uint32_t)stat_sec_ct(hs));
    gs.st_ctime_nsec = ppc32_be32((uint32_t)stat_nsec_ct(hs));
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_put_timespec(const ppc32_ctx_t *ctx, uint32_t va, const struct timespec *hs)
{
    ppc32_timespec_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    gs.tv_sec = (int32_t)ppc32_be32((uint32_t)hs->tv_sec);
    gs.tv_nsec = (int32_t)ppc32_be32((uint32_t)hs->tv_nsec);
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_put_timeval(const ppc32_ctx_t *ctx, uint32_t va, const struct timeval *hs)
{
    ppc32_timeval_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    gs.tv_sec = (int32_t)ppc32_be32((uint32_t)hs->tv_sec);
    gs.tv_usec = (int32_t)ppc32_be32((uint32_t)hs->tv_usec);
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_get_timespec(const ppc32_ctx_t *ctx, uint32_t va, struct timespec *hs)
{
    ppc32_timespec_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memcpy(&gs, ppc32_guest_ptr(ctx, va), sizeof gs);
    hs->tv_sec = (time_t)(int32_t)ppc32_be32((uint32_t)gs.tv_sec);
    hs->tv_nsec = (long)(int32_t)ppc32_be32((uint32_t)gs.tv_nsec);
    return 0;
}

int ppc32_termios_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct termios *hs)
{
#ifdef __linux__
    ppc32_termios_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memset(&gs, 0, sizeof gs);
    gs.c_iflag = ppc32_be32((uint32_t)hs->c_iflag);
    gs.c_oflag = ppc32_be32((uint32_t)hs->c_oflag);
    gs.c_cflag = ppc32_be32((uint32_t)hs->c_cflag);
    gs.c_lflag = ppc32_be32((uint32_t)hs->c_lflag);
    gs.c_line = hs->c_line;
    memcpy(gs.c_cc, hs->c_cc,
        sizeof gs.c_cc < sizeof hs->c_cc ? sizeof gs.c_cc : sizeof hs->c_cc);
    #if defined(__GLIBC__)
    gs.c_ispeed = ppc32_be32((uint32_t)hs->c_ispeed);
    gs.c_ospeed = ppc32_be32((uint32_t)hs->c_ospeed);
#else
    gs.c_ispeed = ppc32_be32((uint32_t)hs->__c_ispeed);
    gs.c_ospeed = ppc32_be32((uint32_t)hs->__c_ospeed);
#endif
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
#else
    (void)ctx;
    (void)va;
    (void)hs;
    return -ENOSYS;
#endif
}

int ppc32_termios_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct termios *hs)
{
#ifdef __linux__
    ppc32_termios_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memcpy(&gs, ppc32_guest_ptr(ctx, va), sizeof gs);
    memset(hs, 0, sizeof *hs);
    hs->c_iflag = (tcflag_t)ppc32_be32(gs.c_iflag);
    hs->c_oflag = (tcflag_t)ppc32_be32(gs.c_oflag);
    hs->c_cflag = (tcflag_t)ppc32_be32(gs.c_cflag);
    hs->c_lflag = (tcflag_t)ppc32_be32(gs.c_lflag);
    hs->c_line = (cc_t)gs.c_line;
    memcpy(hs->c_cc, gs.c_cc,
        sizeof gs.c_cc < sizeof hs->c_cc ? sizeof gs.c_cc : sizeof hs->c_cc);
    #if defined(__GLIBC__)
    hs->c_ispeed = (speed_t)ppc32_be32(gs.c_ispeed);
    hs->c_ospeed = (speed_t)ppc32_be32(gs.c_ospeed);
#else
    hs->__c_ispeed = (speed_t)ppc32_be32(gs.c_ispeed);
    hs->__c_ospeed = (speed_t)ppc32_be32(gs.c_ospeed);
#endif
    return 0;
#else
    (void)ctx;
    (void)va;
    (void)hs;
    return -ENOSYS;
#endif
}

int ppc32_winsize_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct winsize *hs)
{
    ppc32_winsize_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    gs.ws_row = ppc32_be16(hs->ws_row);
    gs.ws_col = ppc32_be16(hs->ws_col);
    gs.ws_xpixel = ppc32_be16(hs->ws_xpixel);
    gs.ws_ypixel = ppc32_be16(hs->ws_ypixel);
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_winsize_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct winsize *hs)
{
    ppc32_winsize_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memcpy(&gs, ppc32_guest_ptr(ctx, va), sizeof gs);
    hs->ws_row = ppc32_be16(gs.ws_row);
    hs->ws_col = ppc32_be16(gs.ws_col);
    hs->ws_xpixel = ppc32_be16(gs.ws_xpixel);
    hs->ws_ypixel = ppc32_be16(gs.ws_ypixel);
    return 0;
}

int ppc32_flock_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct flock *hs)
{
    ppc32_flock_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memset(&gs, 0, sizeof gs);
    gs.l_type = (int16_t)ppc32_be16((uint16_t)hs->l_type);
    gs.l_whence = (int16_t)ppc32_be16((uint16_t)hs->l_whence);
    gs.l_start = (int32_t)ppc32_be32((uint32_t)hs->l_start);
    gs.l_len = (int32_t)ppc32_be32((uint32_t)hs->l_len);
    gs.l_pid = (int32_t)ppc32_be32((uint32_t)hs->l_pid);
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_flock_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct flock *hs)
{
    ppc32_flock_t gs;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memcpy(&gs, ppc32_guest_ptr(ctx, va), sizeof gs);
    memset(hs, 0, sizeof *hs);
    hs->l_type = (short)(int16_t)ppc32_be16((uint16_t)gs.l_type);
    hs->l_whence = (short)(int16_t)ppc32_be16((uint16_t)gs.l_whence);
    hs->l_start = (off_t)(int32_t)ppc32_be32((uint32_t)gs.l_start);
    hs->l_len = (off_t)(int32_t)ppc32_be32((uint32_t)gs.l_len);
    hs->l_pid = (pid_t)(int32_t)ppc32_be32((uint32_t)gs.l_pid);
    return 0;
}

int ppc32_flock64_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct flock *hs)
{
    ppc32_flock64_t gs;
    uint64_t w;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    /* Read-modify-write: the 4-byte pad (and any tail bytes) keep
     * whatever the guest had; the oracle never touches them. */
    memcpy(&gs, ppc32_guest_ptr(ctx, va), sizeof gs);
    gs.l_type = (int16_t)ppc32_be16((uint16_t)hs->l_type);
    gs.l_whence = (int16_t)ppc32_be16((uint16_t)hs->l_whence);
    w = ppc32_be64((uint64_t)hs->l_start);
    memcpy(gs.l_start, &w, sizeof w);
    w = ppc32_be64((uint64_t)hs->l_len);
    memcpy(gs.l_len, &w, sizeof w);
    gs.l_pid = (int32_t)ppc32_be32((uint32_t)hs->l_pid);
    memcpy(ppc32_guest_ptr(ctx, va), &gs, sizeof gs);
    return 0;
}

int ppc32_flock64_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct flock *hs)
{
    ppc32_flock64_t gs;
    uint64_t w;

    if (hs == NULL || !ppc32_range_ok(va, sizeof gs)) {
        return -EFAULT;
    }
    memcpy(&gs, ppc32_guest_ptr(ctx, va), sizeof gs);
    memset(hs, 0, sizeof *hs);
    hs->l_type = (short)(int16_t)ppc32_be16((uint16_t)gs.l_type);
    hs->l_whence = (short)(int16_t)ppc32_be16((uint16_t)gs.l_whence);
    memcpy(&w, gs.l_start, sizeof w);
    hs->l_start = (off_t)(int64_t)ppc32_be64(w);
    memcpy(&w, gs.l_len, sizeof w);
    hs->l_len = (off_t)(int64_t)ppc32_be64(w);
    hs->l_pid = (pid_t)(int32_t)ppc32_be32((uint32_t)gs.l_pid);
    return 0;
}
