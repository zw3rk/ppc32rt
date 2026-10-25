/*
 * src/os/convert.h — Big-endian guest struct conversion for ppc32rt (Phase 2, L2a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest layouts follow Linux arch/powerpc UAPI (asm/stat.h, asm/termbits.h):
 * every multi-byte field is big-endian on the wire, so all access goes
 * through the ppc32_ld/st_be helpers below (REV16/REV under the DBT).
 * Char buffers are byte streams: no byte-swap.
 *
 * `struct stat` (old, nrs 106/107/108) is 72 bytes; `struct stat64`
 * (nrs 195/196/197) is 104 bytes with the E04-verified offsets.
 */

#ifndef PPC32_CONVERT_H
#define PPC32_CONVERT_H

#include <stddef.h>
#include <stdint.h>

#include "ppc32rt.h"

/* musl/glibc spell the host members st_atim/st_mtim/st_ctim and keep
 * st_atime et al. as function-like/object macros; the guest structs below
 * use the kernel spellings, so the aliases are dropped here (undefining
 * an undefined macro is a no-op). Host times always go through the
 * stat_sec/stat_nsec helpers in convert.c, never these spellings. */
#undef st_atime
#undef st_mtime
#undef st_ctime

/* Forward declarations so this header needs no system headers. */
struct stat;
struct timespec;
struct timeval;

/* Replica of the ppc32 kernel struct stat (asm/stat.h, 32-bit only). */
typedef struct ppc32_stat {
    uint32_t st_dev;
    uint32_t st_ino;
    uint32_t st_mode;
    uint16_t st_nlink;
    uint16_t st_pad_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t st_rdev;
    int32_t  st_size;
    uint32_t st_blksize;
    uint32_t st_blocks;
    int32_t  st_atime;
    uint32_t st_atime_nsec;
    int32_t  st_mtime;
    uint32_t st_mtime_nsec;
    int32_t  st_ctime;
    uint32_t st_ctime_nsec;
    uint32_t st_unused4;
    uint32_t st_unused5;
} ppc32_stat_t;

/* Replica of the ppc32 kernel struct stat64 (asm/stat.h, E04-verified). */
typedef struct ppc32_stat64 {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint16_t st_pad2;
    uint8_t  st_pad2b[6];
    int64_t  st_size;
    int32_t  st_blksize;
    int64_t  st_blocks;
    int32_t  st_atime;
    uint32_t st_atime_nsec;
    int32_t  st_mtime;
    uint32_t st_mtime_nsec;
    int32_t  st_ctime;
    uint32_t st_ctime_nsec;
    uint32_t st_unused4;
    uint32_t st_unused5;
} ppc32_stat64_t;

/* Guest struct timespec/timeval/iovec/flock/termios/winsize (all BE). */
typedef struct ppc32_timespec {
    int32_t  tv_sec;
    int32_t  tv_nsec;
} ppc32_timespec_t;

typedef struct ppc32_timeval {
    int32_t tv_sec;
    int32_t tv_usec;
} ppc32_timeval_t;

typedef struct ppc32_iovec {
    uint32_t iov_base;
    uint32_t iov_len;
} ppc32_iovec_t;

typedef struct ppc32_flock {
    int16_t  l_type;
    int16_t  l_whence;
    int32_t  l_start;
    int32_t  l_len;
    int32_t  l_pid;
} ppc32_flock_t;

/* Guest struct flock64 (powerpc uapi: short, short, 4-byte pad,
 * 64-bit start, 64-bit len, 32-bit pid; 28 bytes). The pad keeps the
 * 64-bit fields 8-aligned at guest offsets 8 and 16 with l_pid at 24
 * (verified against the qemu-ppc oracle: GETLK reports the holder pid
 * at offset 24, and offsets 4..7 come back untouched). Raw BE byte
 * arrays avoid host alignment padding. glibc on 32-bit PPC issues all
 * lock commands (F_GETLK/F_SETLK/F_SETLKW) as their 64-bit numbers
 * 12/13/14 with this layout (its struct flock is this plus 4 bytes of
 * tail padding, 32 bytes total). */
typedef struct ppc32_flock64 {
    int16_t  l_type;
    int16_t  l_whence;
    uint8_t  l_pad[4];
    uint8_t  l_start[8];
    uint8_t  l_len[8];
    int32_t  l_pid;
} ppc32_flock64_t;

typedef struct ppc32_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t  c_line;
    uint8_t  c_cc[32];
    uint32_t c_ispeed;
    uint32_t c_ospeed;
} ppc32_termios_t;

typedef struct ppc32_winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
} ppc32_winsize_t;

_Static_assert(sizeof(ppc32_stat_t) == 72, "ppc32 struct stat must be 72 bytes");
_Static_assert(offsetof(ppc32_stat_t, st_uid) == 16, "st_uid offset");
_Static_assert(offsetof(ppc32_stat_t, st_size) == 28, "st_size offset");
_Static_assert(offsetof(ppc32_stat_t, st_atime) == 40, "st_atime offset");
_Static_assert(sizeof(ppc32_stat64_t) == 104, "ppc32 struct stat64 must be 104 bytes");
_Static_assert(offsetof(ppc32_stat64_t, st_dev) == 0x0, "stat64 st_dev offset");
_Static_assert(offsetof(ppc32_stat64_t, st_ino) == 0x8, "stat64 st_ino offset");
_Static_assert(offsetof(ppc32_stat64_t, st_mode) == 0x10, "stat64 st_mode offset");
_Static_assert(offsetof(ppc32_stat64_t, st_uid) == 0x18, "stat64 st_uid offset");
_Static_assert(offsetof(ppc32_stat64_t, st_rdev) == 0x20, "stat64 st_rdev offset");
_Static_assert(offsetof(ppc32_stat64_t, st_size) == 0x30, "stat64 st_size offset");
_Static_assert(offsetof(ppc32_stat64_t, st_blksize) == 0x38, "stat64 st_blksize offset");
_Static_assert(offsetof(ppc32_stat64_t, st_blocks) == 0x40, "stat64 st_blocks offset");
_Static_assert(offsetof(ppc32_stat64_t, st_atime) == 0x48, "stat64 st_atime offset");
_Static_assert(offsetof(ppc32_stat64_t, st_mtime) == 0x50, "stat64 st_mtime offset");
_Static_assert(offsetof(ppc32_stat64_t, st_ctime) == 0x58, "stat64 st_ctime offset");
_Static_assert(sizeof(ppc32_flock64_t) == 28, "ppc32 struct flock64 must be 28 bytes");
_Static_assert(offsetof(ppc32_flock64_t, l_start) == 8, "flock64 l_start offset");
_Static_assert(offsetof(ppc32_flock64_t, l_len) == 16, "flock64 l_len offset");
_Static_assert(offsetof(ppc32_flock64_t, l_pid) == 24, "flock64 l_pid offset");

/* Guest range check: len bytes at va stay inside the 4 GiB window without
 * wrapping, and a nonzero access never touches the low guard page. */
int ppc32_range_ok(uint32_t va, size_t len);

/* Byte streams: raw copy between guest window and host, no byte-swap.
 * Return 0 on success, -EFAULT on a bad range. */
int ppc32_copyin(const ppc32_ctx_t *ctx, uint32_t va, void *dst, size_t len);
int ppc32_copyout(const ppc32_ctx_t *ctx, uint32_t va, const void *src, size_t len);

/* NUL-terminated string fetch: copies at most dstsz-1 bytes plus NUL.
 * Returns 0, -EFAULT (bad range / page wrap), or -ENAMETOOLONG. */
int ppc32_copyin_str(const ppc32_ctx_t *ctx, uint32_t va, char *dst, size_t dstsz);

/* Big-endian scalar guest access (memcpy-based: no alignment assumptions). */
uint16_t ppc32_ld16be(const ppc32_ctx_t *ctx, uint32_t va);
uint32_t ppc32_ld32be(const ppc32_ctx_t *ctx, uint32_t va);
uint64_t ppc32_ld64be(const ppc32_ctx_t *ctx, uint32_t va);
void     ppc32_st16be(const ppc32_ctx_t *ctx, uint32_t va, uint16_t v);
void     ppc32_st32be(const ppc32_ctx_t *ctx, uint32_t va, uint32_t v);
void     ppc32_st64be(const ppc32_ctx_t *ctx, uint32_t va, uint64_t v);

/* Host stat -> guest layout writers. Return 0 or -EFAULT. */
int ppc32_put_stat(const ppc32_ctx_t *ctx, uint32_t va, const struct stat *hs);
int ppc32_put_stat64(const ppc32_ctx_t *ctx, uint32_t va, const struct stat *hs);

/* Time writers: host -> BE guest. Return 0 or -EFAULT. */
int ppc32_put_timespec(const ppc32_ctx_t *ctx, uint32_t va, const struct timespec *hs);
int ppc32_put_timeval(const ppc32_ctx_t *ctx, uint32_t va, const struct timeval *hs);

/* BE guest timespec -> host (futex timeout). Return 0 or -EFAULT. */
int ppc32_get_timespec(const ppc32_ctx_t *ctx, uint32_t va, struct timespec *hs);

/* Terminal structs. Directions are named from the guest's view:
 * to_guest fills the guest struct after a host ioctl(TCGETS/...);
 * from_guest fills the host struct before ioctl(TCSETS/...). */
struct termios;
struct winsize;
struct flock;
int ppc32_termios_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct termios *hs);
int ppc32_termios_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct termios *hs);
int ppc32_winsize_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct winsize *hs);
int ppc32_winsize_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct winsize *hs);
int ppc32_flock_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct flock *hs);
int ppc32_flock_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct flock *hs);
/* 64-bit lock layout (F_GETLK64/F_SETLK64/F_SETLKW64 = 12/13/14). */
int ppc32_flock64_to_guest(const ppc32_ctx_t *ctx, uint32_t va,
    const struct flock *hs);
int ppc32_flock64_from_guest(const ppc32_ctx_t *ctx, uint32_t va,
    struct flock *hs);

#endif /* PPC32_CONVERT_H */
