/*
 * src/os/syscalls.c — Full static-libc PPC32 Linux syscall layer (Phase 2, L2a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * PPC32 `sc` convention (SPEC 2.3, experiments/E01): number in r0,
 * arguments in r3..r8; 64-bit arguments ride consecutive register pairs
 * high word first. Success: CR0.SO=0, r3=(uint32_t)ret. Error:
 * CR0.SO=1, r3=(uint32_t)(-ret). Unknown numbers take the -ENOSYS error
 * path. nip advances past the 4-byte sc on return.
 *
 * Memory-backed calls delegate to the frozen rt32 window manager
 * (src/rt32/ppc32.h); fd and time calls use direct host calls. Char
 * buffers are byte streams (no byte-swap); every multi-byte struct
 * field converts through os/convert.h. Four guest O_* flag bits differ
 * from the host asm-generic layout (DIRECTORY/NOFOLLOW/LARGEFILE/DIRECT),
 * so syscalls_file.c translates them on every open/fcntl crossing.
 * Phase 4
 * (RC4) wires the lane-owned layers: signals via os/signals.h
 * (ppc32_sig_syscall, no-advance rt_sigreturn), threads via os/threads.h
 * (clone/futex/set_tid_address), and process lifecycle via os/proc.h
 * (fork/execve/wait4/pipe/dup2). Old-style sigaction/sigprocmask stay
 * -ENOSYS (the static-libc oracle path uses the rt_* variants).
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "os/syscalls.h"
#include "dbt/dbt.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/proc.h"
#include "os/procfs.h"
#include "os/signals.h"
#include "os/syscall_nr.h"
#include "os/threads.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"
#include "vm/vm32.h"

#ifdef __linux__
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <termios.h>
#endif

/* See convert.h: drop the host st_atime aliases so guest spellings survive. */
#undef st_atime
#undef st_mtime
#undef st_ctime

/* Extended Provider-A helper (defined in src/vm/vm_file.c): identity
 * truncate matches one (host_fd, st_dev, st_ino) mapping. Declared at
 * use so the shared vm32.h contract stays untouched (RC-U3-r2 #4). */
int vm_file_on_truncate_fd(int host_fd, uint64_t new_size);

/* Numbers absent from the frozen os/syscall_nr.h (powerpc syscall.tbl):
 * clock_gettime 246, openat 286, getrandom 359. Guarded so a future
 * header update wins. */
#ifndef PPC32_NR_CLOCK_GETTIME
#define PPC32_NR_CLOCK_GETTIME 246U
#endif
#ifndef PPC32_NR_CLOCK_GETTIME64
#define PPC32_NR_CLOCK_GETTIME64 403U
#endif
#ifndef PPC32_NR_OPENAT
#define PPC32_NR_OPENAT 286U
#endif
#ifndef PPC32_NR_GETRANDOM
#define PPC32_NR_GETRANDOM 359U
#endif

/* ppc utsname: six NUL-padded fields of 65 bytes (matches i686 layout). */
#define PPC32_UTS_FIELD 65U
#define PPC32_UTS_FIELDS 6U

#define PPC32_IOV_CHUNK 16U
#define PPC32_IOV_MAX 1024U

/* Convert a host return (bytes or negative errno) to the kernel-style
 * long the return convention below classifies: negative errno stays
 * negative, values stay non-negative. Short counts are real results. */
static long host_ret(ssize_t n, int err)
{
    if (n < 0) {
        return -(long)err;
    }
    return (long)n;
}

/* P1: read/pread64 helper; landed bytes evict overlapping blocks. */
static long sys_read_at(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va,
    uint32_t count, bool use_pread, int64_t off)
{
    ssize_t n;

    if (count > 0U && !ppc32_range_ok(buf_va, count)) {
        return -EFAULT;
    }
    n = use_pread ? pread((int)fd, ppc32_guest_ptr(ctx, buf_va),
        (size_t)count, (off_t)off) :
        read((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    if (n > 0) {
        ppc32_smc_store(ctx, buf_va, (uint32_t)n, NULL);
    }
    return host_ret(n, errno);
}

static long sys_write(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    ssize_t n;

    if (count > 0U && !ppc32_range_ok(buf_va, count)) {
        return -EFAULT;
    }
    n = write((int)fd, ppc32_guest_ptr(ctx, buf_va), (size_t)count);
    if (n > 0) {
        /* Provider-A hook: an extending write moves the inode EOF
         * forward (no-op until a file mapping registers the fd). */
        off_t end = lseek((int)fd, 0, SEEK_CUR);

        if (end >= (off_t)0) {
            (void)vm_file_hook_write((int)fd, (uint64_t)end);
        }
    }
    return host_ret(n, errno);
}

/* Chunked vectored I/O: a fixed host iovec array (no VLA) walks the BE
 * guest array; partial transfers return the bytes moved so far. */
static long sys_vec(ppc32_ctx_t *ctx, uint32_t fd, uint32_t iov_va,
    uint32_t count, int is_write)
{
    struct iovec hv[PPC32_IOV_CHUNK];
    uint64_t total = 0ULL;
    uint32_t done = 0U;

    if (count == 0U) {
        return 0;
    }
    if (count > PPC32_IOV_MAX) {
        return -EINVAL;
    }
    if (!ppc32_range_ok(iov_va, (size_t)count * sizeof(ppc32_iovec_t))) {
        return -EFAULT;
    }
    while (done < count) {
        uint32_t n = count - done;
        size_t want = 0U;
        ssize_t got;
        uint32_t j;

        if (n > PPC32_IOV_CHUNK) {
            n = PPC32_IOV_CHUNK;
        }
        for (j = 0U; j < n; j++) {
            uint32_t base = ppc32_ld32be(ctx, iov_va + (done + j) * 8U);
            uint32_t len = ppc32_ld32be(ctx, iov_va + (done + j) * 8U + 4U);

            if (len > 0U && !ppc32_range_ok(base, len)) {
                return total > 0ULL ? (long)total : -EFAULT;
            }
            hv[j].iov_base = ppc32_guest_ptr(ctx, base);
            hv[j].iov_len = (size_t)len;
            want += (size_t)len;
        }
        got = is_write ? writev((int)fd, hv, (int)n) : readv((int)fd, hv, (int)n);
        if (got < 0) {
            return total > 0ULL ? (long)total : -(long)errno;
        }
        total += (uint64_t)got;
        done += n;
        if ((uint64_t)got < (uint64_t)want) {
            break;
        }
    }
    if (is_write == 0 && total > 0ULL) { /* P1: readv landed; evict. */
        uint32_t i;
        for (i = 0U; i < count && total > 0ULL; i++) {
            uint32_t len = ppc32_ld32be(ctx, iov_va + i * 8U + 4U);
            uint32_t hit = len > total ? (uint32_t)total : len;
            ppc32_smc_store(ctx, ppc32_ld32be(ctx, iov_va + i * 8U), hit,
                NULL);
            total -= hit;
        }
    }
    if (is_write != 0 && total > 0ULL) {
        /* Same Provider-A EOF hook as sys_write above. */
        off_t end = lseek((int)fd, 0, SEEK_CUR);

        if (end >= (off_t)0) {
            (void)vm_file_hook_write((int)fd, (uint64_t)end);
        }
    }
    return (long)total;
}

/* File opens live in syscalls_file.c (PPC/host O_* translation). */

static long sys_close(uint32_t fd)
{
    if (close((int)fd) != 0) {
        return -(long)errno;
    }
    return 0;
}

/* RC2: glibc remove() lowers to classic unlink(10) (qemu-strace proven). */
static long sys_unlink(ppc32_ctx_t *ctx, uint32_t path_va)
{
    char path[PPC32_PATH_MAX];

    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if (unlink(path) != 0) {
        return -(long)errno;
    }
    return 0;
}

static long sys_lseek(uint32_t fd, uint32_t offset, uint32_t whence)
{
    off_t r = lseek((int)fd, (off_t)(int32_t)offset, (int)whence);

    if (r == (off_t)-1) {
        return -(long)errno;
    }
    return (long)r;
}

/* Provider-A truncate hook: the host call resizes first; only then
 * does the mem layer discard/regrow translations (section 4.5). The
 * identity form moves just the truncated file's mapping (RC-U3-r2 #4). */
static long sys_ftruncate(uint32_t fd, uint32_t length)
{
    if (ftruncate((int)fd, (off_t)length) != 0) {
        return -(long)errno;
    }
    (void)vm_file_on_truncate_fd((int)fd, (uint64_t)length);
    return 0;
}

/* Bonus (file I/O): ppc llseek(140) carries the 64-bit offset as a
 * high/low word pair and stores the result through a BE u64 pointer. */
static long sys_llseek(ppc32_ctx_t *ctx, uint32_t fd, uint32_t hi,
    uint32_t lo, uint32_t res_va, uint32_t whence)
{
    int64_t off = ((int64_t)(int32_t)hi << 32) | (int64_t)(uint64_t)lo;
    off_t r = lseek((int)fd, (off_t)off, (int)whence);

    if (r == (off_t)-1) {
        return -(long)errno;
    }
    if (!ppc32_range_ok(res_va, 8U)) {
        return -EFAULT;
    }
    ppc32_st64be(ctx, res_va, (uint64_t)(int64_t)r);
    return 0;
}

static long sys_brk(ppc32_ctx_t *ctx, uint32_t new_brk)
{
    /* ppc32_vm_brk: new_brk == 0 reads the current break; otherwise it
     * grows/shrinks the heap and returns the new (or old, when invalid)
     * break, matching Linux brk semantics. The u32 packs addresses and
     * (uint32_t)-errno alike; sign-extend so errors stay negative. */
    return (long)(int32_t)ppc32_vm_brk(ctx, new_brk);
}

static long sys_mmap2(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
    uint32_t flags, uint32_t fd, uint32_t pgoffset)
{
    /* Guest PPC MAP bits (SHARED 0x01, PRIVATE 0x02, FIXED 0x10,
     * ANONYMOUS 0x20) match the vm layer's expectations; pass through.
     * (int)fd keeps -1 anonymous maps. */
    uint32_t r = ppc32_vm_mmap2(ctx, addr, len, prot, flags, (int)fd, pgoffset);

    return (long)(int32_t)r;
}

static long sys_mmap(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
    uint32_t flags, uint32_t fd, uint32_t offset)
{
    /* PowerPC sys_mmap(90) takes a byte offset; the vm layer takes pages. */
    if ((offset & (PPC32_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    return sys_mmap2(ctx, addr, len, prot, flags, fd, offset >> 12U);
}

static long sys_munmap(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    return (long)ppc32_vm_munmap(ctx, addr, len);
}

static long sys_mprotect(ppc32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    return (long)ppc32_vm_mprotect(ctx, addr, len, prot);
}

static long sys_uname(ppc32_ctx_t *ctx, uint32_t buf_va)
{
    static const char *const fields[PPC32_UTS_FIELDS] = {
        "Linux",
        "ppc32rt",
        "6.1.0",
        "#1 SMP ppc32rt",
        "ppc",
        "(none)",
    };
    uint8_t *buf;
    size_t i;
    size_t j;

    if (!ppc32_range_ok(buf_va, PPC32_UTS_FIELD * PPC32_UTS_FIELDS)) {
        return -EFAULT;
    }
    buf = (uint8_t *)ppc32_guest_ptr(ctx, buf_va);
    for (i = 0U; i < PPC32_UTS_FIELDS; i++) {
        uint8_t *field = buf + (size_t)i * PPC32_UTS_FIELD;

        memset(field, 0, PPC32_UTS_FIELD);
        for (j = 0U; fields[i][j] != '\0' && j < PPC32_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)fields[i][j];
        }
    }
    return 0;
}

static long sys_stat_path(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t buf_va,
    uint32_t use64, int nofollow)
{
    char path[PPC32_PATH_MAX];
    struct stat hs;

    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    if ((nofollow ? lstat(path, &hs) : stat(path, &hs)) != 0) {
        return -(long)errno;
    }
    if (use64 != 0U) {
        return (long)ppc32_put_stat64(ctx, buf_va, &hs);
    }
    return (long)ppc32_put_stat(ctx, buf_va, &hs);
}

static long sys_fstat(ppc32_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t use64)
{
    struct stat hs;

    if (fstat((int)fd, &hs) != 0) {
        return -(long)errno;
    }
    if (use64 != 0U) {
        return (long)ppc32_put_stat64(ctx, buf_va, &hs);
    }
    return (long)ppc32_put_stat(ctx, buf_va, &hs);
}

static long sys_clock_gettime(ppc32_ctx_t *ctx, uint32_t clk, uint32_t ts_va,
    int is64)
{
    struct timespec ts;
    clockid_t hclk = (clockid_t)clk;

#ifdef __APPLE__
    hclk = (clk == 1U || clk == 4U || clk == 6U || clk == 7U) ?
        CLOCK_MONOTONIC : CLOCK_REALTIME;
#endif
    if (clock_gettime(hclk, &ts) != 0) {
        return -(long)errno;
    }
    if (is64) {
        if (!ppc32_range_ok(ts_va, 16U)) {
            return -EFAULT;
        }
        ppc32_st64be(ctx, ts_va, (uint64_t)(int64_t)ts.tv_sec);
        ppc32_st64be(ctx, ts_va + 8U, (uint64_t)(int64_t)ts.tv_nsec);
        return 0L;
    }
    return (long)ppc32_put_timespec(ctx, ts_va, &ts);
}

static long sys_gettimeofday(ppc32_ctx_t *ctx, uint32_t tv_va)
{
    struct timeval tv;

    /* The guest tz argument is obsolete on Linux; always ignore it. */
    if (gettimeofday(&tv, NULL) != 0) {
        return -(long)errno;
    }
    return (long)ppc32_put_timeval(ctx, tv_va, &tv);
}

static long sys_getrandom(ppc32_ctx_t *ctx, uint32_t buf_va, uint32_t len,
    uint32_t flags)
{
#ifdef __linux__
    ssize_t n;

    if (len > 0U && !ppc32_range_ok(buf_va, len)) {
        return -EFAULT;
    }
    /* GRND_* flag bits are Linux-generic: pass through. */
    n = getrandom(ppc32_guest_ptr(ctx, buf_va), (size_t)len, (unsigned int)flags);
    return host_ret(n, errno);
#else
    (void)ctx;
    (void)buf_va;
    (void)len;
    (void)flags;
    return -ENOSYS;
#endif
}

/* E01 return convention (SPEC 2.3, experiments/E01): classify on the
 * kernel-style long, never on the magnitude of the truncated r3 alone.
 * Under --trace, also reports the kernel-style result (G3 bring-up). */
static void sys_apply_ret(ppc32_ctx_t *ctx, uint32_t nr, long ret)
{
    if (ctx->trace_syscalls) {
        fprintf(stderr, "  sc=%u -> %ld\n", nr, ret);
    }
    if (ret < 0L && ret >= -4095L) {
        ctx->gpr[3] = (uint32_t)(-ret);
        ctx->cr |= PPC32_CR0_SO;
    } else {
        ctx->gpr[3] = (uint32_t)ret;
        ctx->cr &= (uint32_t)~PPC32_CR0_SO;
    }
}

/* getpid(2) and kill(2) live in their owning layers (proc.c, signals.c):
 * the switch below calls ppc32_proc_getpid and ppc32_sig_kill. */

/* RC4 synchronous-clone reaping. Inline clone children (see the CLONE
 * case) exit before the clone sc returns and own no host process, so a
 * host wait4/waitpid would report ECHILD; consult this table first. The
 * stored status is the guest exit code; the reported word is status<<8
 * like a native wait4 status for _exit(status). WNOHANG with no exited
 * child reports 0 instead of hanging. */
#define SYNC_KID_MAX 32U

typedef struct {
    uint32_t tid;
    int status;
    bool used;
} sync_kid_t;

static sync_kid_t sync_kids[SYNC_KID_MAX];

static void sync_kid_record(uint32_t tid, int status)
{
    uint32_t i;

    for (i = 0U; i < SYNC_KID_MAX; i++) {
        if (!sync_kids[i].used) {
            sync_kids[i].tid = tid;
            sync_kids[i].status = status;
            sync_kids[i].used = true;
            return;
        }
    }
}

/* Returns 1 with *out_ret set when pid matched a reaped inline child
 * (E01 + advance still apply in the caller); 0 when pid is not ours. */
static int sync_kid_reap(ppc32_ctx_t *ctx, uint32_t pid_va,
    uint32_t status_va, uint32_t options, uint32_t rusage_va, long *out_ret)
{
    uint32_t i;
    uint32_t word;

    for (i = 0U; i < SYNC_KID_MAX; i++) {
        if (!sync_kids[i].used) {
            continue;
        }
        if (pid_va != 0xFFFFFFFFU && pid_va != sync_kids[i].tid) {
            continue;
        }
        if (status_va != 0U && !ppc32_range_ok(status_va, 4U)) {
            *out_ret = -EFAULT;
            return 1;
        }
        word = (sync_kids[i].status < 0) ?
            (uint32_t)(-sync_kids[i].status & 0x7F) :
            (((uint32_t)sync_kids[i].status & 0xFFU) << 8U);
        if (status_va != 0U) {
            ppc32_st32be(ctx, status_va, word);
        }
        if (rusage_va != 0U) {
            if (!ppc32_range_ok(rusage_va, 72U)) {
                *out_ret = -EFAULT;
                return 1;
            }
            memset(ppc32_guest_ptr(ctx, rusage_va), 0, 72U);
        }
        sync_kids[i].used = false;
        *out_ret = (long)(int32_t)sync_kids[i].tid;
        return 1;
    }
    if (pid_va == 0xFFFFFFFFU && (options & (uint32_t)WNOHANG) != 0U) {
        *out_ret = 0L;
        return 1;
    }
    return 0;
}

/* ioctl allowlist: only pure-status queries plus termios and winsize
 * cross the boundary; everything else takes -ENOSYS rather than leaking
 * host ioctls to the guest. The allowlisted request numbers are
 * asm-generic on Linux, so the guest values compare directly against
 * the host macros. */
static long sys_ioctl(ppc32_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg_va)
{
#ifdef __linux__
    switch (req) {
    case 0x5401U: /* TCGETS */
    {
        struct termios hs;

        if (ioctl((int)fd, TCGETS, &hs) != 0) {
            return -(long)errno;
        }
        return (long)ppc32_termios_to_guest(ctx, arg_va, &hs);
    }
    case 0x5402U: /* TCSETS */
    case 0x5403U: /* TCSETSW */
    case 0x5404U: /* TCSETSF */
    {
        struct termios hs;
        int kind = (req == 0x5402U) ? TCSANOW :
            (req == 0x5403U) ? TCSADRAIN : TCSAFLUSH;

        if (ppc32_termios_from_guest(ctx, arg_va, &hs) != 0) {
            return -EFAULT;
        }
        if (tcsetattr((int)fd, kind, &hs) != 0) {
            return -(long)errno;
        }
        return 0;
    }
    case 0x5413U: /* TIOCGWINSZ */
    {
        struct winsize hs;

        if (ioctl((int)fd, TIOCGWINSZ, &hs) != 0) {
            return -(long)errno;
        }
        return (long)ppc32_winsize_to_guest(ctx, arg_va, &hs);
    }
    case 0x5414U: /* TIOCSWINSZ */
    {
        struct winsize hs;

        if (ppc32_winsize_from_guest(ctx, arg_va, &hs) != 0) {
            return -EFAULT;
        }
        if (ioctl((int)fd, TIOCSWINSZ, &hs) != 0) {
            return -(long)errno;
        }
        return 0;
    }
    case 0x541BU: /* FIONREAD */
    {
        int n = 0;

        if (ioctl((int)fd, FIONREAD, &n) != 0) {
            return -(long)errno;
        }
        if (!ppc32_range_ok(arg_va, 4U)) {
            return -EFAULT;
        }
        ppc32_st32be(ctx, arg_va, (uint32_t)n);
        return 0;
    }
    default:
        break;
    }
    return -ENOSYS;
#else
    (void)ctx;
    (void)fd;
    (void)req;
    (void)arg_va;
    return -ENOSYS;
#endif
}

int ppc32_syscall_is_exit(uint32_t nr)
{
    return (nr == PPC32_NR_EXIT || nr == PPC32_NR_EXIT_GROUP) ? 1 : 0;
}

void ppc32_syscall(ppc32_ctx_t *ctx)
{
    uint32_t nr;
    uint32_t a0;
    uint32_t a1;
    uint32_t a2;
    uint32_t a3;
    uint32_t a4;
    uint32_t a5;
    long ret;

    if (ctx == NULL) {
        return;
    }
    nr = ctx->gpr[0];
    a0 = ctx->gpr[3];
    a1 = ctx->gpr[4];
    a2 = ctx->gpr[5];
    a3 = ctx->gpr[6];
    a4 = ctx->gpr[7];
    a5 = ctx->gpr[8];

    /* Reservations die at syscall entry (SPEC 2.2, lwarx/stwcx.). */
    ctx->res_valid = 0;
    ctx->reservation_epoch++;

    /* RC5 (G3): guest syscall trace for dynamic bring-up; prints the
     * number + raw args at entry. Quiet unless --trace is passed. */
    if (ctx->trace_syscalls) {
        fprintf(stderr, "ppc32rt: sc=%u(%u,%u,%u,%u,%u,%u)\n", nr, a0, a1,
            a2, a3, a4, a5);
    }

    /* Phase 4 signal syscalls (L4a): rt_sigaction/procmask/pending,
     * rt_sigreturn, sigaltstack. rt_sigreturn restores nip/r3/cr from
     * the frame, so neither the E01 convention nor the sc advance
     * applies to it (ppc32_sig_nr_no_advance). */
    {
        long hook = 0L;

        if (ppc32_sig_syscall(ctx, nr, a0, a1, a2, a3, &hook)) {
            if (!ppc32_sig_nr_no_advance(nr)) {
                sys_apply_ret(ctx, nr, hook);
                ctx->nip += 4U;
            }
            ctx->syscalls_executed++;
            return;
        }
    }
    /* Inline-clone children own no host process: reap them here before
     * the host wait4/waitpid path (which would report ECHILD). */
    if (nr == PPC32_NR_WAIT4 || nr == PPC32_NR_WAITPID) {
        long waited = 0L;

        if (sync_kid_reap(ctx, a0, a1, a2, a3, &waited)) {
            sys_apply_ret(ctx, nr, waited);
            ctx->nip += 4U;
            ctx->syscalls_executed++;
            return;
        }
    }
    /* Phase 4 process lifecycle (L4c): fork/execve/wait4/pipe/dup2.
     * Owned numbers apply E01 + nip internally (proc_dispatch owns the
     * tail, including the execve-success no-advance reparking). */
    if (ppc32_proc_dispatch(ctx, nr, a0, a1, a2, a3, a4, a5)) {
        return;
    }
    /* RC5 dynamic-loading layer (access/statx/getcwd/rlimit/dents64/
     * ids). Owned numbers take the common E01 + advance tail below. */
    {
        long dyn = 0L;

        if (ppc32_dyn_dispatch(ctx, nr, a0, a1, a2, a3, a4, a5, &dyn)) {
            sys_apply_ret(ctx, nr, dyn);
            ctx->nip += 4U;
            ctx->syscalls_executed++;
            return;
        }
    }

    switch (nr) {
    case PPC32_NR_EXIT:
        ctx->exit_arg = a0 & 0xFFU;
        ret = (long)(int32_t)ctx->exit_arg;
        break;
    case PPC32_NR_EXIT_GROUP:
        ctx->exit_arg = a0 & 0xFFU;
        ret = (long)(int32_t)ctx->exit_arg;
        break;
    case PPC32_NR_READ:
        ret = sys_read_at(ctx, a0, a1, a2, false, 0);
        break;
    case PPC32_NR_PREAD64:
        ret = sys_read_at(ctx, a0, a1, a2, true,
            ((int64_t)(int32_t)a3 << 32) | (int64_t)a4);
        break;
    case PPC32_NR_WRITE:
        ret = sys_write(ctx, a0, a1, a2);
        break;
    case PPC32_NR_READV:
        ret = sys_vec(ctx, a0, a1, a2, 0);
        break;
    case PPC32_NR_WRITEV:
        ret = sys_vec(ctx, a0, a1, a2, 1);
        break;
    case PPC32_NR_OPEN:
        ret = sys_openat(ctx, (uint32_t)(int32_t)-100, a0, a1, a2);
        break;
    case PPC32_NR_OPENAT:
        ret = sys_openat(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_CLOSE:
        ret = sys_close(a0);
        break;
    case PPC32_NR_READLINK:
        /* Phase 5 L5a: /proc/self/exe keeps symlink semantics; other
         * paths fall through to the host readlink inside procfs.c. */
        ret = ppc32_procfs_readlink(ctx, a0, a1, a2);
        break;
    case PPC32_NR_READLINKAT:
        /* RC5: readlinkat (BusyBox resolves /proc/self/exe through it);
         * dirfd-relative resolution matches openat semantics. */
        ret = ppc32_procfs_readlinkat(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_UNLINK:
        ret = sys_unlink(ctx, a0);
        break;
    case PPC32_NR_LSEEK:
        ret = sys_lseek(a0, a1, a2);
        break;
    case PPC32_NR_LLSEEK:
        ret = sys_llseek(ctx, a0, a1, a2, a3, a4);
        break;
    case PPC32_NR_BRK:
        ret = sys_brk(ctx, a0);
        break;
    case PPC32_NR_MMAP:
        ret = sys_mmap(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case PPC32_NR_MMAP2:
        ret = sys_mmap2(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case PPC32_NR_MUNMAP:
        ret = sys_munmap(ctx, a0, a1);
        break;
    case PPC32_NR_MPROTECT:
        ret = sys_mprotect(ctx, a0, a1, a2);
        break;
    case PPC32_NR_UNAME:
        ret = sys_uname(ctx, a0);
        break;
    case PPC32_NR_STAT:
        ret = sys_stat_path(ctx, a0, a1, 0U, 0);
        break;
    case PPC32_NR_LSTAT:
        ret = sys_stat_path(ctx, a0, a1, 0U, 1);
        break;
    case PPC32_NR_FSTAT:
        ret = sys_fstat(ctx, a0, a1, 0U);
        break;
    case PPC32_NR_STAT64:
        ret = sys_stat_path(ctx, a0, a1, 1U, 0);
        break;
    case PPC32_NR_LSTAT64:
        ret = sys_stat_path(ctx, a0, a1, 1U, 1);
        break;
    case PPC32_NR_FSTAT64:
        ret = sys_fstat(ctx, a0, a1, 1U);
        break;
    case PPC32_NR_GETTIMEOFDAY:
        ret = sys_gettimeofday(ctx, a0);
        break;
    case PPC32_NR_CLOCK_GETTIME:
        ret = sys_clock_gettime(ctx, a0, a1, 0);
        break;
    case PPC32_NR_CLOCK_GETTIME64:
        ret = sys_clock_gettime(ctx, a0, a1, 1);
        break;
    case PPC32_NR_GETRANDOM:
        ret = sys_getrandom(ctx, a0, a1, a2);
        break;
    case PPC32_NR_FUTEX:
        ret = ppc32_futex(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case PPC32_NR_FCNTL:
    case PPC32_NR_FCNTL64:
        ret = sys_fcntl(ctx, a0, a1, a2);
        break;
    case PPC32_NR_FTRUNCATE:
        ret = sys_ftruncate(a0, a1);
        break;
    case PPC32_NR_IOCTL:
        ret = sys_ioctl(ctx, a0, a1, a2);
        break;
    case PPC32_NR_GETPID:
        ret = ppc32_proc_getpid();
        break;
    case PPC32_NR_KILL:
    {
        long killed = 0L;

        if (ppc32_sig_kill(ctx, a0, a1, &killed)) {
            return;
        }
        ret = killed;
        break;
    }
    case PPC32_NR_CLONE:
    {
        /* PPC clone arg order (threads.h): flags, stack, parent_tid,
         * tls, child_tid in r3..r7. RC4 runs the child inline on the
         * calling host thread to guest exit: single-threaded, so the
         * fixture's lwarx/stwcx counter (1000 = parent 500 + child
         * 500) reproduces the oracle exactly under interp, dbt, and
         * difftest (whose snapshot refreshes after this dispatch). A
         * host-thread child would race the interpreter's non-atomic
         * reservation ops; true concurrency is a Phase 7 concern. */
        /* Fork-style clone (no CLONE_VM): process semantics, e.g. the
         * BusyBox posix_spawn idiom SIGCHLD|CHILD_CLEARTID|CHILD_SETTID.
         * A host fork copies mm/files/fs exactly like fork(2); thread
         * semantics w/o an address space stay -EINVAL (kernel parity).
         * SETTID stores honored; CLEARTID clearing is best-effort. */
        if ((a0 & PPC32_CLONE_VM) == 0U) {
            long pid;

            if ((a0 & (PPC32_CLONE_THREAD | PPC32_CLONE_SIGHAND)) != 0U) {
                ret = -EINVAL;
                break;
            }
            pid = ppc32_proc_fork(ctx);
            if (pid < 0L) {
                ret = pid;
                break;
            }
            if (pid == 0L) {
                if ((a0 & PPC32_CLONE_CHILD_SETTID) != 0U &&
                    a4 != 0U && ppc32_range_ok(a4, 4U)) {
                    ppc32_st32be(ctx, a4, ctx->guest_pid);
                }
                ret = 0L;
                break;
            }
            if ((a0 & PPC32_CLONE_PARENT_SETTID) != 0U &&
                a2 != 0U && ppc32_range_ok(a2, 4U)) {
                ppc32_st32be(ctx, a2, (uint32_t)pid);
            }
            ret = pid;
            break;
        }
        ppc32_ctx_t *child = NULL;
        long tid = ppc32_clone(ctx, a0, a1, a2, a3, a4, NULL, NULL,
            &child);

        if (tid < 0L) {
            ret = tid;
            break;
        }
        if (child == NULL) {
            ret = -EFAULT;
            break;
        }
        sync_kid_record((uint32_t)tid,
            (int)ppc32_run_guest_child(child));
        ppc32_thread_exit(child);
        ret = tid;
        break;
    }
    case PPC32_NR_SIGPROCMASK:
        /* Old-style mask stays -ENOSYS; the rt_* path above owns it. */
        ret = -ENOSYS;
        break;
    case PPC32_NR_SET_TID_ADDRESS:
        ret = ppc32_set_tid_address(ctx, a0);
        break;
    default:
        ret = -ENOSYS;
        break;
    }

    sys_apply_ret(ctx, nr, ret);
    ctx->syscalls_executed++;
    ctx->nip += 4U;
}
