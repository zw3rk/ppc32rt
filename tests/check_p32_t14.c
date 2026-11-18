/*
 * tests/check_p32_t14.c — Regression suite for lane ppc32rt-t14
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers the t14 work order: dup(41) single-argument semantics, the
 * CLONE_VM-without-VFORK pthread routing (p4_threads shape), the Darwin
 * errno translation table, fchmodat/faccessat flag hygiene,
 * AT_EMPTY_PATH fd-direct ops, utimensat_time64 tv_nsec handling, the
 * 32-bit utimensat sentinels, renameat2 Darwin ENOSYS, creating-open
 * vs mutation path symmetry, Darwin poll WRNORM/WRBAND mapping, and
 * the pselect6/ppoll saved-mask deferral.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dbt/cache_edge.h"
#include "dbt/dbt.h"
#include "os/convert.h"
#include "os/proc.h"
#include "os/signals.h"
#include "os/syscall_nr.h"
#include "os/syscalls.h"
#include "os/threads.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

static int g_fails = 0;

long ppc32_run_guest_child(ppc32_ctx_t *child)
{
    (void)child;
    return 0L;
}

#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__,     \
                (msg));                                                   \
            g_fails++;                                                    \
        }                                                                 \
    } while (0)

#define E2H(h, want) CHECK(ppc32_errno_map(h) == (want), "errno " #h)

/* dup(41) is a 1-argument call: garbage in r4 must not fail the dup. */
static void test_dup_single_arg(void)
{
    ppc32_ctx_t ctx;
    int nullfd;
    int owned;
    int newfd;

    nullfd = open("/dev/null", O_RDONLY);
    CHECK(nullfd >= 0, "dup open /dev/null");
    if (nullfd < 0) {
        return;
    }
    memset(&ctx, 0, sizeof(ctx));
    owned = ppc32_proc_dispatch(&ctx, PPC32_NR_DUP, (uint32_t)nullfd,
        0xDEADBEEFU, 0U, 0U, 0U, 0U);
    CHECK(owned == 1, "dup owned");
    CHECK((ctx.cr & PPC32_CR0_SO) == 0U, "dup garbage a1 ignored");
    newfd = (int)ctx.gpr[3];
    CHECK(newfd >= 0 && newfd != nullfd, "dup returned new fd");
    if (newfd >= 0) {
        CHECK(fcntl(newfd, F_GETFD) >= 0, "dup fd usable");
        (void)close(newfd);
    }
    (void)close(nullfd);

    /* Errors still map (EBADF is 9 on both hosts). */
    memset(&ctx, 0, sizeof(ctx));
    owned = ppc32_proc_dispatch(&ctx, PPC32_NR_DUP, 0xFFFFFFFEU, 0U, 0U, 0U,
        0U, 0U);
    CHECK(owned == 1, "dup badfd owned");
    CHECK((ctx.cr & PPC32_CR0_SO) != 0U && ctx.gpr[3] == 9U,
        "dup badfd EBADF");
}

/* CLONE_VM|FS|FILES|SIGHAND|SIGCHLD without THREAD or VFORK shares
 * memory: it must take the pthread path, never fork. */
static void test_clone_vm_no_thread(void)
{
    ppc32_ctx_t ctx;
    uint32_t tid;

    memset(&ctx, 0, sizeof(ctx));
    CHECK(ppc32_thread_init_main(&ctx) == 0, "clone init main");
    ctx.gpr[0] = PPC32_NR_CLONE;
    ctx.gpr[3] = 0xF11U;
    ctx.gpr[4] = 0U;
    ctx.gpr[5] = 0U;
    ctx.gpr[6] = 0U;
    ctx.gpr[7] = 0U;
    ctx.nip = 0x00100000U;
    ppc32_syscall(&ctx);
    CHECK((ctx.cr & PPC32_CR0_SO) == 0U, "clone-vm pthread path");
    CHECK(ctx.nip == 0x00100004U, "clone advanced");
    tid = ctx.gpr[3];
    CHECK(tid != 0U, "clone returns child tid");
    if (tid != 0U) {
        CHECK(ppc32_thread_signal(tid, 0U, 0) == 0,
            "clone child owns a thread slot");
        (void)ppc32_thread_join(tid);
    }
}

/* Darwin errno values above 34 diverge from Linux: spot-check the table
 * (ETIMEDOUT 60->110, ENOLCK 77->37, ENOSYS 78->38); unknown codes
 * degrade to EIO so raw Darwin codes never leak. */
static void test_errno_map(void)
{
    E2H(2, 2);
#ifdef __APPLE__
    E2H(EAGAIN, 11);
    E2H(EDEADLK, 58);
    E2H(ENAMETOOLONG, 36);
    E2H(ENOLCK, 37);
    E2H(ENOSYS, 38);
    E2H(ENOTEMPTY, 39);
    E2H(ELOOP, 40);
    E2H(ENOMSG, 42);
    E2H(EIDRM, 43);
    E2H(ENOSTR, 60);
    E2H(ENODATA, 61);
    E2H(ETIME, 62);
    E2H(ENOSR, 63);
    E2H(EREMOTE, 66);
    E2H(ENOLINK, 67);
    E2H(EPROTO, 71);
    E2H(EMULTIHOP, 72);
    E2H(EBADMSG, 74);
    E2H(EOVERFLOW, 75);
    E2H(EILSEQ, 84);
    E2H(EUSERS, 87);
    E2H(ENOTSOCK, 88);
    E2H(EDESTADDRREQ, 89);
    E2H(EMSGSIZE, 90);
    E2H(EPROTOTYPE, 91);
    E2H(ENOPROTOOPT, 92);
    E2H(EPROTONOSUPPORT, 93);
    E2H(ESOCKTNOSUPPORT, 94);
    E2H(EOPNOTSUPP, 95);
    E2H(ENOTSUP, 95);
    E2H(EPFNOSUPPORT, 96);
    E2H(EAFNOSUPPORT, 97);
    E2H(EADDRINUSE, 98);
    E2H(EADDRNOTAVAIL, 99);
    E2H(ENETDOWN, 100);
    E2H(ENETUNREACH, 101);
    E2H(ENETRESET, 102);
    E2H(ECONNABORTED, 103);
    E2H(ECONNRESET, 104);
    E2H(ENOBUFS, 105);
    E2H(EISCONN, 106);
    E2H(ENOTCONN, 107);
    E2H(ESHUTDOWN, 108);
    E2H(ETOOMANYREFS, 109);
    E2H(ETIMEDOUT, 110);
    E2H(ECONNREFUSED, 111);
    E2H(EHOSTDOWN, 112);
    E2H(EHOSTUNREACH, 113);
    E2H(EALREADY, 114);
    E2H(EINPROGRESS, 115);
    E2H(ESTALE, 116);
    E2H(EDQUOT, 122);
    E2H(ECANCELED, 125);
    E2H(EOWNERDEAD, 130);
    E2H(ENOTRECOVERABLE, 131);
#ifdef ENOATTR
    E2H(ENOATTR, 61);
#endif
    E2H(999, 5);
#else
    E2H(999, 999);
#endif
}

static void guest_put8(ppc32_ctx_t *ctx, uint32_t va, const void *src,
    size_t len)
{
    CHECK(ppc32_vm_copyout_safe(ctx, va, src, len) == 0, "guest write");
}

static void guest_put32be(ppc32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t b[4];

    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
    guest_put8(ctx, va, b, sizeof b);
}

/* One shared guest window for every VM test in this process. Regions
 * and the mmap cursor live in globals (each mmap still takes fresh
 * VAs), so later tests reuse the first test's base instead of
 * reserving a new 4 GiB window each. Returns 0 with ctx ready. */
static bool g_t14_vm_live = false;
static uint64_t g_t14_vm_base = 0ULL;

static int t14_vm_ctx(ppc32_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    if (!g_t14_vm_live) {
        if (ppc32_vm_init(ctx, UINT64_MAX) != 0) {
            return -1;
        }
        g_t14_vm_base = ctx->guest_base;
        g_t14_vm_live = true;
        return 0;
    }
    ctx->guest_base = g_t14_vm_base;
    ctx->vm_ready = true;
    return 0;
}

/* fchmodat(297)/faccessat(298) are 3-argument calls (garbage 4th register
 * is flags-free); AT_EMPTY_PATH with "" stats/chowns/utimens the fd. */
static void test_fs_at_flags(void)
{
    ppc32_ctx_t ctx;
    char path[] = "/tmp/ppc32rt-t14-test.XXXXXX";
    uint8_t *win;
    uint32_t page;
    uint32_t path_va;
    uint32_t empty_va;
    uint32_t buf_va;
    int fd;
    struct stat st;
    long out = -1L;
    int owned;

    memset(&ctx, 0, sizeof(ctx));
    CHECK(t14_vm_ctx(&ctx) == 0, "fs vm init");
    page = ppc32_vm_mmap2(&ctx, 0U, 0x4000U, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | 0x20U, -1, 0U);
    CHECK(page < 0xfffff000U, "fs mmap page");
    if (page >= 0xfffff000U) {
        return;
    }
    win = (uint8_t *)(uintptr_t)ctx.guest_base;
    (void)win;
    path_va = page + 0x100U;
    empty_va = page + 0x200U;
    buf_va = page + 0x1000U;

    fd = mkstemp(path);
    CHECK(fd >= 0, "fs mkstemp");
    if (fd < 0) {
        return;
    }
    CHECK(fstat(fd, &st) == 0, "fs fstat");
    guest_put8(&ctx, path_va, path, strlen(path) + 1U);
    guest_put8(&ctx, empty_va, "", 1U);

    /* Garbage 4th register must not become flags (stray AT_EACCESS used
     * to force musl's fork-based emulation / EINVAL). */
    owned = ppc32_fs_dispatch(&ctx, 297U, (uint32_t)(int32_t)-100, path_va,
        (uint32_t)(st.st_mode & 07777U), 0xDEADBEEFU, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "fchmodat ignores a3");
    owned = ppc32_fs_dispatch(&ctx, 298U, (uint32_t)(int32_t)-100, path_va,
        4U, 0xDEADBEEFU, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "faccessat ignores a3");
    owned = ppc32_fs_dispatch(&ctx, 439U, (uint32_t)(int32_t)-100, path_va,
        4U, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "faccessat2 flags 0");

    /* AT_EMPTY_PATH with "": fstat the fd itself, no resolution. The
     * flags-free control proves the bypass is what makes it work. */
    owned = ppc32_fs_dispatch(&ctx, 291U, (uint32_t)fd, empty_va, buf_va,
        0x1000U, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "fstatat64 EMPTY_PATH on fd");
    owned = ppc32_fs_dispatch(&ctx, 291U, (uint32_t)fd, empty_va, buf_va,
        0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == -ENOENT, "fstatat64 empty needs flag");

    /* utimensat_time64: BE tv_nsec is 32-bit at +12; 2e9 is EINVAL. */
    guest_put32be(&ctx, buf_va, 0U);
    guest_put32be(&ctx, buf_va + 4U, 0U);
    guest_put32be(&ctx, buf_va + 8U, 0U);
    guest_put32be(&ctx, buf_va + 12U, 500000000U);
    guest_put32be(&ctx, buf_va + 16U, 0U);
    guest_put32be(&ctx, buf_va + 20U, 0U);
    guest_put32be(&ctx, buf_va + 24U, 0U);
    guest_put32be(&ctx, buf_va + 28U, 500000000U);
    owned = ppc32_fs_dispatch(&ctx, 412U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "utimensat64 wide nsec ok");
    guest_put32be(&ctx, buf_va + 12U, 2000000000U);
    owned = ppc32_fs_dispatch(&ctx, 412U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == -EINVAL, "utimensat64 wide nsec EINVAL");

    (void)close(fd);
    (void)unlink(path);
}

/* pselect6/ppoll saved-mask deferral: the tail pump delivers under the
 * tmp mask with the pre-wait mask in the frame, and restores the
 * pre-wait mask when no handler runs. */
static void test_saved_sigmask(void)
{
    ppc32_ctx_t ctx;
    ppc32_sigact_t ign;
    ppc32_sigact_t act;
    uint64_t usr1 = 1ULL << (uint64_t)(PPC32_SIGUSR1 - 1U);
    uint64_t tmp = 0x00FF00FF00000000ULL;
    uint64_t saved = 0x0F0F0F0F0F0F0F0FULL;
    uint32_t frame = 0U;

    ppc32_sig_reset();

    /* Pump with nothing to deliver restores the pre-wait mask. */
    memset(&ctx, 0, sizeof(ctx));
    memset(&ign, 0, sizeof(ign));
    ign.handler = PPC32_SIG_IGN;
    CHECK(ppc32_sigaction_set_raw((int)PPC32_SIGUSR1, &ign) == 0,
        "saved ignore usr1");
    __atomic_fetch_or(&ctx.pending_signals, usr1, __ATOMIC_ACQ_REL);
    ctx.sig_mask = tmp;
    ctx.saved_sigmask = saved;
    ctx.has_saved_sigmask = true;
    ppc32_sig_pump_pending(&ctx);
    CHECK((__atomic_load_n(&ctx.pending_signals, __ATOMIC_ACQUIRE) &
        usr1) == 0ULL, "saved ign clears");
    CHECK(!ctx.has_saved_sigmask && ctx.sig_mask == saved,
        "saved restored by pump");

    /* A pushed frame reports the pre-wait mask and consumes the flag;
     * the handler itself runs under tmp | act | sig. */
    memset(&ctx, 0, sizeof(ctx));
    CHECK(t14_vm_ctx(&ctx) == 0, "saved vm init");
    {
        uint32_t stack = ppc32_vm_mmap2(&ctx, 0U, 0x4000U,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20U, -1, 0U);

        CHECK(stack < 0xfffff000U, "saved mmap stack");
        if (stack >= 0xfffff000U) {
            return;
        }
        ctx.gpr[PPC32_REG_SP] = stack + 0x4000U;
    }
    memset(&act, 0, sizeof(act));
    act.handler = 0x100100U;
    act.flags = PPC32_SA_RESTORER;
    act.restorer = 0x100200U;
    ctx.sig_mask = tmp;
    ctx.saved_sigmask = saved;
    ctx.has_saved_sigmask = true;
    CHECK(ppc32_sig_build_frame(&ctx, (int)PPC32_SIGUSR1, &act, 0, 0U, 0U,
        0U, &frame) == 0, "saved frame builds");
    if (frame != 0U) {
        uint8_t *win = (uint8_t *)(uintptr_t)ctx.guest_base;
        uint32_t lo = ((uint32_t)win[frame + 0xB4U] << 24) |
            ((uint32_t)win[frame + 0xB5U] << 16) |
            ((uint32_t)win[frame + 0xB6U] << 8) |
            (uint32_t)win[frame + 0xB7U];
        uint32_t hi = ((uint32_t)win[frame + 0xB8U] << 24) |
            ((uint32_t)win[frame + 0xB9U] << 16) |
            ((uint32_t)win[frame + 0xBAU] << 8) |
            (uint32_t)win[frame + 0xBBU];

        CHECK((((uint64_t)hi << 32) | (uint64_t)lo) == saved,
            "saved frame uc_sigmask");
    }
    CHECK(!ctx.has_saved_sigmask, "saved consumed by frame");
    CHECK(ctx.sig_mask == (tmp | usr1), "saved handler mask tmp|sig");
    ppc32_sig_reset();
}

/* utimensat(304) 32-bit branch: UTIME_NOW/UTIME_OMIT sentinels pass,
 * any other tv_nsec outside [0, 999999999] is -EINVAL. */
static void test_fs_utimens32(void)
{
    ppc32_ctx_t ctx;
    char path[] = "/tmp/ppc32rt-t14-utime.XXXXXX";
    uint32_t page;
    uint32_t path_va;
    uint32_t buf_va;
    int fd;
    long out = -1L;
    int owned;

    memset(&ctx, 0, sizeof(ctx));
    CHECK(t14_vm_ctx(&ctx) == 0, "utime vm init");
    page = ppc32_vm_mmap2(&ctx, 0U, 0x4000U,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20U, -1, 0U);
    CHECK(page < 0xfffff000U, "utime mmap page");
    if (page >= 0xfffff000U) {
        return;
    }
    path_va = page + 0x100U;
    buf_va = page + 0x1000U;

    fd = mkstemp(path);
    CHECK(fd >= 0, "utime mkstemp");
    if (fd < 0) {
        return;
    }
    (void)close(fd);
    guest_put8(&ctx, path_va, path, strlen(path) + 1U);

    /* UTIME_NOW on both stamps: must succeed. */
    guest_put32be(&ctx, buf_va, 0U);
    guest_put32be(&ctx, buf_va + 4U, 0x3fffffffU);
    guest_put32be(&ctx, buf_va + 8U, 0U);
    guest_put32be(&ctx, buf_va + 12U, 0x3fffffffU);
    owned = ppc32_fs_dispatch(&ctx, 304U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "utimens32 UTIME_NOW ok");

    /* UTIME_OMIT on both stamps: must succeed. */
    guest_put32be(&ctx, buf_va + 4U, 0x3ffffffeU);
    guest_put32be(&ctx, buf_va + 12U, 0x3ffffffeU);
    owned = ppc32_fs_dispatch(&ctx, 304U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "utimens32 UTIME_OMIT ok");

    /* 2e9 and exactly 1e9 are invalid; 999999999 is the last valid. */
    guest_put32be(&ctx, buf_va + 4U, 2000000000U);
    owned = ppc32_fs_dispatch(&ctx, 304U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == -EINVAL, "utimens32 nsec 2e9 EINVAL");
    guest_put32be(&ctx, buf_va + 4U, 1000000000U);
    owned = ppc32_fs_dispatch(&ctx, 304U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == -EINVAL, "utimens32 nsec 1e9 EINVAL");
    guest_put32be(&ctx, buf_va + 4U, 999999999U);
    owned = ppc32_fs_dispatch(&ctx, 304U, (uint32_t)(int32_t)-100, path_va,
        buf_va, 0U, 0U, 0U, &out);
    CHECK(owned == 1 && out == 0L, "utimens32 nsec max ok");

    (void)unlink(path);
}

/* renameat2(357) with nonzero flags on Darwin is Linux -ENOSYS (-38),
 * never the raw Darwin code (which the guest decodes as EREMCHG). */
static void test_fs_renameat2_flags(void)
{
    ppc32_ctx_t ctx;
    uint32_t page;
    uint32_t a_va;
    uint32_t b_va;
    long out = 0L;
    int owned;

    memset(&ctx, 0, sizeof(ctx));
    CHECK(t14_vm_ctx(&ctx) == 0, "rn2 vm init");
    page = ppc32_vm_mmap2(&ctx, 0U, 0x4000U,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20U, -1, 0U);
    CHECK(page < 0xfffff000U, "rn2 mmap page");
    if (page >= 0xfffff000U) {
        return;
    }
    a_va = page + 0x100U;
    b_va = page + 0x200U;
    guest_put8(&ctx, a_va, "/no/such/src-t14", 16U);
    guest_put8(&ctx, b_va, "/no/such/dst-t14", 16U);
    owned = ppc32_fs_dispatch(&ctx, 357U, (uint32_t)(int32_t)-100, a_va,
        (uint32_t)(int32_t)-100, b_va, 0xFFFFU, 0U, &out);
    CHECK(owned == 1 && out < 0L, "renameat2 flags owned+error");
#ifdef __APPLE__
    CHECK(out == -38L, "renameat2 flags is -ENOSYS, not EREMCHG");
#endif
}

/* Creating opens and mutations share one rule: a file created under the
 * sysroot unlinks at the exact same host path. */
static void test_path_mut_symmetry(void)
{
    ppc32_ctx_t ctx;
    char sysroot[] = "/tmp/ppc32rt-t14-sym.XXXXXX";
    char sub[256];
    char expect[256];
    uint32_t page;
    uint32_t path_va;
    long fd = -1L;
    int pre;

    CHECK(mkdtemp(sysroot) != NULL, "sym mkdtemp");
    if (sysroot[0] == '\0') {
        return;
    }
    snprintf(sub, sizeof sub, "%s/t14sym", sysroot);
    CHECK(mkdir(sub, 0700) == 0, "sym mkdir sub");
    snprintf(expect, sizeof expect, "%s/t14sym/f", sysroot);
    /* Seed the file with a host create (Darwin host O_CREAT differs
     * from the guest spelling; the translator paths under test are
     * resolution, not host flag spelling). */
    pre = open(expect, O_CREAT | O_WRONLY, 0644);
    CHECK(pre >= 0, "sym seed file");
    if (pre >= 0) {
        (void)close(pre);
    }

    CHECK(t14_vm_ctx(&ctx) == 0, "sym vm init");
    ctx.sysroot = sysroot;
    page = ppc32_vm_mmap2(&ctx, 0U, 0x4000U,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20U, -1, 0U);
    CHECK(page < 0xfffff000U, "sym mmap page");
    if (page >= 0xfffff000U) {
        goto out;
    }
    path_va = page + 0x100U;
    guest_put8(&ctx, path_va, "/t14sym/f", 9U);

    /* O_CREAT|O_WRONLY must resolve under the sysroot (parent exists). */
    fd = sys_openat(&ctx, (uint32_t)(int32_t)-100, path_va, 0x41U, 0644U);
    CHECK(fd >= 0L, "sym creating open under sysroot");
    if (fd >= 0L) {
        (void)close((int)fd);
    }
    CHECK(access(expect, F_OK) == 0, "sym file at sysroot path");

    /* A non-creating reopen finds the same file (exists-or-raw). */
    fd = sys_openat(&ctx, (uint32_t)(int32_t)-100, path_va, 0U, 0U);
    CHECK(fd >= 0L, "sym reopen finds sysroot file");
    if (fd >= 0L) {
        (void)close((int)fd);
    }

    /* Unlink resolves identically: the sysroot file is gone. */
    CHECK(sys_unlink(&ctx, path_va) == 0L, "sym unlink ok");
    CHECK(access(expect, F_OK) != 0, "sym file removed from sysroot");

out:
    (void)unlink(expect);
    (void)rmdir(sub);
    (void)rmdir(sysroot);
}

/* poll(167): WRNORM asked as 0x0100 reports back when writable, RDHUP
 * (0x2000) never leaks through on Darwin. */
static void test_poll_bits(void)
{
    ppc32_ctx_t ctx;
    uint32_t page;
    uint32_t fds_va;
    uint8_t req[8];
    uint8_t got[8];
    long out = -1L;
    int owned;
    int pf[2] = { -1, -1 };

    CHECK(pipe(pf) == 0, "poll pipe");
    memset(&ctx, 0, sizeof(ctx));
    CHECK(t14_vm_ctx(&ctx) == 0, "poll vm init");
    page = ppc32_vm_mmap2(&ctx, 0U, 0x4000U,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20U, -1, 0U);
    CHECK(page < 0xfffff000U, "poll mmap page");
    if (page >= 0xfffff000U || pf[0] < 0) {
        if (pf[0] >= 0) {
            (void)close(pf[0]);
            (void)close(pf[1]);
        }
        return;
    }
    fds_va = page + 0x100U;
    req[0] = (uint8_t)((uint32_t)pf[1] >> 24);
    req[1] = (uint8_t)((uint32_t)pf[1] >> 16);
    req[2] = (uint8_t)((uint32_t)pf[1] >> 8);
    req[3] = (uint8_t)(uint32_t)pf[1];
    req[4] = 0x21U;
    req[5] = 0x04U;
    req[6] = 0U;
    req[7] = 0U;
    CHECK(ppc32_vm_copyout_safe(&ctx, fds_va, req, sizeof req) == 0,
        "poll write req");
    owned = ppc32_poll_dispatch(&ctx, 167U, fds_va, 1U, 0U, 0U, 0U, 0U,
        &out);
    CHECK(owned == 1 && out > 0L, "poll writable hit");
    CHECK(ppc32_vm_copyin_safe(&ctx, fds_va, got, sizeof got) == 0,
        "poll read back");
    CHECK((((uint16_t)got[6] << 8) | (uint16_t)got[7]) == 0x0104U,
        "poll WRNORM reports, RDHUP dropped");
    (void)close(pf[0]);
    (void)close(pf[1]);
}

/* pselect6 with a NULL sigmask ignores a bogus size (Linux
 * set_user_sigmask semantics, matching pl_ppoll_mask). */
static void test_pselect_nullmask_size(void)
{
    ppc32_ctx_t ctx;
    uint32_t page;
    uint32_t ap_va;
    long out = -1L;
    int owned;

    memset(&ctx, 0, sizeof(ctx));
    CHECK(t14_vm_ctx(&ctx) == 0, "pselect-null vm init");
    page = ppc32_vm_mmap2(&ctx, 0U, 0x4000U, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | 0x20U, -1, 0U);
    CHECK(page < 0xfffff000U, "pselect-null mmap page");
    if (page >= 0xfffff000U) {
        return;
    }
    ap_va = page + 0x100U;
    guest_put32be(&ctx, ap_va, 0U);
    guest_put32be(&ctx, ap_va + 4U, 0xDEADBEEFU);
    owned = ppc32_poll_dispatch(&ctx, 280U, 0U, 0U, 0U, 0U, 0U, ap_va,
        &out);
    CHECK(owned == 1 && out == 0L, "pselect6 NULL mask ignores size");
}

/* A reclaim sync records the reclamation generation without touching
 * the semantic cache epoch (s1: reclaim pressure never invalidates). */
static void test_reclaim_sync_epoch_stable(void)
{
    ppc32_ctx_t ctx;
    uint32_t before;

    memset(&ctx, 0, sizeof(ctx));
    before = *ppc32_cache_epoch_ptr();
    ppc32_cache_sync_ctx(&ctx);
    CHECK(*ppc32_cache_epoch_ptr() == before, "sync never bumps epoch");
    CHECK(ctx.reclaim_synced_gen != 0U, "sync records reclaim gen");
    CHECK(ctx.ibtc_synced_epoch == before, "sync records cache epoch");
}

/* v8 SMC sweep regression (p3_torture --dbt stall): an 8-byte signal
 * trampoline and FPR spill stores share one 4 KiB stack page on
 * different 64-byte lines. The precheck must report no overlap for the
 * spill range (previously every stfd swept 2 * 262144 slots), while a
 * store landing mid-block must still report overlap. */
static ppc32_block_t *t14_smc_table[PPC32_DBT_HT_SIZE];

static uint32_t t14_cache_idx(uint32_t pc)
{
    return (pc >> 2U) & (PPC32_DBT_HT_SIZE - 1U);
}

static void test_smc_overlap_precheck(void)
{
    ppc32_block_t blk;
    uint32_t cur;
    uint32_t tramp = 0x1FF00000U;
    uint32_t spill = 0x1FF00100U;
    uint32_t bstart = 0x00200000U;

    memset(t14_smc_table, 0, sizeof t14_smc_table);
    ppc32_edge_code_clear_all();
    cur = *ppc32_cache_epoch_ptr();

    /* Trampoline block occupies line 0 of the stack page. */
    ppc32_edge_code_mark(tramp, tramp + 8U);
    CHECK(ppc32_edge_code_any(tramp, tramp + 8U), "smc page marked");
    CHECK(ppc32_edge_code_any(spill, spill + 8U), "smc same page hit");
    CHECK(!ppc32_edge_lines_any(spill, spill + 8U),
        "smc spill line unmarked");
    /* Same page, disjoint line: no sweep. */
    CHECK(!ppc32_edge_has_overlap_locked(t14_smc_table, spill,
        spill + 8U, NULL, cur), "smc spill skips sweep");

    /* Four-instruction block: a store into instruction 2 overlaps. */
    memset(&blk, 0, sizeof(blk));
    blk.occupied = true;
    blk.guest_pc = bstart;
    blk.pad0[1] = (uint64_t)bstart;
    blk.pad0[2] = (uint64_t)(bstart + 16U);
    t14_smc_table[t14_cache_idx(bstart)] = &blk;
    ppc32_edge_code_mark(bstart, bstart + 16U);
    CHECK(ppc32_edge_has_overlap_locked(t14_smc_table, bstart + 8U,
        bstart + 12U, NULL, cur), "smc mid-block hit");
    CHECK(ppc32_edge_has_overlap_locked(t14_smc_table, bstart,
        bstart + 4U, NULL, cur), "smc block-start hit");
    CHECK(!ppc32_edge_has_overlap_locked(t14_smc_table, bstart + 64U,
        bstart + 72U, NULL, cur), "smc past-block miss");

    /* Executing entry counted via skip even when not installed. */
    t14_smc_table[t14_cache_idx(bstart)] = NULL;
    CHECK(ppc32_edge_has_overlap_locked(t14_smc_table, bstart + 8U,
        bstart + 12U, &blk, cur), "smc skip hit");

    /* Conservative fallbacks: huge span and same-epoch eviction. */
    CHECK(ppc32_edge_has_overlap_locked(t14_smc_table, bstart,
        bstart + 65537U, NULL, cur), "smc huge span sweeps");
    ppc32_edge_note_evict(cur);
    CHECK(ppc32_edge_has_overlap_locked(t14_smc_table, tramp,
        tramp + 8U, NULL, cur), "smc evicted epoch sweeps");
    CHECK(!ppc32_edge_has_overlap_locked(t14_smc_table, spill,
        spill + 8U, NULL, cur), "smc unmarked line still skips");

    ppc32_edge_code_clear_all();
}

int main(void)
{
    test_dup_single_arg();
    test_clone_vm_no_thread();
    test_errno_map();
    test_fs_at_flags();
    test_fs_utimens32();
    test_fs_renameat2_flags();
    test_path_mut_symmetry();
    test_poll_bits();
    test_saved_sigmask();
    test_pselect_nullmask_size();
    test_reclaim_sync_epoch_stable();
    test_smc_overlap_precheck();

    if (g_fails != 0) {
        fprintf(stderr, "check_p32_t14: %d FAILURES\n", g_fails);
        return 1;
    }
    printf("check_p32_t14: ALL OK\n");
    return 0;
}
