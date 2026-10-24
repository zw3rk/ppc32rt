/*
 * src/os/proc.c — Process-lifecycle syscall layer for ppc32rt (Phase 4, L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements fork(2), vfork(190), execve(11), wait4(114)/waitpid(7),
 * waitid, pipe2/pipe(42), dup2(63) per SPEC sections 1.1 and 2.3.
 * Return convention is kernel-style (negative errno or value); the
 * caller applies the E01 CR0.SO/r3 rule via ppc32_proc_return. The
 * lwarx/stwcx. reservation dies at every entry (SPEC 2.2), matching
 * the syscall layer. Guest O_CLOEXEC (02000000) matches the host
 * asm-generic bit, so pipe2 flags pass through on Linux.
 */

/* Feature-test macros: strict POSIX on Linux (plus GNU for pipe2 and
 * waitid); on Apple the POSIX macro would hide the BSD wait4, so the
 * Darwin full level is used instead (wait4/pipe/dup2/fork stay
 * declared under strict -std=c11). */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#if !defined(__APPLE__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "os/proc.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "os/convert.h"
#include "os/syscall_nr.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"

/* execve vector bounds: Linux caps MAX_ARG_STRINGS at 2^31 pages, but a
 * translator-side copy keeps a small fixed table (no VLA); beyond it
 * the call fails with -E2BIG, as on an overlong kernel command line. */
#define PROC_MAX_VEC 256U
#define PROC_ARG_MAX 4096U

/* waitid idtype_t values (Linux-generic, match the guest). */
#define PROC_P_ALL 0U
#define PROC_P_PID 1U
#define PROC_P_PGID 2U

/* waitid options that cross the boundary; WNOWAIT is rejected (no
 * siginfo queue is kept, so the zombie must stay queued). */
#define PROC_WID_OK_MASK 0x0100000FU

/* Guest struct rusage: two 8 B timevals + fourteen 4 B longs = 72 B. */
#define PROC_RUSAGE_SIZE 72U
#define PROC_RUSAGE_LONGS 14U

/* Guest siginfo is SI_MAX_SIZE 128 B (sigframe_ppc32.h). */
#define PROC_SIGINFO_SIZE 128U

static void proc_invalidate_reservation(ppc32_ctx_t *ctx)
{
    ctx->res_valid = 0;
    ctx->reservation_epoch++;
}

/* fork/vfork child refresh: per-process identity follows the host pid;
 * the LL/SC reservation, robust list, and tid address are per-process
 * kernel state, so they reset. Signal mask/altstack are inherited. */
static void proc_child_refresh(ppc32_ctx_t *ctx)
{
    long pid = (long)getpid();

    ctx->host_tid = (int)pid;
    ctx->guest_pid = (uint32_t)pid;
    ctx->guest_tid = (uint32_t)pid;
    ctx->clear_child_tid = 0U;
    ctx->robust_list_head = 0U;
    ctx->robust_list_len = 0U;
    ctx->pending_signals = 0U;
    ctx->sig_last_frame_va = 0U;
    ctx->sig_last_frame_rt = 0U;
    proc_invalidate_reservation(ctx);
}

long ppc32_proc_fork(ppc32_ctx_t *ctx)
{
    pid_t pid;

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    pid = fork();
    if (pid < 0) {
        return -(long)errno;
    }
    if (pid == 0) {
        proc_child_refresh(ctx);
        return 0;
    }
    return (long)pid;
}

long ppc32_proc_vfork(ppc32_ctx_t *ctx)
{
    /* No address-space sharing fast path: plain fork preserves the
     * observable result (0 in the child, the child pid in the parent)
     * and is safe when the child promptly execves or exits. */
    return ppc32_proc_fork(ctx);
}

/* Scan guest text for a major-opcode-4 word (SPE APU, SPEC 2.2). Only
 * the first 65536 instructions are probed to stay bounded; SPE binaries
 * execute vector code from entry, so presence shows early. */
void ppc32_proc_redetect_profile(ppc32_ctx_t *ctx, uint32_t text_start,
    uint32_t text_end)
{
    uint64_t len;
    uint64_t n;
    uint64_t i;

    if (ctx == NULL) {
        return;
    }
    if (ctx->profile == PPC32_PROFILE_CLASSIC ||
        ctx->profile == PPC32_PROFILE_SPE) {
        ctx->is_spe = (ctx->profile == PPC32_PROFILE_SPE) ? 1U : 0U;
        return;
    }
    if (text_end <= text_start ||
        !ppc32_range_ok(text_start, (size_t)(text_end - text_start))) {
        ctx->profile = PPC32_PROFILE_CLASSIC;
        ctx->is_spe = 0U;
        return;
    }
    len = (uint64_t)text_end - (uint64_t)text_start;
    n = len / 4ULL;
    if (n > 65536ULL) {
        n = 65536ULL;
    }
    for (i = 0ULL; i < n; i++) {
        uint32_t w = ppc32_ld32be(ctx,
            (uint32_t)(text_start + (uint32_t)(i * 4ULL)));

        if ((w >> 26U) == 4U) {
            ctx->profile = PPC32_PROFILE_SPE;
            ctx->is_spe = 1U;
            return;
        }
    }
    ctx->profile = PPC32_PROFILE_CLASSIC;
    ctx->is_spe = 0U;
}

/* Free a partially built exec vector (count entries valid). */
static void proc_free_vec(char **vec, uint32_t count)
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

/* Copy a guest argv/envp vector (BE words, NUL-terminated) into a
 * host-side NULL-terminated array. envp_va == 0 yields an empty
 * environment (Linux execve semantics), never the host one. */
static long proc_copy_vec(ppc32_ctx_t *ctx, uint32_t vec_va, char ***out,
    uint32_t *out_count)
{
    char **vec;
    uint32_t n = 0U;

    vec = (char **)calloc((size_t)PROC_MAX_VEC + 1U, sizeof(char *));
    if (vec == NULL) {
        return -ENOMEM;
    }
    if (vec_va == 0U) {
        *out = vec;
        *out_count = 0U;
        return 0;
    }
    for (;;) {
        uint32_t str_va;
        char *buf;

        if (n >= PROC_MAX_VEC) {
            proc_free_vec(vec, n);
            return -E2BIG;
        }
        if (!ppc32_range_ok(vec_va + n * 4U, 4U)) {
            proc_free_vec(vec, n);
            return -EFAULT;
        }
        str_va = ppc32_ld32be(ctx, vec_va + n * 4U);
        if (str_va == 0U) {
            break;
        }
        buf = (char *)malloc(PROC_ARG_MAX);
        if (buf == NULL) {
            proc_free_vec(vec, n);
            return -ENOMEM;
        }
        if (ppc32_copyin_str(ctx, str_va, buf, PROC_ARG_MAX) != 0) {
            free(buf);
            proc_free_vec(vec, n);
            return -EFAULT;
        }
        vec[n] = buf;
        n++;
    }
    vec[n] = NULL;
    *out = vec;
    *out_count = n;
    return 0;
}

long ppc32_proc_execve(ppc32_ctx_t *ctx, uint32_t path_va, uint32_t argv_va,
    uint32_t envp_va)
{
    char path[PROC_ARG_MAX];
    char **args = NULL;
    char **env = NULL;
    uint32_t argc = 0U;
    uint32_t envc = 0U;
    long rc;
    int fd;
    ppc32_elf_info_t info;
    uint32_t sp = 0U;
    char **use_env;

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    if (ppc32_copyin_str(ctx, path_va, path, sizeof path) != 0) {
        return -EFAULT;
    }
    rc = proc_copy_vec(ctx, argv_va, &args, &argc);
    if (rc != 0) {
        return rc;
    }
    rc = proc_copy_vec(ctx, envp_va, &env, &envc);
    if (rc != 0) {
        proc_free_vec(args, argc);
        return rc;
    }
    /* Admission re-entry (SPEC 1.1): resolve through the sysroot, then
     * tear the old address space down before loading, so a failed load
     * still leaves the old image behind (rc < 0 returns early). */
    fd = ppc32_open_guest_ro(ctx, path);
    if (fd < 0) {
        rc = -(long)errno;
        proc_free_vec(args, argc);
        proc_free_vec(env, envc);
        return rc;
    }
    memset(&info, 0, sizeof info);
    ppc32_vm_reset_for_exec(ctx);
    if (ppc32_elf_load(ctx, fd, path, &info) != 0) {
        proc_free_vec(args, argc);
        proc_free_vec(env, envc);
        return -ENOEXEC;
    }
    /* Fresh process image: the register file, pending signals, signal
     * stack, thread identity, and heap/stack mirrors reset to the
     * load state (Linux exec semantics); then the new stack + auxv. */
    memset(ctx->gpr, 0, sizeof ctx->gpr);
    memset(ctx->gpr_hi, 0, sizeof ctx->gpr_hi);
    memset(ctx->fpr, 0, sizeof ctx->fpr);
    ctx->nip = 0U;
    ctx->lr = 0U;
    ctx->ctr = 0U;
    ctx->cr = 0U;
    ctx->xer = 0U;
    ctx->fpscr = 0U;
    ctx->spefscr = 0U;
    ctx->acc = 0ULL;
    ctx->res_addr = 0U;
    ctx->res_val = 0U;
    ctx->res_valid = 0U;
    ctx->reservation_epoch++;
    ctx->sig_mask = 0ULL;
    ctx->pending_signals = 0ULL;
    ctx->sig_last_frame_va = 0U;
    ctx->sig_last_frame_rt = 0U;
    ctx->altstack_sp = 0U;
    ctx->altstack_size = 0U;
    ctx->altstack_flags = 2U; /* SS_DISABLE */
    ctx->clear_child_tid = 0U;
    ctx->robust_list_head = 0U;
    ctx->robust_list_len = 0U;
    ctx->host_tid = (int)(long)getpid();
    ctx->guest_pid = (uint32_t)(long)getpid();
    ctx->guest_tid = ctx->guest_pid;
    ctx->exec_path = NULL;
    use_env = env;
    if (ppc32_stack_setup(ctx, &info, (int)argc, args, use_env, &sp) != 0) {
        proc_free_vec(args, argc);
        proc_free_vec(env, envc);
        return -ENOMEM;
    }
    ppc32_proc_redetect_profile(ctx, info.text_start, info.text_end);
    ctx->nip = info.entry;
    ctx->gpr[PPC32_REG_SP] = sp;
    ctx->exit_reason = PPC32_EXIT_NONE;
    /* The new vectors back guest_argv/host_envp from here on (ownership
     * transfers to ctx; execve is rare, so no reclaim). */
    ctx->guest_argc = (int)argc;
    ctx->guest_argv = args;
    ctx->host_envp = env;
    (void)envc;
    return 0;
}

/* Host rusage -> BE guest struct rusage (72 B) at va. */
static long proc_put_rusage(ppc32_ctx_t *ctx, uint32_t va,
    const struct rusage *hs)
{
    uint32_t i;
    uint32_t off;

    if (hs == NULL) {
        return 0;
    }
    if (!ppc32_range_ok(va, PROC_RUSAGE_SIZE)) {
        return -EFAULT;
    }
    ppc32_st32be(ctx, va, (uint32_t)(int32_t)hs->ru_utime.tv_sec);
    ppc32_st32be(ctx, va + 4U, (uint32_t)(int32_t)hs->ru_utime.tv_usec);
    ppc32_st32be(ctx, va + 8U, (uint32_t)(int32_t)hs->ru_stime.tv_sec);
    ppc32_st32be(ctx, va + 12U, (uint32_t)(int32_t)hs->ru_stime.tv_usec);
    {
        static const size_t ru_offs[PROC_RUSAGE_LONGS] = {
            16U, 20U, 24U, 28U, 32U, 36U, 40U, 44U, 48U, 52U, 56U, 60U,
            64U, 68U
        };
        long vals[PROC_RUSAGE_LONGS];

        vals[0] = hs->ru_maxrss;
        vals[1] = hs->ru_ixrss;
        vals[2] = hs->ru_idrss;
        vals[3] = hs->ru_isrss;
        vals[4] = hs->ru_minflt;
        vals[5] = hs->ru_majflt;
        vals[6] = hs->ru_nswap;
        vals[7] = hs->ru_inblock;
        vals[8] = hs->ru_oublock;
        vals[9] = hs->ru_msgsnd;
        vals[10] = hs->ru_msgrcv;
        vals[11] = hs->ru_nsignals;
        vals[12] = hs->ru_nvcsw;
        vals[13] = hs->ru_nivcsw;
        for (i = 0U; i < PROC_RUSAGE_LONGS; i++) {
            off = (uint32_t)ru_offs[i];
            ppc32_st32be(ctx, va + off, (uint32_t)(int32_t)vals[i]);
        }
    }
    return 0;
}

long ppc32_proc_wait4(ppc32_ctx_t *ctx, uint32_t pid_va, uint32_t status_va,
    uint32_t options, uint32_t rusage_va)
{
#if defined(__linux__) || defined(__APPLE__)
    pid_t pid = (pid_va == 0xFFFFFFFFU) ? (pid_t)-1 : (pid_t)(int32_t)pid_va;
    struct rusage ru;
    struct rusage *rup = (rusage_va == 0U) ? NULL : &ru;
    int status = 0;
    pid_t r;

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    if (status_va != 0U && !ppc32_range_ok(status_va, 4U)) {
        return -EFAULT;
    }
    if (rusage_va != 0U && !ppc32_range_ok(rusage_va, PROC_RUSAGE_SIZE)) {
        return -EFAULT;
    }
    memset(&ru, 0, sizeof ru);
    r = wait4(pid, (status_va == 0U) ? NULL : &status,
        (int)options, rup);
    if (r < 0) {
        return -(long)errno;
    }
    if (status_va != 0U) {
        ppc32_st32be(ctx, status_va, (uint32_t)status);
    }
    if (rup != NULL) {
        long rc = proc_put_rusage(ctx, rusage_va, &ru);

        if (rc != 0) {
            return rc;
        }
    }
    return (long)r;
#else
    (void)ctx;
    (void)pid_va;
    (void)status_va;
    (void)options;
    (void)rusage_va;
    return -ENOSYS;
#endif
}

long ppc32_proc_waitid(ppc32_ctx_t *ctx, uint32_t idtype, uint32_t id,
    uint32_t infop_va, uint32_t options)
{
#ifdef __linux__
    siginfo_t si;
    int r;

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    if (idtype != PROC_P_ALL && idtype != PROC_P_PID &&
        idtype != PROC_P_PGID) {
        return -EINVAL;
    }
    if ((options & (uint32_t)0x01000000U) != 0U) {
        return -EINVAL; /* WNOWAIT: no siginfo queue is kept */
    }
    if ((options & ~PROC_WID_OK_MASK) != 0U) {
        return -EINVAL;
    }
    if (infop_va != 0U && !ppc32_range_ok(infop_va, PROC_SIGINFO_SIZE)) {
        return -EFAULT;
    }
    memset(&si, 0, sizeof si);
    r = waitid((idtype_t)idtype, (id_t)id,
        (infop_va == 0U) ? NULL : &si, (int)options);
    if (r != 0) {
        return -(long)errno;
    }
    if (infop_va != 0U) {
        uint8_t zero[PROC_SIGINFO_SIZE];
        uint32_t i;

        memset(zero, 0, sizeof zero);
        if (ppc32_copyout(ctx, infop_va, zero, sizeof zero) != 0) {
            return -EFAULT;
        }
        ppc32_st32be(ctx, infop_va, (uint32_t)si.si_signo);
        ppc32_st32be(ctx, infop_va + 4U, (uint32_t)si.si_errno);
        ppc32_st32be(ctx, infop_va + 8U, (uint32_t)si.si_code);
        ppc32_st32be(ctx, infop_va + 12U, (uint32_t)si.si_pid);
        ppc32_st32be(ctx, infop_va + 16U, (uint32_t)si.si_uid);
        ppc32_st32be(ctx, infop_va + 20U, (uint32_t)si.si_status);
        for (i = 24U; i < PROC_SIGINFO_SIZE; i += 4U) {
            ppc32_st32be(ctx, infop_va + i, 0U);
        }
    }
    return 0;
#else
    (void)ctx;
    (void)idtype;
    (void)id;
    (void)infop_va;
    (void)options;
    return -ENOSYS;
#endif
}

long ppc32_proc_pipe2(ppc32_ctx_t *ctx, uint32_t fds_va, uint32_t flags)
{
#ifdef __linux__
    int fds[2];

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    if (!ppc32_range_ok(fds_va, 8U)) {
        return -EFAULT;
    }
    if ((flags & ~(uint32_t)02000000U) != 0U) {
        return -EINVAL;
    }
    fds[0] = -1;
    fds[1] = -1;
    if (pipe2(fds, (int)flags) != 0) {
        return -(long)errno;
    }
    ppc32_st32be(ctx, fds_va, (uint32_t)fds[0]);
    ppc32_st32be(ctx, fds_va + 4U, (uint32_t)fds[1]);
    return 0;
#else
    (void)ctx;
    (void)fds_va;
    (void)flags;
    return -ENOSYS;
#endif
}

long ppc32_proc_pipe(ppc32_ctx_t *ctx, uint32_t fds_va)
{
#if defined(__linux__) || defined(__APPLE__)
    int fds[2];

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    if (!ppc32_range_ok(fds_va, 8U)) {
        return -EFAULT;
    }
    fds[0] = -1;
    fds[1] = -1;
    if (pipe(fds) != 0) {
        return -(long)errno;
    }
    ppc32_st32be(ctx, fds_va, (uint32_t)fds[0]);
    ppc32_st32be(ctx, fds_va + 4U, (uint32_t)fds[1]);
    return 0;
#else
    (void)ctx;
    (void)fds_va;
    return -ENOSYS;
#endif
}

long ppc32_proc_dup2(uint32_t oldfd, uint32_t newfd)
{
#if defined(__linux__) || defined(__APPLE__)
    int r;

    if (oldfd == newfd) {
        if (fcntl((int)oldfd, F_GETFD) < 0) {
            return -(long)errno;
        }
        return (long)newfd;
    }
    r = dup2((int)oldfd, (int)newfd);
    if (r < 0) {
        return -(long)errno;
    }
    return (long)r;
#else
    (void)oldfd;
    (void)newfd;
    return -ENOSYS;
#endif
}

void ppc32_proc_return(ppc32_ctx_t *ctx, long ret)
{
    if (ctx == NULL) {
        return;
    }
    if (ret < 0L && ret >= -4095L) {
        ctx->gpr[3] = (uint32_t)(-ret);
        ctx->cr |= PPC32_CR0_SO;
    } else {
        ctx->gpr[3] = (uint32_t)ret;
        ctx->cr &= (uint32_t)~PPC32_CR0_SO;
    }
    ctx->syscalls_executed++;
    ctx->nip += 4U;
}

int ppc32_proc_dispatch(ppc32_ctx_t *ctx, uint32_t nr, uint32_t a0,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
    long ret;
    int advance = 1;

    if (ctx == NULL) {
        return 0;
    }
    switch (nr) {
    case PPC32_NR_FORK:
        ret = ppc32_proc_fork(ctx);
        break;
    case PPC32_NR_VFORK:
        ret = ppc32_proc_vfork(ctx);
        break;
    case PPC32_NR_EXECVE:
        ret = ppc32_proc_execve(ctx, a0, a1, a2);
        /* Success reparks nip on the new entry: no sc advance. */
        advance = (ret == 0L) ? 0 : 1;
        break;
    case PPC32_NR_WAITPID:
        ret = ppc32_proc_wait4(ctx, a0, a1, a2, 0U);
        break;
    case PPC32_NR_WAIT4:
        ret = ppc32_proc_wait4(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_WAITID:
        ret = ppc32_proc_waitid(ctx, a0, a1, a2, a3);
        break;
    case PPC32_NR_PIPE:
        ret = ppc32_proc_pipe(ctx, a0);
        break;
    case PPC32_NR_PIPE2:
        ret = ppc32_proc_pipe2(ctx, a0, a1);
        break;
    case PPC32_NR_DUP:
        if (a1 > 1024U) {
            ret = -EINVAL;
            break;
        }
        {
            int r = fcntl((int)a0, F_DUPFD, (int)a1);

            ret = (r < 0) ? -(long)errno : (long)r;
            proc_invalidate_reservation(ctx);
        }
        break;
    case PPC32_NR_DUP2:
        proc_invalidate_reservation(ctx);
        ret = ppc32_proc_dup2(a0, a1);
        break;
    default:
        (void)a4;
        (void)a5;
        return 0;
    }
    (void)a4;
    (void)a5;
    if (ret < 0L && ret >= -4095L) {
        ctx->gpr[3] = (uint32_t)(-ret);
        ctx->cr |= PPC32_CR0_SO;
    } else {
        ctx->gpr[3] = (uint32_t)ret;
        ctx->cr &= (uint32_t)~PPC32_CR0_SO;
    }
    ctx->syscalls_executed++;
    if (advance != 0) {
        ctx->nip += 4U;
    }
    return 1;
}
