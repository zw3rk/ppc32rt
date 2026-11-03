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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dbt/dbt.h"
#include "os/convert.h"
#include "os/signals.h"
#include "os/syscall_nr.h"
#include "os/threads.h"
#include "ppc32rt.h"
#include "rt32/ppc32.h"
#include "rt32/ppc32_vm_priv.h"
#include "vm/vm32.h"

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

long ppc32_proc_getpid(void)
{
    return (long)getpid();
}

/* Coordinated fork protocol (P32-R3-4): the parent holds every
 * process-global runtime lock across the snapshot so no update is
 * half-written when the address space clones, releases them after a
 * parent return, and the child drops every inherited locked value
 * (each owner is gone) and rebuilds the thread table around the sole
 * surviving thread. Global acquisition order (outermost first, matching
 * all observed runtime nesting: dispositions enter the VM through the
 * locked copy helpers; file and TLB updates run under the VM lock):
 * signal dispositions, thread table, translation cache, VM, TLB,
 * inode, LL/SC. The fork syscall path holds none of these on entry,
 * so the prepare cannot self-deadlock; a concurrent holder only
 * delays the snapshot. The cache sits before the VM (snapshot reads
 * nest cache -> VM). The truncate/write file paths honor the same
 * order (P32-R4-8): the inode lock is only ever taken alone or under
 * the VM lock, and TLB updates happen after it is released, so no
 * thread can hold the inode lock while waiting on the TLB lock fork
 * holds. */
static void proc_fork_prepare(void)
{
    ppc32_sig_fork_prepare();
    ppc32_thread_fork_prepare();
    ppc32_cache_fork_prepare();
    ppc32_vm_lock();
    vm32_tlb_fork_prepare();
    vm_file_fork_prepare();
    vm32_ll_fork_prepare();
}

static void proc_fork_parent(void)
{
    vm32_ll_fork_parent();
    vm_file_fork_parent();
    vm32_tlb_fork_parent();
    ppc32_vm_unlock();
    ppc32_cache_fork_parent();
    ppc32_thread_fork_parent();
    ppc32_sig_fork_parent();
}

static void proc_fork_child(ppc32_ctx_t *ctx)
{
    vm32_ll_fork_child();
    vm_file_fork_child();
    vm32_tlb_fork_child();
    ppc32_vm_fork_child();
    proc_child_refresh(ctx);
    ppc32_thread_fork_child(ctx);
    ppc32_cache_fork_child();
    ppc32_sig_fork_child();
}

long ppc32_proc_fork(ppc32_ctx_t *ctx)
{
    pid_t pid;

    if (ctx == NULL) {
        return -EFAULT;
    }
    proc_invalidate_reservation(ctx);
    proc_fork_prepare();
    pid = fork();
    if (pid < 0) {
        int e = errno;

        proc_fork_parent();
        return -(long)e;
    }
    if (pid == 0) {
        proc_fork_child(ctx);
        return 0;
    }
    proc_fork_parent();
    return (long)pid;
}

long ppc32_proc_vfork(ppc32_ctx_t *ctx)
{
    /* No address-space sharing fast path: plain fork preserves the
     * observable result (0 in the child, the child pid in the parent)
     * and is safe when the child promptly execves or exits. */
    return ppc32_proc_fork(ctx);
}

/* Scan guest text for a major-opcode-4 word (SPE APU, SPEC 2.2).
 * P32-R9-7: the whole executable segment is probed (not just the first
 * 65536 instructions) so late-SPE binaries classify correctly; a
 * PT_GNU_ATTRIBUTES SPE marker (ppc32_elf_info_t.gnu_power_spe) is
 * honored by the callers on top of this scan. */
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
        !ppc32_range_ok(text_start, (size_t)(text_end - text_start)) ||
        !ppc32_vm_range_prot_ok(ctx, text_start,
            (size_t)(text_end - text_start), 1U)) {
        ctx->profile = PPC32_PROFILE_CLASSIC;
        ctx->is_spe = 0U;
        return;
    }
    len = (uint64_t)text_end - (uint64_t)text_start;
    n = len / 4ULL;
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
        /* P32-R9-5: the vector slot needs a mapped, readable,
         * untrapped page; a raw ld32be could crash the host. */
        if (!ppc32_range_ok(vec_va + n * 4U, 4U) ||
            !ppc32_vm_range_prot_ok(ctx, vec_va + n * 4U, 4U, 1U)) {
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

/* Header probe mirroring the loader's admission (ppc32_elf32.c):
 * magic, ELFCLASS32, ELFDATA2MSB, EM_PPC(20), ET_EXEC(2)/ET_DYN(3).
 * Runs on the already-open fd via pread, so the caller can reject a
 * foreign binary before ppc32_vm_reset_for_exec. */
/* Admission classes: 1 runs (32-bit big-endian PowerPC EXEC/DYN),
 * 0 is a script-or-text fallback (-ENOEXEC, the shell re-execs its own
 * interpreter like the kernel would), -1 is a valid ELF of another
 * machine (the caller runs it natively in a host child: qemu-user
 * parity for host binaries on PATH). */
static int proc_admission_ok(int fd, const char *path)
{
    uint8_t h[20];
    size_t got = 0U;
    uint16_t type;
    uint16_t machine;

    while (got < sizeof h) {
        ssize_t n = pread(fd, h + got, sizeof h - got, (off_t)got);

        if (n <= 0) {
            return 0;
        }
        got += (size_t)n;
    }
    if (h[0] != 0x7fU || h[1] != (uint8_t)'E' || h[2] != (uint8_t)'L' ||
        h[3] != (uint8_t)'F') {
        return 0;
    }
    if (h[4] != 1U || h[5] != 2U) {
        return -1;
    }
    type = (uint16_t)(((uint16_t)h[16] << 8) | (uint16_t)h[17]);
    machine = (uint16_t)(((uint16_t)h[18] << 8) | (uint16_t)h[19]);
    if (machine != 20U) {
        return -1;
    }
    if (type != 2U && type != 3U) {
        fprintf(stderr, "ppc32rt: %s: unsupported ELF type %u\n", path,
            (unsigned int)type);
        return 0;
    }
    return 1;
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
     * probe the header BEFORE tearing the old address space down, so a
     * foreign binary (scripts, native host binaries) is rejected with
     * -ENOEXEC while the old image still runs. Deeper load failures past
     * this point still destroy the image (partial-teardown exposure, as
     * on Linux). */
    /* RC5: /proc/self/exe names the running guest image (BusyBox applets
     * re-exec it); substitute the guest executable path with the same
     * priority procfs uses (exec_path, else argv[0]). The literal host
     * path would open the translator itself and fail admission. */
    if (strcmp(path, "/proc/self/exe") == 0) {
        const char *ep = NULL;

        if (ctx->exec_path != NULL) {
            ep = ctx->exec_path;
        } else if (ctx->guest_argv != NULL && ctx->guest_argc > 0) {
            ep = ctx->guest_argv[0];
        }
        if (ep == NULL) {
            proc_free_vec(args, argc);
            proc_free_vec(env, envc);
            return -ENOENT;
        }
        {
            size_t i;

            for (i = 0U; ep[i] != '\0'; i++) {
                if (i + 1U >= sizeof path) {
                    proc_free_vec(args, argc);
                    proc_free_vec(env, envc);
                    return -ENAMETOOLONG;
                }
                path[i] = ep[i];
            }
            path[i] = '\0';
        }
    }
    fd = ppc32_open_guest_ro(ctx, path);
    if (fd < 0) {
        rc = -(long)errno;
        proc_free_vec(args, argc);
        proc_free_vec(env, envc);
        return rc;
    }
    {
        int adm = proc_admission_ok(fd, path);

        if (adm == 0) {
            close(fd);
            proc_free_vec(args, argc);
            proc_free_vec(env, envc);
            return -ENOEXEC;
        }
        if (adm < 0) {
            /* Foreign ELF (host arch): run it natively in a host child
             * (qemu-user parity: the oracle execs host binaries like
             * /usr/bin/ls natively, so BusyBox applets resolve through
             * PATH). The waiting guest exits with the native status;
             * gpr[0] is reparked on EXIT so the engine stops (the
             * dispatch post-check in main.c picks it up). */
            pid_t pid;
            int st = 0;
            int code;

            close(fd);
            fflush(NULL);
            pid = fork();
            if (pid < 0) {
                int e = errno;

                proc_free_vec(args, argc);
                proc_free_vec(env, envc);
                return -(long)e;
            }
            if (pid == 0) {
                execve(path, args, env);
                _exit(127);
            }
            proc_free_vec(args, argc);
            proc_free_vec(env, envc);
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
            }
            code = WIFEXITED(st) ? WEXITSTATUS(st) :
                (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 127);
            ctx->exit_arg = (uint32_t)(code & 0xFF);
            ctx->gpr[0] = PPC32_NR_EXIT;
            ctx->gpr[3] = ctx->exit_arg;
            return (long)code;
        }
    }
    memset(&info, 0, sizeof info);
    ppc32_vm_reset_for_exec(ctx);
    if (ppc32_elf_load(ctx, fd, path, &info) != 0) {
        proc_free_vec(args, argc);
        proc_free_vec(env, envc);
        return -ENOEXEC;
    }
    /* Fresh process image: the register file, signal stack, thread
     * identity, and heap/stack mirrors reset to the load state; then
     * the new stack + auxv. Linux exec semantics for signals: caught
     * dispositions return to SIG_DFL (ignored ones stay ignored), while
     * the calling thread's blocked mask and pending set survive the
     * image replacement, so neither is cleared here. */
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
    ppc32_sig_reset_exec();
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
    /* AT_EXECFN/_dl_get_origin needs the guest-absolute path (the kernel
     * reports d_path; BusyBox re-execs relative argv[0] when running a
     * script fallback). Guest cwd == host cwd (no chdir emulation). */
    {
        char *ep = NULL;

        if (path[0] == '/') {
            size_t m = strlen(path);

            ep = (char *)malloc(m + 1U);
            if (ep != NULL) {
                memcpy(ep, path, m + 1U);
            }
        } else {
            char cwd[4096];

            if (getcwd(cwd, sizeof cwd) != NULL) {
                size_t n = strlen(cwd);
                size_t m = strlen(path);

                if (n + 1U + m + 1U <= sizeof cwd) {
                    ep = (char *)malloc(n + 1U + m + 1U);
                    if (ep != NULL) {
                        memcpy(ep, cwd, n);
                        ep[n] = '/';
                        memcpy(ep + n + 1U, path, m + 1U);
                    }
                }
            }
        }
        ctx->exec_path = (ep != NULL) ? ep : NULL;
    }
    use_env = env;
    if (ppc32_stack_setup(ctx, &info, (int)argc, args, use_env, &sp) != 0) {
        proc_free_vec(args, argc);
        proc_free_vec(env, envc);
        return -ENOMEM;
    }
    ppc32_proc_redetect_profile(ctx, info.text_start, info.text_end);
    /* P32-R9-7: a PT_GNU_ATTRIBUTES SPE marker wins over the opcode
     * scan (an explicit --profile still wins; redetect honors it). */
    if (info.gnu_power_spe != 0U &&
        ctx->profile != PPC32_PROFILE_CLASSIC &&
        ctx->profile != PPC32_PROFILE_SPE) {
        ctx->profile = PPC32_PROFILE_SPE;
        ctx->is_spe = 1U;
    }
    /* RC5: interpreter entry when PT_INTERP is present (see main.c). */
    ctx->nip = ctx->elf_entry;
    ctx->gpr[PPC32_REG_SP] = sp;
    ctx->exit_reason = PPC32_EXIT_NONE;
    /* The reset cleared vm_ready; the new image + stack are up. */
    ctx->vm_ready = true;
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
