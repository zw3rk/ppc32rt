/*
 * src/main.c — entry point and option handling for ppc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0: option/env plumbing and the invocation forms only. No engine
 * is wired yet (Phases 1 and 2); running a guest exits 2 with a clear
 * message.
 */

/* POSIX 2008: setenv/environ under strict -std=c11 with musl. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef AT_EXECFD
#define AT_EXECFD 2 /* kernel auxv key (linux/auxvec.h) */
#endif
#endif

#include "ppc32rt.h"
#include "main_parse.h"
#include "rt32/ppc32.h"
#include "interp/interp.h"
#include "os/convert.h"
#include "os/hostfault.h"
#include "os/signals.h"
#include "os/syscalls.h"
#include "os/threads.h"
#include "dbt/dbt.h"
#include "dbt/emit_int.h"
#include "dbt/emit_fp.h"
#include "dbt/difftest.h"

extern char **environ;

/* Probe skip latch owned by src/rt32/ppc32_host.c (the frozen context
 * carries no slot for it); declared here so main.c stays the only
 * other file that names it. */
extern void ppc32_host_set_no_host(bool skip);

#define PPC32RT_VERSION "0.2-phase2"

static void usage(FILE *out)
{
    static const char *msg =
        "ppc32rt — 32-bit PowerPC (750 / e500v2) Linux user-mode translator\n"
        "\n"
        "Usage:\n"
        "  ppc32rt [--interp | --dbt] [--difftest] [--trace]\n"
        "          [--profile classic|spe] [--sysroot DIR] [--window HEX]\n"
        "          [--cache DIR | --aot-cache FILE]\n"
        "          [--execfn PATH] [--image-fd FD] [--no-host] -- PATH [ARGS...]\n"
        "  ppc32rt --help\n"
        "  ppc32rt --version\n"
        "\n"
        "Environment: PPC32RT_ENGINE, PPC32RT_PROFILE\n";
    fputs(msg, out);
}

/* Wave 1 host-contract CLI state (HOST-CONTRACT §3). The frozen
 * ppc32_ctx_t carries no window/fd slots, so parsed values wait here
 * until guest_load consumes them. UINT64_MAX = no --window: run the
 * contract G order (PPC32RT_WINDOW → host hint → G=0 → scan). */
static uint64_t g_requested_window = UINT64_MAX;
static const char *g_execfn = NULL;
static int g_image_fd = -1;
static bool g_no_host = false;

/* Returns the index of the guest PATH in argv[], or -1 on error. */
static int parse_args(ppc32_ctx_t *ctx, int argc, char **argv)
{
    int i = 1;

    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            exit(0);
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("ppc32rt %s\n", PPC32RT_VERSION);
            exit(0);
        }
        if (strcmp(argv[i], "--interp") == 0) {
            ctx->engine = PPC32_ENGINE_INTERP;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--dbt") == 0) {
            ctx->engine = PPC32_ENGINE_DBT;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--difftest") == 0) {
            ctx->difftest = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--sysroot") == 0) {
            if (i + 1 >= argc) {
                return -1;
            }
            ctx->sysroot = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--cache") == 0 ||
            strcmp(argv[i], "--aot-cache") == 0) {
            if (i + 1 >= argc) {
                return -1;
            }
            ctx->cache_dir = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--trace") == 0) {
            ctx->trace_syscalls = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--window") == 0) {
            /* Fail-hard on a bad value (incl. the UINT64_MAX
             * "unset" sentinel); reservation failure is fail-hard
             * in ppc32_vm_init. */
            uint64_t w = 0U;

            if (i + 1 >= argc || ppc32_parse_u64(argv[i + 1], 0, &w) != 0 ||
                w == UINT64_MAX) {
                return -1;
            }
            g_requested_window = w;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--execfn") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '\0') {
                return -1;
            }
            g_execfn = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--image-fd") == 0) {
            /* Any fd >= 0 is valid (0 included, stdin closed). */
            uint64_t f = 0U;

            if (i + 1 >= argc || ppc32_parse_u64(argv[i + 1], 10, &f) != 0 ||
                f > (uint64_t)INT_MAX) {
                return -1;
            }
            g_image_fd = (int)f;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--no-host") == 0) {
            g_no_host = true;
            i++;
            continue;
        }
        if (argv[i][0] != '-') {
            return i;
        }
        if (i + 1 >= argc) {
            return -1;
        }
        if (strcmp(argv[i], "--profile") == 0) {
            if (ppc32_parse_profile(argv[i + 1], &ctx->profile) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
        i += 2;
    }

    if (i >= argc) {
        return -1; /* missing "-- PATH" */
    }
    return i + 1; /* first token after "--" */
}

static void apply_env(ppc32_ctx_t *ctx)
{
    const char *s;

    if (ctx->engine != PPC32_ENGINE_INTERP &&
        ctx->engine != PPC32_ENGINE_DBT) {
        s = getenv("PPC32RT_ENGINE");
        if (s != NULL) {
            if (ppc32_parse_engine(s, &ctx->engine) != 0) {
                fprintf(stderr, "ppc32rt: bad PPC32RT_ENGINE=%s\n", s);
                exit(2);
            }
        }
    }
    if (ctx->profile != PPC32_PROFILE_CLASSIC &&
        ctx->profile != PPC32_PROFILE_SPE) {
        s = getenv("PPC32RT_PROFILE");
        if (s != NULL) {
            if (ppc32_parse_profile(s, &ctx->profile) != 0) {
                fprintf(stderr, "ppc32rt: bad PPC32RT_PROFILE=%s\n", s);
                exit(2);
            }
        }
    }
    /* RC5 E2: guest sysroot for absolute-path resolution (loader,
     * openat/access/statx); --sysroot wins over the environment. */
    if (ctx->sysroot == NULL) {
        ctx->sysroot = getenv("PPC32RT_SYSROOT");
    }
}

static int run_interp(ppc32_ctx_t *ctx);
static int run_dbt(ppc32_ctx_t *ctx);
static int run_difftest(ppc32_ctx_t *ctx);
static int report_stop(ppc32_ctx_t *ctx);

/* RC2 emitter bridge: adapt L2c's ppc32_emit_int (own ctx struct) to the
 * L2b driver callback (single definition lives in dbt.h). emit_begin is
 * a trivial binder, so rebinding per instruction is correct. NEXT and
 * END both count as emitted (dbt.c ends blocks itself); FALLBACK and
 * staging overflow count as refuse. */
static ppc32_ctx_t *g_emit_owner;

static int emit_bridge_fn(a64_buf_t *b, const ppc32_insn_t *insn,
    uint32_t pc)
{
    ppc32_emit_ctx_t e;
    int rc;

    ppc32_emit_begin(&e, g_emit_owner, b);
    rc = ppc32_emit_int(&e, insn, pc);
    if (rc == PPC32_EMIT_FALLBACK && !b->overflow) {
        rc = ppc32_emit_fp(&e, insn, pc);
    }
    if (rc == PPC32_EMIT_FALLBACK || b->overflow) {
        return 1;
    }
    return 0;
}

static void emit_bridge_install(ppc32_ctx_t *ctx)
{
    g_emit_owner = ctx;
    ppc32_dbt_set_emitter(emit_bridge_fn);
}

/* RC5: absolute guest-executable path for /proc/self/exe (ld.so's
 * _dl_get_origin asserts linkval[0] == '/'; the kernel always reports
 * an absolute d_path). Falls back to argv as-is when the cwd is
 * not recoverable. */
static const char *abs_exec_path(const char *given)
{
    static char abs[4096];
    size_t n;

    if (given == NULL || given[0] == '/') {
        return given;
    }
    if (getcwd(abs, sizeof abs) == NULL) {
        return given;
    }
    n = strlen(abs);
    if (n + 1U + strlen(given) + 1U > sizeof abs) {
        return given;
    }
    abs[n] = '/';
    memcpy(abs + n + 1U, given, strlen(given) + 1U);
    return abs;
}

int main(int argc, char **argv)
{
    ppc32_ctx_t ctx;
    int path_idx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = -1;  /* unset: --interp/--dbt or PPC32RT_ENGINE */
    ctx.profile = -1; /* unset: --profile or PPC32RT_PROFILE */

    path_idx = parse_args(&ctx, argc, argv);
    if (path_idx < 0) {
        usage(stderr);
        return 2;
    }
    apply_env(&ctx);
    /* Host protection-fault translation (hostfault.h): guest accesses
     * that violate page permissions revive at the engine checkpoints
     * with FAULT recorded; anything else still crashes loudly. */
    ppc32_hostfault_install();
    if (g_no_host) {
        ppc32_host_set_no_host(true);
    }
    if (g_execfn != NULL) {
        /* --execfn decouples the path from argv: every token after
         * "--" stays verbatim in guest_argv (custom argv[0] kept,
         * even with no extra args). */
        ctx.exec_path = abs_exec_path(g_execfn);
    } else {
        /* Without --execfn, argv[i] is both path and argv[0]. */
        ctx.exec_path = abs_exec_path(argv[path_idx]);
    }
    ctx.guest_argc = argc - path_idx;
    ctx.guest_argv = &argv[path_idx];
    ctx.host_envp = environ;

    /* RC2: interp + dbt engines live; --difftest runs dbt-vs-interp. */
    if (getenv("PPC32RT_ENGINE") == NULL && ctx.engine < 0) {
        ctx.engine = PPC32_ENGINE_DBT;
    }
    if (ctx.difftest) {
        return run_difftest(&ctx);
    }
    if (ctx.engine == PPC32_ENGINE_DBT) {
        return run_dbt(&ctx);
    }
    return run_interp(&ctx);
}

/* Shared guest load: reserve the window, load the ELF, set up the stack,
 * and park nip/sp at the entry point. Returns 0 on success. */
static int guest_load(ppc32_ctx_t *ctx, ppc32_elf_info_t *info, uint32_t *sp)
{
    int fd = -1;

    ppc32_host_probe(ctx);
    /* Contract G order lives in ppc32_vm_init; UINT64_MAX means "no
     * explicit --window": env → host hint → G=0 → aligned scan. */
    if (ppc32_vm_init(ctx, g_requested_window) != 0) {
        fprintf(stderr, "ppc32rt: cannot reserve guest window\n");
        return 1;
    }
    /* Image source order: --image-fd wins, then AT_EXECFD from our own
     * auxv, then the exec path. The loader closes fd after mapping
     * (all paths); no other fd is touched. */
    if (g_image_fd >= 0) {
        fd = g_image_fd;
    } else {
        fd = ppc32_auxv_exec_fd();
    }
    if (fd < 0) {
        fd = ppc32_open_guest_ro(ctx, ctx->exec_path);
        if (fd < 0) {
            fprintf(stderr, "ppc32rt: cannot open '%s'\n", ctx->exec_path);
            return 1;
        }
    }
    /* ppc32_elf_load closes fd (success and failure paths). */
    if (ppc32_elf_load(ctx, fd, ctx->exec_path, info) != 0) {
        return 1;
    }
    if (ppc32_stack_setup(ctx, info, ctx->guest_argc, ctx->guest_argv,
            ctx->host_envp, sp) != 0) {
        fprintf(stderr, "ppc32rt: stack setup failed\n");
        return 1;
    }
    /* RC5: start at the interpreter entry when PT_INTERP is present
     * (ctx->elf_entry tracks the interp entry; info->entry is the app). */
    ctx->nip = ctx->elf_entry;
    ctx->gpr[PPC32_REG_SP] = *sp;
    ctx->exit_reason = PPC32_EXIT_NONE;
    /* RC4: register the main thread (slot 0, guest/host tids) before the
     * first clone; failure is non-fatal (clone then reports EAGAIN). */
    (void)ppc32_thread_init_main(ctx);
    return 0;
}

/* RC4: deliver a synchronous guest fault/trap to an installed handler.
 * FAULT (fault_addr set by the engine) raises SIGSEGV; TRAP (nip at the
 * trapping insn) raises SIGTRAP. Returns 1 when execution resumes at
 * the handler (or re-executes on SIG_IGN), 0 when the guest must die
 * (SIG_DFL or an unbuildable frame). */
static int deliver_sync(ppc32_ctx_t *ctx)
{
    long r;

    if (ctx->exit_reason == PPC32_EXIT_TRAP) {
        r = ppc32_sig_deliver_sync(ctx, (int)PPC32_SIGTRAP, 0, ctx->nip,
            0U);
    } else {
        /* FAULT carries the preserved class: host SIGBUS (truncated file
         * page) delivers guest SIGBUS, everything else SIGSEGV. */
        uint32_t sig = (ctx->fault_signo == (uint32_t)PPC32_SIGBUS) ?
            (uint32_t)PPC32_SIGBUS : (uint32_t)PPC32_SIGSEGV;

        r = ppc32_sig_deliver_sync(ctx, (int)sig, 0, ctx->fault_addr, 0U);
    }
    if (r != 0L && r != 1L) {
        return 0;
    }
    ctx->exit_reason = PPC32_EXIT_NONE;
    return 1;
}

/* RC4 inline clone child (syscalls.c CLONE): drive `child` to guest
 * exit on the calling host thread. Returns the guest exit code
 * (0..255), or a negative guest signal number when a fault/trap goes
 * undelivered. */
/* Host-fault-run adapters: single segments match the callback type
 * directly (interp_run); the int-returning dbt_run and the
 * loop-until-stop difftest drivers need these shims. */
static void run_dbt_one(ppc32_ctx_t *ctx)
{
    (void)dbt_run(ctx);
}

static void run_interp_stop(ppc32_ctx_t *ctx)
{
    while (ctx->exit_reason == PPC32_EXIT_NONE) {
        interp_run(ctx);
    }
}

static void run_dbt_stop(ppc32_ctx_t *ctx)
{
    while (ctx->exit_reason == PPC32_EXIT_NONE) {
        (void)dbt_run(ctx);
    }
}

long ppc32_run_guest_child(ppc32_ctx_t *child)
{
    if (child == NULL) {
        return -(long)PPC32_SIGSEGV;
    }
    for (;;) {
        if (child->engine == PPC32_ENGINE_DBT) {
            (void)ppc32_hostfault_run(child, run_dbt_one);
        } else {
            (void)ppc32_hostfault_run(child, interp_run);
        }
        if (child->exit_reason == PPC32_EXIT_SYSCALL) {
            uint32_t nr = child->gpr[0];

            if (ppc32_syscall_is_exit(nr)) {
                ppc32_syscall(child);
                return (long)(child->exit_arg & 0xFFU);
            }
            ppc32_syscall(child);
            if (ppc32_syscall_is_exit(child->gpr[0])) {
                return (long)(child->exit_arg & 0xFFU);
            }
            child->exit_reason = PPC32_EXIT_NONE;
            continue;
        }
        if (child->exit_reason == PPC32_EXIT_FAULT ||
            child->exit_reason == PPC32_EXIT_TRAP) {
            int trap = (child->exit_reason == PPC32_EXIT_TRAP);

            if (deliver_sync(child)) {
                continue;
            }
            return trap ? -(long)PPC32_SIGTRAP : -(long)PPC32_SIGSEGV;
        }
        if (child->exit_reason == PPC32_EXIT_NONE) {
            continue;
        }
        return -(long)PPC32_SIGILL;
    }
}

/* Dispatch one stopped-at-sc state; returns guest status on exit calls. */
static int syscall_dispatch(ppc32_ctx_t *ctx, int *status)
{
    uint32_t nr = ctx->gpr[0];

    if (ppc32_syscall_is_exit(nr)) {
        ppc32_syscall(ctx);
        *status = (int)(ctx->exit_arg & 0xFFU);
        return 1;
    }
    ppc32_syscall(ctx);
    /* Native execve delegation reparks gpr[0] on EXIT with the native
     * status in exit_arg (proc.c): stop the engine like an exit call. */
    if (ppc32_syscall_is_exit(ctx->gpr[0])) {
        *status = (int)(ctx->exit_arg & 0xFFU);
        return 1;
    }
    ctx->exit_reason = PPC32_EXIT_NONE;
    return 0;
}

/*
 * RC1 interp driver: guest_load, then interp_run <-> syscall dispatch
 * until a terminal exit. exit/exit_group return the guest status byte.
 */
static int run_interp(ppc32_ctx_t *ctx)
{
    ppc32_elf_info_t info;
    uint32_t sp;
    int status;

    if (guest_load(ctx, &info, &sp) != 0) {
        return 1;
    }
    for (;;) {
        /* Host protection faults inside the engine revive here with
         * FAULT already recorded (hostfault.h); the engine runs
         * inside the checkpoint frame. */
        (void)ppc32_hostfault_run(ctx, interp_run);
        if (ctx->exit_reason == PPC32_EXIT_NONE) {
            continue; /* budget/page stop: keep going */
        }
        if (ctx->exit_reason == PPC32_EXIT_FAULT ||
            ctx->exit_reason == PPC32_EXIT_TRAP) {
            if (deliver_sync(ctx)) {
                continue;
            }
        }
        if (ctx->exit_reason != PPC32_EXIT_SYSCALL) {
            return report_stop(ctx);
        }
        if (syscall_dispatch(ctx, &status) != 0) {
            return status;
        }
    }
}

/* RC5: stop-report helper shared by run_interp/run_dbt: reason, fault
 * address, and nip on one line for post-mortems. */
static int report_stop(ppc32_ctx_t *ctx)
{
    unsigned char b[4] = { 0U, 0U, 0U, 0U };

    if (ppc32_range_ok(ctx->nip, 4U)) {
        memcpy(b, ppc32_guest_ptr(ctx, ctx->nip), 4U);
    }
    fprintf(stderr, "ppc32rt: stopped, reason %u addr 0x%08X at nip 0x%08X word %02X%02X%02X%02X\n",
        ctx->exit_reason, ctx->fault_addr, ctx->nip, b[0], b[1], b[2],
        b[3]);
    return 1;
}

/*
 * RC2 dbt driver: same load, then dbt_run <-> syscall dispatch. The L2c
 * integer emitter is installed via the bridge; anything it refuses
 * falls back to interp_step inside dbt_run.
 */
static int run_dbt(ppc32_ctx_t *ctx)
{
    ppc32_elf_info_t info;
    uint32_t sp;
    int status;

    if (guest_load(ctx, &info, &sp) != 0) {
        return 1;
    }
    emit_bridge_install(ctx);
    for (;;) {
        (void)ppc32_hostfault_run(ctx, run_dbt_one);
        if (ctx->exit_reason == PPC32_EXIT_NONE) {
            continue;
        }
        if (ctx->exit_reason == PPC32_EXIT_FAULT ||
            ctx->exit_reason == PPC32_EXIT_TRAP) {
            if (deliver_sync(ctx)) {
                continue;
            }
        }
        if (ctx->exit_reason != PPC32_EXIT_SYSCALL) {
            return report_stop(ctx);
        }
        if (syscall_dispatch(ctx, &status) != 0) {
            return status;
        }
    }
}

/* Snapshot of one initially-writable guest region for difftest reset. */
typedef struct {
    uint32_t start;
    uint32_t len;
    uint8_t *bytes;
} difftest_snap_t;

/* Per-segment snapshot of every writable tracked region (stack, heap,
 * image data). The two engines share one window and the oracle runs
 * ahead, so without a restore the DUT would read the oracle's later
 * writes (RC2: glibc reused an LR save slot across a segment boundary
 * and the DUT returned into __tls_init_tp instead of its caller).
 * The snapshot is refreshed after load and after every syscall dispatch
 * (brk/mmap can reshape the region table); restoring before each DUT
 * segment reverts exactly the oracle's segment writes. Any writable
 * region that cannot be captured (cap or 16 MiB limit) aborts loudly
 * via *incomplete instead of silently mis-comparing. */
#define DIFFTEST_SNAP_CAP 64U
static size_t difftest_snapshot(ppc32_ctx_t *ctx, difftest_snap_t *segs,
    size_t cap, bool *incomplete)
{
    size_t n = 0U;
    size_t i;

    if (incomplete != NULL) {
        *incomplete = false;
    }
    for (i = 0U; i < ctx->region_count; i++) {
        uint32_t start = ctx->regions[i].start;
        uint32_t end = ctx->regions[i].end;

        if (end <= start || (ctx->regions[i].prot & 0x2U) == 0U) {
            continue;
        }
        if (n >= cap ||
            (uint64_t)end - (uint64_t)start > 16ULL * 1024ULL * 1024ULL) {
            if (incomplete != NULL) {
                *incomplete = true;
            }
            break;
        }
        segs[n].start = start;
        segs[n].len = end - start;
        segs[n].bytes = malloc(segs[n].len);
        if (segs[n].bytes == NULL) {
            if (incomplete != NULL) {
                *incomplete = true;
            }
            break;
        }
        memcpy(segs[n].bytes, ppc32_guest_ptr(ctx, start), segs[n].len);
        n++;
    }
    return n;
}

static void difftest_snap_free(difftest_snap_t *segs, size_t n)
{
    size_t i;

    for (i = 0U; i < n; i++) {
        free(segs[i].bytes);
        segs[i].bytes = NULL;
        segs[i].len = 0U;
    }
}

static void difftest_restore(ppc32_ctx_t *ctx, difftest_snap_t *segs,
    size_t n)
{
    size_t i;

    for (i = 0U; i < n; i++) {
        memcpy(ppc32_guest_ptr(ctx, segs[i].start), segs[i].bytes,
            segs[i].len);
    }
}

/* Copy the dispatched-syscall outcome (and VM mirrors) from the oracle
 * ctx to the DUT ctx after a shared dispatch. */
static void difftest_sync_dut(ppc32_ctx_t *dut, const ppc32_ctx_t *ref)
{
    size_t i;

    for (i = 0U; i < 32U; i++) {
        dut->gpr[i] = ref->gpr[i];
    }
    dut->nip = ref->nip;
    dut->lr = ref->lr;
    dut->ctr = ref->ctr;
    dut->cr = ref->cr;
    dut->xer = ref->xer;
    dut->exit_arg = ref->exit_arg;
    dut->brk_base = ref->brk_base;
    dut->brk_curr = ref->brk_curr;
    dut->mmap_cursor = ref->mmap_cursor;
    dut->region_count = ref->region_count;
    if (ref->region_count > 0U) {
        memcpy(dut->regions, ref->regions,
            ref->region_count * sizeof(dut->regions[0]));
    }
    dut->exit_reason = PPC32_EXIT_NONE;
}

/* Refresh the difftest snapshot after state-changing work on ref
 * (syscall dispatch or signal-frame delivery): free the old segments
 * and re-snapshot the post-change writable state. Returns 0, or 2 with
 * an INCONCLUSIVE report when the snapshot has a gap. */
static int difftest_refresh(ppc32_ctx_t *ctx, difftest_snap_t *snap,
    size_t *n)
{
    bool incomplete = false;

    difftest_snap_free(snap, *n);
    *n = difftest_snapshot(ctx, snap, DIFFTEST_SNAP_CAP, &incomplete);
    if (incomplete) {
        printf("DIFFTEST: INCONCLUSIVE (snapshot gap)\n");
        difftest_snap_free(snap, *n);
        return 2;
    }
    return 0;
}

/*
 * RC2 differential driver: the interp oracle (ref) and the dbt DUT share
 * one window/memory and run to the same syscall boundaries, where full
 * architectural state is compared with difftest_check. Each syscall is
 * dispatched ONCE (on ref; effects are shared memory) and the outcome
 * is synced into the DUT. Prints DIFFTEST: EQUAL/DIVERGENCE.
 */
static int run_difftest(ppc32_ctx_t *ctx)
{
    static ppc32_ctx_t ref;
    ppc32_elf_info_t info;
    uint32_t sp;
    int mismatches = 0;
    uint64_t bounds = 1000000ULL;

    if (guest_load(ctx, &info, &sp) != 0) {
        return 1;
    }
    emit_bridge_install(ctx);
    memset(&ref, 0, sizeof(ref));
    ref.guest_base = ctx->guest_base;
    ref.vm_ready = true;
    ref.profile = ctx->profile;
    ref.host_info = ctx->host_info;
    ref.nip = ctx->elf_entry;
    ref.gpr[PPC32_REG_SP] = sp;
    ref.exit_reason = PPC32_EXIT_NONE;
    /* RC5: startup metadata the syscall layer (procfs, sysroot) and the
     * allocator mirrors derive from the main ctx, not the engine loop.
     * Without these, /proc/self reads fail on the ref side and the DUT
     * inherits the same gap through sync (L5a id=b0 finding). */
    ref.guest_argc = ctx->guest_argc;
    ref.guest_argv = ctx->guest_argv;
    ref.host_envp = ctx->host_envp;
    ref.exec_path = ctx->exec_path;
    ref.sysroot = ctx->sysroot;
    ref.guest_pid = ctx->guest_pid;
    ref.trace_syscalls = ctx->trace_syscalls;
    if (ctx->auxv_bytes <= sizeof ref.auxv_data) {
        memcpy(ref.auxv_data, ctx->auxv_data, ctx->auxv_bytes);
        ref.auxv_bytes = ctx->auxv_bytes;
    }
    /* Prime the ref VM mirrors from the shared globals. */
    ref.brk_base = ctx->brk_base;
    ref.brk_curr = ctx->brk_curr;
    ref.mmap_cursor = ctx->mmap_cursor;
    ref.region_count = ctx->region_count;
    if (ctx->region_count > 0U) {
        memcpy(ref.regions, ctx->regions,
            ctx->region_count * sizeof(ref.regions[0]));
    }
    difftest_snap_t snap[DIFFTEST_SNAP_CAP];
    bool incomplete = false;
    size_t snap_n = difftest_snapshot(ctx, snap, DIFFTEST_SNAP_CAP,
        &incomplete);
    if (incomplete) {
        printf("DIFFTEST: INCONCLUSIVE (snapshot gap at load)\n");
        difftest_snap_free(snap, snap_n);
        return 2;
    }
    for (;;) {
        uint32_t stop_pc;

        if (bounds-- == 0ULL) {
            printf("DIFFTEST: INCONCLUSIVE (driver bound)\n");
            difftest_snap_free(snap, snap_n);
            return 2;
        }
        (void)ppc32_hostfault_run(&ref, run_interp_stop);
        /* Revert the oracle's segment writes so the DUT starts the
         * segment from the exact post-boundary state (see
         * difftest_snapshot). */
        difftest_restore(ctx, snap, snap_n);
        (void)ppc32_hostfault_run(ctx, run_dbt_stop);
        if (ref.exit_reason != ctx->exit_reason) {
            printf("DIFFTEST: DIVERGENCE stop-reason interp=%u dbt=%u\n",
                ref.exit_reason, ctx->exit_reason);
            difftest_snap_free(snap, snap_n);
            return 1;
        }
        stop_pc = ref.nip;
        difftest_check(&ref, ctx, stop_pc, &mismatches);
        if (mismatches != 0) {
            printf("DIFFTEST: DIVERGENCE mismatches=%d\n", mismatches);
            difftest_snap_free(snap, snap_n);
            return 1;
        }
        if (ref.exit_reason == PPC32_EXIT_SYSCALL) {
            uint32_t nr = ref.gpr[0];

            if (nr != ctx->gpr[0]) {
                printf("DIFFTEST: DIVERGENCE syscall-nr interp=%u dbt=%u\n",
                    nr, ctx->gpr[0]);
                difftest_snap_free(snap, snap_n);
                return 1;
            }
            if (ppc32_syscall_is_exit(nr)) {
                int rst;

                ppc32_syscall(&ref);
                rst = (int)(ref.exit_arg & 0xFFU);
                printf("DIFFTEST: EQUAL exit=%d\n", rst);
                difftest_snap_free(snap, snap_n);
                return rst;
            }
            ppc32_syscall(&ref);
            difftest_sync_dut(ctx, &ref);
            /* Dispatch can reshape memory (brk/mmap/mprotect): refresh
             * the snapshot so the next restore reverts the oracle's
             * next-segment writes against the true post-dispatch state. */
            {
                int rc = difftest_refresh(ctx, snap, &snap_n);

                if (rc != 0) {
                    return rc;
                }
            }
            ref.exit_reason = PPC32_EXIT_NONE;
            continue;
        }
        if (ref.exit_reason == PPC32_EXIT_FAULT ||
            ref.exit_reason == PPC32_EXIT_TRAP) {
            /* RC4: deliver once on ref (the frame lives in shared
             * memory), sync the DUT onto the handler entry, and refresh
             * the snapshot so the frame survives the next restore. */
            if (!deliver_sync(&ref)) {
                printf("DIFFTEST: DIVERGENCE fatal stop %u at nip 0x%08X\n",
                    ref.exit_reason, ref.nip);
                difftest_snap_free(snap, snap_n);
                return 1;
            }
            difftest_sync_dut(ctx, &ref);
            {
                int rc = difftest_refresh(ctx, snap, &snap_n);

                if (rc != 0) {
                    return rc;
                }
            }
            ref.exit_reason = PPC32_EXIT_NONE;
            continue;
        }
        printf("DIFFTEST: DIVERGENCE stop-reason %u at nip 0x%08X\n",
            ref.exit_reason, ref.nip);
        difftest_snap_free(snap, snap_n);
        return 1;
    }
}
