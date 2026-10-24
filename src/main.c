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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ppc32rt.h"

extern char **environ;

#define PPC32RT_VERSION "0.0-phase0"

static void usage(FILE *out)
{
    static const char *msg =
        "ppc32rt — 32-bit PowerPC (750 / e500v2) Linux user-mode translator\n"
        "\n"
        "Usage:\n"
        "  ppc32rt [--interp | --dbt] [--difftest] [--trace]\n"
        "          [--profile classic|spe] -- PATH [ARGV0...]\n"
        "  ppc32rt --help\n"
        "  ppc32rt --version\n"
        "\n"
        "Environment: PPC32RT_ENGINE, PPC32RT_PROFILE\n";
    fputs(msg, out);
}

static int parse_engine(const char *s, int *out)
{
    if (strcmp(s, "interp") == 0) {
        *out = PPC32_ENGINE_INTERP;
        return 0;
    }
    if (strcmp(s, "dbt") == 0) {
        *out = PPC32_ENGINE_DBT;
        return 0;
    }
    return -1;
}

static int parse_profile(const char *s, int *out)
{
    if (strcmp(s, "classic") == 0) {
        *out = PPC32_PROFILE_CLASSIC;
        return 0;
    }
    if (strcmp(s, "spe") == 0) {
        *out = PPC32_PROFILE_SPE;
        return 0;
    }
    return -1;
}

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
        if (strcmp(argv[i], "--trace") == 0) {
            ctx->trace_syscalls = true;
            i++;
            continue;
        }
        if (i + 1 >= argc) {
            return -1;
        }
        if (strcmp(argv[i], "--profile") == 0) {
            if (parse_profile(argv[i + 1], &ctx->profile) != 0) {
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
            if (parse_engine(s, &ctx->engine) != 0) {
                fprintf(stderr, "ppc32rt: bad PPC32RT_ENGINE=%s\n", s);
                exit(2);
            }
        }
    }
    if (ctx->profile != PPC32_PROFILE_CLASSIC &&
        ctx->profile != PPC32_PROFILE_SPE) {
        s = getenv("PPC32RT_PROFILE");
        if (s != NULL) {
            if (parse_profile(s, &ctx->profile) != 0) {
                fprintf(stderr, "ppc32rt: bad PPC32RT_PROFILE=%s\n", s);
                exit(2);
            }
        }
    }
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
    ctx.exec_path = argv[path_idx];
    ctx.guest_argc = argc - path_idx;
    ctx.guest_argv = &argv[path_idx];
    ctx.host_envp = environ;

    /* Engines arrive in Phase 1 (interp) and Phase 2 (dbt). */
    if (getenv("PPC32RT_ENGINE") == NULL && ctx.engine < 0) {
        ctx.engine = PPC32_ENGINE_INTERP; /* default oracle */
    }
    fprintf(stderr, "ppc32rt: engine %s not implemented in Phase 0\n",
            ctx.engine == PPC32_ENGINE_DBT ? "dbt" : "interp");
    return 2;
}
