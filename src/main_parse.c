/*
 * src/main_parse.c — CLI value parsers for main.c.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from main.c under the file-size discipline; behavior unchanged.
 */

#include "main_parse.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef AT_EXECFD
#define AT_EXECFD 2 /* kernel auxv key (linux/auxvec.h) */
#endif
#endif

#include "ppc32rt.h"

int ppc32_parse_engine(const char *s, int *out)
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

int ppc32_parse_profile(const char *s, int *out)
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

int ppc32_parse_u64(const char *s, int base, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    errno = 0;
    if (s[0] == '\0' || strchr(s, '-') != NULL) {
        return -1;
    }
    v = strtoull(s, &end, base);
    if (errno == ERANGE || end == s || *end != '\0') {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

int ppc32_auxv_exec_fd(void)
{
#if defined(__linux__)
    unsigned long v;

    errno = 0;
    v = getauxval((unsigned long)AT_EXECFD);
    if (errno == 0 && v <= (unsigned long)INT_MAX) {
        return (int)v;
    }
#endif
    return -1;
}
