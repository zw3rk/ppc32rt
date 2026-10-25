/*
 * tests/test_p5_dyn.c — dynamic-libc PPC32 Phase 5 fixture (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dynamic companion to the static tests/test_p2_libc.c fixture: exercises
 * the PT_INTERP path (Debian powerpc ld.so.1), shared-library PLT calls
 * (printf/qsort out of libc.so.6), dlopen/dlsym of the companion
 * tests/test_p5_dynlib.c shared object, main-thread __thread TLS
 * (including cross-DSO access into the companion), and the argv/envp/auxv
 * contract (getauxval(AT_ENTRY) is the app entry, getauxval(AT_BASE) is the
 * nonzero interpreter base).
 *
 * Target build (Debian powerpc cross sysroot, see docs/lanes/phase-5.md;
 * -no-pie keeps the app entry at its link-time address so the AT_ENTRY
 * self-check is exact):
 *   powerpc-linux-gnu-gcc -O2 -fPIC -shared \
 *       tests/test_p5_dynlib.c -o _build/test_p5_dynlib.so
 *   powerpc-linux-gnu-gcc -O2 -no-pie tests/test_p5_dyn.c \
 *       -o _build/test_p5_dyn -ldl
 *
 * Oracle / translator runs (from _build):
 *   qemu-ppc -cpu 750 -L /usr/powerpc-linux-gnu ./test_p5_dyn
 *   qemu-ppc -cpu e500v2 -L /usr/powerpc-linux-gnu ./test_p5_dyn
 *   ppc32rt --interp -- ./test_p5_dyn   (with PPC32RT_SYSROOT honored)
 *   ppc32rt --dbt -- ./test_p5_dyn      (with PPC32RT_SYSROOT honored)
 * All four print identical stdout and exit 0; RC5 byte-diffs them. Note:
 * AT_BASE arrives with lane L5a's stack32 auxv hunk, so the auxv check only
 * passes once both Phase 5 lanes have merged.
 *
 * Host check (no powerpc toolchain on macOS): the source is portable C, so
 *   cc -O2 -fPIC -shared tests/test_p5_dynlib.c -o /tmp/test_p5_dynlib.so
 *   cc -O2 -no-pie tests/test_p5_dyn.c -o /tmp/test_p5_dyn   (Linux host;
 *     macOS lacks getauxval and always builds PIE, so the auxv self-check
 *     is compiled out there) plus a native run must print PASS.
 */

#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <elf.h>
#include <sys/auxv.h>

extern char _start[];
#endif

static __thread int tls_counter = 0;

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    if (x < y) {
        return -1;
    }
    if (x > y) {
        return 1;
    }
    return 0;
}

static int check_shared_calls(void)
{
    int v[] = { 9, -3, 17, 0, 42, -100, 7, 7 };
    int want[] = { -100, -3, 0, 7, 7, 9, 17, 42 };
    size_t n = sizeof(v) / sizeof(v[0]);
    size_t i;
    int count;

    /* printf/qsort resolve through the PLT into shared libc.so.6. */
    count = printf("p5 dyn printf: %d %s %x\n", 42, "ok", 255U);
    if (count <= 0) {
        return 1;
    }
    qsort(v, n, sizeof(v[0]), cmp_int);
    for (i = 0; i < n; i++) {
        if (v[i] != want[i]) {
            return 2;
        }
    }
    printf("p5 dyn qsort ok\n");
    return 0;
}

/* Companion path: "<argv0 dir>/test_p5_dynlib.so", else a cwd fallback. */
static void lib_path_for(const char *argv0, char *out, size_t out_n)
{
    size_t len = strlen(argv0);
    size_t dir = 0U;
    size_t j;

    for (j = 0U; j < len; j++) {
        if (argv0[j] == '/') {
            dir = j + 1U;
        }
    }
    if (dir > 0U) {
        (void)snprintf(out, out_n, "%.*stest_p5_dynlib.so", (int)dir,
            argv0);
    } else {
        (void)snprintf(out, out_n, "%s", "./test_p5_dynlib.so");
    }
}

static int check_dlopen(const char *argv0)
{
    char path[1024];
    void *h;
    int (*add_fn)(int, int);
    int *valp;
    void (*tls_set_fn)(int);
    int (*tls_get_fn)(void);

    *(void **)(&add_fn) = NULL;
    *(void **)(&tls_set_fn) = NULL;
    *(void **)(&tls_get_fn) = NULL;

    lib_path_for(argv0, path, sizeof(path));
    h = dlopen(path, RTLD_NOW);
    if (h == NULL) {
        h = dlopen("./test_p5_dynlib.so", RTLD_NOW);
    }
    if (h == NULL) {
        /* Bare-soname search (LD_LIBRARY_PATH, no getcwd needed). */
        h = dlopen("test_p5_dynlib.so", RTLD_NOW);
    }
    if (h == NULL) {
        return 1;
    }
    *(void **)(&add_fn) = dlsym(h, "p5_dyn_add");
    valp = (int *)dlsym(h, "p5_dyn_value");
    *(void **)(&tls_set_fn) = dlsym(h, "p5_dyn_tls_set");
    *(void **)(&tls_get_fn) = dlsym(h, "p5_dyn_tls_get");
    if (add_fn == NULL || valp == NULL || tls_set_fn == NULL ||
        tls_get_fn == NULL) {
        (void)dlclose(h);
        return 2;
    }
    if (add_fn(19, 23) != 42 || *valp != 1234567) {
        (void)dlclose(h);
        return 3;
    }
    /* Cross-DSO TLS: write the companion's __thread cell, read it back. */
    tls_set_fn(777);
    if (tls_get_fn() != 777) {
        (void)dlclose(h);
        return 4;
    }
    (void)dlclose(h);
    printf("p5 dyn dlopen ok\n");
    return 0;
}

static int check_tls(void)
{
    tls_counter = 1234;
    if (tls_counter != 1234) {
        return 1;
    }
    printf("p5 dyn tls ok\n");
    return 0;
}

static int check_args_env(int argc, char *argv[], char *envp[])
{
    if (argc < 1 || argv == NULL || argv[0] == NULL) {
        return 1;
    }
    if (envp == NULL || envp[0] == NULL) {
        return 2;
    }
    return 0;
}

#if defined(__linux__)
static int check_auxv(void)
{
    unsigned long entry;
    unsigned long base;
    unsigned long hwcap;

    entry = getauxval(AT_ENTRY);
    base = getauxval(AT_BASE);
    hwcap = getauxval(AT_HWCAP);
    if (entry == 0UL || entry != (unsigned long)_start) {
        return 1;
    }
    /* Dynamic build: the interpreter base is nonzero (0 when static). */
    if (base == 0UL) {
        return 2;
    }
    if (hwcap == 0UL) {
        return 3;
    }
    printf("p5 dyn auxv ok\n");
    return 0;
}
#else
static int check_auxv(void)
{
    /* No getauxval off Linux (macOS host check): nothing to verify. */
    printf("p5 dyn auxv ok\n");
    return 0;
}
#endif

int main(int argc, char *argv[], char *envp[])
{
    int site;

    site = check_args_env(argc, argv, envp);
    if (site != 0) {
        printf("FAIL args %d\n", site);
        return 1;
    }
    site = check_shared_calls();
    if (site != 0) {
        printf("FAIL shlib %d\n", site);
        return 1;
    }
    site = check_dlopen(argv[0]);
    if (site != 0) {
        const char *err = dlerror();

        printf("FAIL dlopen %d: %s\n", site,
            err != NULL ? err : "?");
        return 1;
    }
    site = check_tls();
    if (site != 0) {
        printf("FAIL tls %d\n", site);
        return 1;
    }
    site = check_auxv();
    if (site != 0) {
        printf("FAIL auxv %d\n", site);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
