/*
 * tests/test_p2_libc.c — static-libc PPC32 Phase 2 fixture source (lane L2d)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Normal-libc PPC32 guest exercising the Phase 2 static-libc syscall
 * surface (docs/lanes/phase-2.md, card L2d): hello/printf, malloc/free,
 * qsort, and file I/O. Built for the target with
 *   powerpc-linux-gnu-gcc -static -O2 tests/test_p2_libc.c \
 *     -o _build/test_p2_libc
 * and run under qemu-ppc (-cpu 750 and -cpu e500v2, oracle) and under
 * ppc32rt --interp / --dbt at RC2. Prints "PASS" and exits 0 when every
 * check holds, else "FAIL <site>" and exits 1 (the coordinator diffs
 * guest stdout across oracle and both engines).
 *
 * Host check (no powerpc toolchain on macOS): the source is portable C,
 * so `cc -fsyntax-only` plus a native build+run must also print PASS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int check_printf(void)
{
    int n;

    n = printf("hello p2 libc\n");
    if (n <= 0) {
        return 1;
    }
    n = printf("printf: %d %s %x\n", 42, "ok", 255U);
    if (n <= 0) {
        return 2;
    }
    return 0;
}

static int check_malloc(void)
{
    size_t i;
    size_t n = 1024U;
    unsigned char *p = (unsigned char *)malloc(n);

    if (p == NULL) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        p[i] = (unsigned char)(i & 0xFFU);
    }
    for (i = 0; i < n; i++) {
        if (p[i] != (unsigned char)(i & 0xFFU)) {
            free(p);
            return 2;
        }
    }
    free(p);
    p = (unsigned char *)calloc(16U, 4U);
    if (p == NULL) {
        return 3;
    }
    for (i = 0; i < 64U; i++) {
        if (p[i] != 0U) {
            free(p);
            return 4;
        }
    }
    free(p);
    return 0;
}

static int check_qsort(void)
{
    int v[] = { 9, -3, 17, 0, 42, -100, 7, 7 };
    int want[] = { -100, -3, 0, 7, 7, 9, 17, 42 };
    size_t n = sizeof(v) / sizeof(v[0]);
    size_t i;

    qsort(v, n, sizeof(v[0]), cmp_int);
    for (i = 0; i < n; i++) {
        if (v[i] != want[i]) {
            return 1;
        }
    }
    return 0;
}

static int check_file_io(void)
{
    static const char msg[] = "p2 file io\n";
    char buf[32];
    FILE *f;
    size_t got;

    f = fopen("test_p2_libc.tmp", "w");
    if (f == NULL) {
        return 1;
    }
    if (fputs(msg, f) < 0) {
        fclose(f);
        return 2;
    }
    if (fclose(f) != 0) {
        return 3;
    }
    f = fopen("test_p2_libc.tmp", "r");
    if (f == NULL) {
        return 4;
    }
    memset(buf, 0, sizeof(buf));
    got = fread(buf, 1U, sizeof(buf) - 1U, f);
    if (fclose(f) != 0) {
        return 5;
    }
    if (got != strlen(msg) || strcmp(buf, msg) != 0) {
        return 6;
    }
    if (remove("test_p2_libc.tmp") != 0) {
        return 7;
    }
    return 0;
}

int main(void)
{
    int site;

    site = check_printf();
    if (site != 0) {
        printf("FAIL printf %d\n", site);
        return 1;
    }
    site = check_malloc();
    if (site != 0) {
        printf("FAIL malloc %d\n", site);
        return 1;
    }
    site = check_qsort();
    if (site != 0) {
        printf("FAIL qsort %d\n", site);
        return 1;
    }
    site = check_file_io();
    if (site != 0) {
        printf("FAIL fileio %d\n", site);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
