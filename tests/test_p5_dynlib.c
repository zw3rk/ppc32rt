/*
 * tests/test_p5_dynlib.c — companion shared object for the Phase 5 dynamic
 * fixture (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * One exported function plus one exported variable, exercised through
 * dlopen/dlsym by tests/test_p5_dyn.c, plus a cross-DSO __thread TLS cell
 * accessed through setter/getter helpers.
 *
 * Target build (Debian powerpc cross sysroot, see docs/lanes/phase-5.md):
 *   powerpc-linux-gnu-gcc -O2 -fPIC -shared \
 *       tests/test_p5_dynlib.c -o _build/test_p5_dynlib.so
 */

int p5_dyn_value = 1234567;

static __thread int p5_dyn_tls_cell = 0;

int p5_dyn_add(int a, int b)
{
    return a + b;
}

void p5_dyn_tls_set(int v)
{
    p5_dyn_tls_cell = v;
}

int p5_dyn_tls_get(void)
{
    return p5_dyn_tls_cell;
}
