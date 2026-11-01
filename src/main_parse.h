/*
 * src/main_parse.h — CLI value parsers for main.c.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Strict parsers for --engine/--profile/--window/--image-fd values
 * and the AT_EXECFD presence probe (HOST-CONTRACT §3.1). Split from
 * main.c under the file-size discipline; behavior unchanged.
 */

#ifndef PPC32_MAIN_PARSE_H
#define PPC32_MAIN_PARSE_H

#include <stdint.h>

int ppc32_parse_engine(const char *s, int *out);
int ppc32_parse_profile(const char *s, int *out);

/* Strict unsigned value parse (base 0 for --window, base 10 for
 * --image-fd): 0 ok, -1 on empty/negative/junk/overflow. */
int ppc32_parse_u64(const char *s, int base, uint64_t *out);

/* AT_EXECFD presence probe: errno-checked getauxval, so a valid fd 0
 * (stdin closed before execve) counts. Off Linux there is no auxv to
 * read; -1 means "absent". */
int ppc32_auxv_exec_fd(void);

#endif /* PPC32_MAIN_PARSE_H */
