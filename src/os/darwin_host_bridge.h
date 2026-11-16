/*
 * src/os/darwin_host_bridge.h — G02 Darwin host bridge client (A32H_ABI 1.2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Client side of frozen include/a32host.h (A32H_ABI 1.2). ppc32rt stays
 * small: this bridge owns only CPU/memory/trap plumbing (reserve the 4
 * GiB window, register VMAs, run interp/dbt/difftest, pack the GPR/FPR/
 * VR snapshot, apply host reply actions). All Mach-O/dyld/BSD/Mach
 * policy lives in hl or in the in-process mock handler used by
 * tests/check_p32_darwin_g02.c.
 */

#ifndef PPC32RT_OS_DARWIN_HOST_BRIDGE_H
#define PPC32RT_OS_DARWIN_HOST_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "a32host.h"
#include "ppc32rt.h"

/* Next-minor reply bit: exit only the calling worker thread (reclaiming
 * its slot). Frozen include/a32host.h (ABI 1.2) reserves no EXIT_THREAD
 * reply bit, so it lives here until the header freeze lifts. */
#ifndef A32H_DACT_EXIT_THREAD
#define A32H_DACT_EXIT_THREAD (1U << 5)
#endif

/* CLI personality wiring (main.c): --personality <name> and
 * --darwin-boot, plus PPC32RT_PERSONALITY env. */
void ppc32_darwin_set_cli(const char *personality, bool darwin_boot);
bool ppc32_darwin_personality_active(void);

/* True for the two bridge personalities (explicit --personality value,
 * --personality=<value> form, or PPC32RT_PERSONALITY env). */
bool ppc32_darwin_is_bridge_personality(const char *p);

/* True for every --personality value main.c accepts (bridge pair plus
 * explicit "linux"); anything else is rejected with exit status 1. */
bool ppc32_darwin_personality_known(const char *p);

/* Scan argv for bridge intent, stopping at "--" or the first positional
 * path: --darwin-boot, --personality <bridge>, --personality=<bridge>,
 * or the env override. Never reads past argc. */
bool ppc32_darwin_cli_wants_bridge(int argc, char **argv,
    bool *out_darwin_boot);

/* True when fd's first 4 bytes are a 32-bit BE Mach-O (0xfeedface,
 * byte-swapped 0xcefaedfe) or FAT (0xcafebabe / 0xbebafeca) magic. */
bool ppc32_darwin_is_macho_fd(int fd);

/* Reserve the 4 GiB window G, handshake A32H_DARWIN_BOOT with fn,
 * register VMAs into vm32 + ctx regions, mix the AOT personality hash,
 * and park nip/sp/r3 at the boot entry state. With fn == NULL the
 * handshake runs over the real /dev/a32host transport. */
int ppc32_darwin_boot(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque);

/* Run the G02 loop on ctx until the handler replies EXIT_PROCESS.
 * engine is PPC32_ENGINE_INTERP or PPC32_ENGINE_DBT. Returns the
 * process exit status. */
int ppc32_darwin_run_loop(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, int engine);

/* Real-transport lifecycle (no in-process handler): negotiate
 * /dev/a32host (ABI major + DARWIN cap + window hint), boot the Mach-O
 * image hl provides at path, then run interp / dbt / lockstep
 * difftest. Returns the guest exit status (1 on transport failure). */
int ppc32_run_darwin_host(const char *path, int engine, bool difftest);

/* Full in-process lifecycle for host unit tests (no /dev/a32host):
 * boot via fn, then run interp / dbt / --difftest lockstep. Returns
 * the process exit status (0..255). */
int ppc32_run_darwin_with_handler(a32h_darwin_handler_fn fn, void *opaque,
    int engine, bool difftest);

/* Handler code patch for G02 SMC (test_a stub rewrite): bytes written
 * straight through the host mapping bypass the guest store path (and
 * the DBT SMC hook), so widen the covering host pages, copy, and
 * restore the recorded protections (A2 union, A1 exact). The caller
 * still replies FLUSH_ICACHE so translated blocks covering
 * [va, va+len) are dropped. Only for in-process handlers. */
int ppc32_darwin_patch_code(uint64_t window_base, uint32_t va,
    const void *src, size_t len, uint32_t restore_prot);

/* AOT cache isolation key: Linux ELF uses 0 as the personality hash;
 * Darwin mixes boot.aot_personality_hash. Never collides across
 * personalities for the same guest PC. */
uint64_t ppc32_darwin_cache_key(const ppc32_ctx_t *ctx);

/* Worker thread entry (pthread_create target for SPAWN_THREAD). */
void *ppc32_darwin_worker_entry(void *a);

#endif /* PPC32RT_OS_DARWIN_HOST_BRIDGE_H */
