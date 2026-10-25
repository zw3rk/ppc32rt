/*
 * src/os/hostfault.h — host SIGSEGV/SIGBUS translation for engine memory
 * accesses.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The interpreter checks the low guard in software but trusts the host
 * page protections for the rest; DBT-emitted loads/stores check nothing
 * at all. A guest access that violates its page permissions (write to
 * an RX page, any touch of a PROT_NONE guard) therefore raises a host
 * fault inside engine code. This layer translates a fault whose data
 * address lies in the guest window [G, G + 4 GiB) into a guest FAULT
 * exit (delivered as SIGSEGV); anything else chains to the previous
 * disposition so translator bugs still crash loudly.
 */

#ifndef PPC32_HOSTFAULT_H
#define PPC32_HOSTFAULT_H

#include "ppc32rt.h"

/* Install the process-wide handler once (main startup, before engines
 * run). Safe to call once; further calls are no-ops. */
void ppc32_hostfault_install(void);

/* Like setjmp: may return twice (0 when the run completes, 1 on
 * revival), so callers must preserve live state across the call. The
 * attribute enforces that; without it the compiler keeps caller-saved
 * registers across what it believes is a single return. */
#if defined(__GNUC__)
#define PPC32_RETURNS_TWICE __attribute__((returns_twice))
#else
#define PPC32_RETURNS_TWICE
#endif

/* Engine-run callback: runs the engine (one segment, or loop-until-stop
 * for difftest) inside the checkpoint frame. */
typedef void (*ppc32_hostfault_fn_t)(ppc32_ctx_t *ctx);

/* Runs `run(ctx)` under the host-fault guard. Returns 0 when the run
 * completes (guard disarmed); returns 1 when reviving from a translated
 * host fault (fault_addr/exit_reason/reservation already recorded on
 * ctx; the caller must dispatch, not run). The callee frame must stay
 * ancestral to the fault: the engine runs inside this call, never
 * after it returns (a returned checkpoint revives into a dead frame). */
int ppc32_hostfault_run(ppc32_ctx_t *ctx, ppc32_hostfault_fn_t run)
    PPC32_RETURNS_TWICE;

/* Disarm after a clean engine run. */
void ppc32_hostfault_leave(void);

#endif /* PPC32_HOSTFAULT_H */
