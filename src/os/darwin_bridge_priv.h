/*
 * src/os/darwin_bridge_priv.h — internal bridge plumbing (not public)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared between src/os/darwin_host_bridge.c (trap core), -vm.c (VMA
 * mirrors + SYNC_VM_PROT), and -run.c (boot + lifecycles). Never
 * included outside src/os/.
 */

#ifndef PPC32RT_OS_DARWIN_BRIDGE_PRIV_H
#define PPC32RT_OS_DARWIN_BRIDGE_PRIV_H

#include <stddef.h>
#include <stdint.h>

#include "os/darwin_host_bridge.h"

/* Bridge-wide serialization (bridge.c). */
void bridge_lock(void);
void bridge_unlock(void);

/* One engine segment (bridge.c). The bridge mutex is taken inside. */
void bridge_run_stop(ppc32_ctx_t *ctx, int engine);

/* Apply one trap reply (bridge.c): 0 EXIT_PROCESS, 1 EXIT_THREAD,
 * -1 resume, -2 fatal. Caller holds the bridge mutex. */
int bridge_handle_exit(ppc32_ctx_t *ctx, a32h_darwin_handler_fn fn,
    void *opaque, int *status_out);

/* Window + worker bookkeeping (bridge.c). take_window returns the
 * reserved base and clears the stored copy for teardown.
 * bridge_reset_workers assumes the caller already holds the bridge
 * mutex (it never locks: both callers bracket reset + mirrors_reset
 * under one critical section). */
void bridge_set_window(uint64_t base);
uint64_t bridge_take_window(void);
size_t bridge_live_workers(void);
void bridge_reset_workers(void);

/* Transport (bridge.c): cached /dev/a32host ioctl with EINTR retry,
 * and the fn-or-ioctl fan-out used by boot/trap paths. */
int bridge_host_ioctl(unsigned long req, void *arg);
int bridge_trap(a32h_darwin_handler_fn fn, void *opaque,
    unsigned long req, void *arg);

/* VMA mirrors + SYNC_VM_PROT (darwin_host_vm.c). register_vma records
 * one boot VMA (vm32 record + exec mark + host protect + mirror);
 * apply_sync handles SYNC_VM_PROT incl. the prot == 0 unmap path. */
void bridge_mirror_add(ppc32_ctx_t *ctx);
void bridge_mirror_remove(ppc32_ctx_t *ctx);
void bridge_mirrors_reset(void);
void bridge_register_vma(uint32_t va, uint32_t end, uint8_t prot,
    uint64_t window_base);
void bridge_apply_sync_prot(uint32_t va, uint32_t len, uint32_t prot);

#endif /* PPC32RT_OS_DARWIN_BRIDGE_PRIV_H */
