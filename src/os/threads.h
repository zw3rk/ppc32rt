/*
 * src/os/threads.h — PPC32 multithreading primitives (Phase 4, lane L4b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers the L4b card of docs/lanes/phase-4.md: clone(2) with
 * CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_CHILD_CLEARTID (r2 TLS
 * pointer per experiments/E06), futex WAIT/WAKE (+PRIVATE variants),
 * TLS register plumbing, set_tid_address, LL/SC reservation
 * invalidation across helpers/signal delivery/thread switches (SPEC
 * 2.2, E06), and D19 table locking for CLONE_VM mapping changes.
 *
 * Return convention: every entry point returns a kernel-style long
 * (bytes moved / child TID / woken count on success, negative errno
 * on failure). The syscall dispatcher (frozen src/os/syscalls.c,
 * coordinator-owned) maps that onto the PPC convention from SPEC 2.3
 * (success: CR0.SO=0, r3=ret; error: CR0.SO=1, r3=-ret).
 *
 * This header has no platform dependencies beyond ppc32_ctx_t: the
 * host thread handle stays private to threads.c.
 */

#ifndef PPC32RT_OS_THREADS_H
#define PPC32RT_OS_THREADS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "ppc32rt.h"

/* ---- clone(2) flags: Linux arch-generic ABI (linux/sched.h) ---- */
#define PPC32_CLONE_VM             0x00000100U
#define PPC32_CLONE_FS             0x00000200U
#define PPC32_CLONE_FILES          0x00000400U
#define PPC32_CLONE_SIGHAND        0x00000800U
#define PPC32_CLONE_PTRACE         0x00002000U
#define PPC32_CLONE_VFORK          0x00004000U
#define PPC32_CLONE_PARENT         0x00008000U
#define PPC32_CLONE_THREAD         0x00010000U
#define PPC32_CLONE_SYSVSEM        0x00040000U
#define PPC32_CLONE_SETTLS         0x00080000U
#define PPC32_CLONE_PARENT_SETTID  0x00100000U
#define PPC32_CLONE_CHILD_CLEARTID 0x00200000U
#define PPC32_CLONE_UNTRACED       0x00800000U
#define PPC32_CLONE_CHILD_SETTID   0x01000000U
#define PPC32_CLONE_NEWCGROUP      0x02000000U
#define PPC32_CLONE_NEWUTS         0x04000000U
#define PPC32_CLONE_NEWIPC         0x08000000U
#define PPC32_CLONE_NEWUSER        0x10000000U
#define PPC32_CLONE_NEWPID         0x20000000U
#define PPC32_CLONE_NEWNET         0x40000000U
#define PPC32_CLONE_IO             0x80000000U
#define PPC32_CLONE_CSIGNAL        0x000000FFU

/* ---- futex(2) ops used by NPTL (linux/futex.h, arch-generic) ---- */
#define PPC32_FUTEX_WAIT          0U
#define PPC32_FUTEX_WAKE          1U
#define PPC32_FUTEX_REQUEUE       3U
#define PPC32_FUTEX_CMP_REQUEUE   4U
#define PPC32_FUTEX_PRIVATE_FLAG  128U
#define PPC32_FUTEX_CLOCK_REALTIME 256U
#define PPC32_FUTEX_CMD_MASK      (~(128U | 256U))

/* Thread-table capacity: fixed, no heap growth, no VLA. */
#define PPC32_MAX_THREADS 32U

/* Child execution hook: runs on a fresh host thread with the cloned
 * context. The engine (interp/dbt run-loop, owned by other lanes)
 * supplies this; threads.c never depends on the engines. When run is
 * NULL the child context is created and registered but no host thread
 * is started, so the caller can drive it synchronously. */
typedef void (*ppc32_thread_run_t)(ppc32_ctx_t *child, void *opaque);

/* Register the initial (main) thread: records host/getpid tids, takes
 * table slot 0. Call once before the first clone. Returns 0 or -errno. */
long ppc32_thread_init_main(ppc32_ctx_t *ctx);

/* Clone the calling thread (PPC clone nr 120 arg order: flags, stack,
 * parent_tid, tls, child_tid). On success returns the child guest TID
 * (> 0); on failure a negative errno. The child inherits a snapshot of
 * the parent's register/file state (see threads.c for the field list),
 * gpr[1] = stack_va when nonzero, gpr[2] = tls_va under CLONE_SETTLS,
 * gpr[3] = 0, and nip advanced past the trapping sc. Clones without
 * CLONE_VM take -ENOSYS (process path, lane L4c owns fork/vfork). */
long ppc32_clone(ppc32_ctx_t *parent, uint32_t flags, uint32_t stack_va,
    uint32_t parent_tid_va, uint32_t tls_va, uint32_t child_tid_va,
    ppc32_thread_run_t run, void *opaque, ppc32_ctx_t **out_child);

/* Reap a finished child thread (pthread_join + table release). The
 * child context is freed by the exiting thread itself; after a
 * successful join the guest TID is no longer valid. */
long ppc32_thread_join(uint32_t guest_tid);

/* Child-side teardown: clears the CLONE_CHILD_CLEARTID word (BE zero
 * store) and wakes one waiter, releases the table slot, and frees the
 * child context. Runs at the end of the host-thread wrapper and after
 * run() returns, so engine code never calls it directly. */
void ppc32_thread_exit(ppc32_ctx_t *child);

/* Futex op on a guest word (nr 221 arg order: uaddr, op, val, timeout,
 * uaddr2, val3). WAIT/CMP_REQUEUE compare against the byte-swapped
 * register value because guest memory is big-endian while the host
 * futex compares raw little-endian words. WAKE/REQUEUE counts pass
 * through. PI ops and FUTEX_FD take -ENOSYS. */
long ppc32_futex(ppc32_ctx_t *ctx, uint32_t uaddr, uint32_t op,
    uint32_t val, uint32_t timeout_va, uint32_t uaddr2, uint32_t val3);

/* Non-Linux futex emulation (src/os/futex_ulock.c, Darwin __ulock):
 * same arg shape as the host futex call, guest-visible Linux errno
 * negatives. Used by threads.c where futex(2) is unavailable. */
long ppc32_futex_emul(int32_t *uaddr, uint32_t op, int32_t val,
    const struct timespec *timeout, int32_t *uaddr2, int32_t val3);

/* set_tid_address (nr 232): records clear_child_tid, returns the
 * caller's TID. The robust-list pointer lives in the ctx fields but is
 * only written by set_robust_list (not in L4b scope). */
long ppc32_set_tid_address(ppc32_ctx_t *ctx, uint32_t tidptr_va);

/* TLS plumbing (E06): the PPC32 thread pointer is r2 (PPC64 r13 does
 * not apply; there is no set_thread_area: only clone(CLONE_SETTLS)
 * writes it). Set bumps the reservation epoch (register write). */
void ppc32_tls_set(ppc32_ctx_t *ctx, uint32_t tls_va);
uint32_t ppc32_tls_get(const ppc32_ctx_t *ctx);

/* Reservation invalidation (SPEC 2.2, E06): spurious stwcx. failure is
 * always legal, so every helper entry, signal delivery, and thread
 * switch clears res_valid and bumps the epoch. */
void ppc32_reservation_invalidate(ppc32_ctx_t *ctx);
void ppc32_thread_switch_invalidate(ppc32_ctx_t *prev, ppc32_ctx_t *next);

/* Live-thread count (main thread included). Useful to the L4c test
 * fixture; 0 means the table was never initialised. */
uint32_t ppc32_thread_count(void);

#endif /* PPC32RT_OS_THREADS_H */
