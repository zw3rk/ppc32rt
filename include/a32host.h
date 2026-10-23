/*
 * include/a32host.h — Versioned host capability handshake ABI (A32H_ABI 1.0 / 1.1)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared header between Class-A 32-bit translators (`a32rt`, `i686rt`,
 * `mips32rt`, `ppc32rt`, `sparc32rt`) and optional host providers such as
 * `hyper-linux` (`/dev/a32host`) or a Linux kernel module.
 *
 * Versioning rule:
 *   - `A32H_ABI_MAJOR` (1) and `sizeof(a32h_info_t) == 256` with `A32H_GET_INFO`
 *     (`0x81006101UL`) are frozen across all 1.x minor revisions.
 *   - `A32H_ABI_MINOR` (0) is the minimum accepted wire-layout minor version;
 *     consumers accept any `info.abi_major == A32H_ABI_MAJOR` (regardless of
 *     whether `info.abi_minor` is 0 or >= 1) and test individual capability
 *     bits in `info.caps`.
 *   - `A32H_ABI_MINOR_TSO` (1) introduces `A32H_CAP_HW_TSO` (bit 9). A host
 *     provider may set `A32H_CAP_HW_TSO` only when hardware TSO is active on
 *     the initial vCPU and preserved across all thread/fork/exec vCPUs.
 *   - When syncing this header into `../a32rt/include/a32host.h`,
 *     `../i686rt/include/a32host.h`, and `../hyper-linux/src/a32host.h`,
 *     update all copies together so `make -C ../a32rt check-headers` passes.
 */

#ifndef A32HOST_H
#define A32HOST_H

#include <stdint.h>

#define A32H_ABI_MAJOR     1U
#define A32H_ABI_MINOR     0U
#define A32H_ABI_MINOR_TSO 1U

#define A32H_DEV_PATH "/dev/a32host"

/*
 * Capability flags advertised in `a32h_info_t.caps`.
 */
#define A32H_CAP_PAGE4K            (1ULL << 0) /* mmap/mprotect granularity is 4 KiB */
#define A32H_CAP_WX_ENFORCED       (1ULL << 1) /* W^X enforced; host toggles on fault (hl) or denies */
#define A32H_CAP_ICACHE_TRAP_IALLU (1ULL << 2) /* one trapped IC op suffices to invalidate all */
#define A32H_CAP_LOW4G_FREE        (1ULL << 3) /* [mmap_min_addr, 4G) guaranteed free -> G = 0 */
#define A32H_CAP_DIROFF32          (1ULL << 4) /* getdents64/lseek dir cookies fit in 31 bits */
#define A32H_CAP_AOT_SOCKET        (1ULL << 5) /* aot_socket valid */
#define A32H_CAP_COMPAT_IOCTL      (1ULL << 6) /* A32H_COMPAT_IOCTL supported */
#define A32H_CAP_ROBUST32          (1ULL << 7) /* A32H_SET_ROBUST_LIST32 supported */
#define A32H_CAP_SET_PROC          (1ULL << 8) /* A32H_SET_PROC supported */
#define A32H_CAP_HW_TSO            (1ULL << 9) /* ACTLR_EL1.EnTSO hardware TSO active on all vCPUs (ABI 1.1) */

/*
 * Linux-compatible `_IOR('a', 0x01, struct a32h_info)` encoding:
 *   dir  = 2 (read, _IOC_READ) << 30
 *   size = 256 (sizeof(a32h_info_t)) << 16
 *   type = 'a' (0x61) << 8
 *   nr   = 0x01
 */
#define A32H_GET_INFO 0x81006101UL

typedef struct a32h_info {
    uint16_t abi_major;        /* A32H_ABI_MAJOR (1) */
    uint16_t abi_minor;        /* A32H_ABI_MINOR (0 or 1) */
    uint32_t flags;            /* reserved, 0 */
    uint64_t caps;             /* A32H_CAP_* bitmask */
    uint64_t window_hint;      /* preferred G (e.g. 0x100000000ULL), 0 = none */
    uint32_t page_size;        /* guaranteed mmap granularity (4096) */
    uint32_t _pad;             /* reserved, 0 */
    char     aot_socket[108];  /* AF_UNIX path, "" = none */
    uint8_t  _reserved[116];   /* pad total size to 256 bytes */
} a32h_info_t;

_Static_assert(sizeof(a32h_info_t) == 256, "a32h_info_t must be exactly 256 bytes");

#endif /* A32HOST_H */
