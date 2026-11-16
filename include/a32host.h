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

#define A32H_ABI_MAJOR        1U
#define A32H_ABI_MINOR        0U
#define A32H_ABI_MINOR_TSO    1U
#define A32H_ABI_MINOR_DARWIN 2U

#define A32H_DEV_PATH "/dev/a32host"

/*
 * Capability flags advertised in `a32h_info_t.caps`.
 */
#define A32H_CAP_PAGE4K             (1ULL << 0)  /* mmap/mprotect granularity is 4 KiB */
#define A32H_CAP_WX_ENFORCED        (1ULL << 1)  /* W^X enforced; host toggles on fault (hl) or denies */
#define A32H_CAP_ICACHE_TRAP_IALLU  (1ULL << 2)  /* one trapped IC op suffices to invalidate all */
#define A32H_CAP_LOW4G_FREE         (1ULL << 3)  /* [mmap_min_addr, 4G) guaranteed free -> G = 0 */
#define A32H_CAP_DIROFF32           (1ULL << 4)  /* getdents64/lseek dir cookies fit in 31 bits */
#define A32H_CAP_AOT_SOCKET         (1ULL << 5)  /* aot_socket valid */
#define A32H_CAP_COMPAT_IOCTL       (1ULL << 6)  /* A32H_COMPAT_IOCTL supported */
#define A32H_CAP_ROBUST32           (1ULL << 7)  /* A32H_SET_ROBUST_LIST32 supported */
#define A32H_CAP_SET_PROC           (1ULL << 8)  /* A32H_SET_PROC supported */
#define A32H_CAP_HW_TSO             (1ULL << 9)  /* ACTLR_EL1.EnTSO hardware TSO active on all vCPUs (ABI 1.1) */
#define A32H_CAP_FIXADE             (1ULL << 10) /* MIPS unaligned load/store fixup (ABI 1.1) */
#define A32H_CAP_SOFT_TLB_256M      (1ULL << 11) /* 256 MiB Regime A2 Soft-TLB supported (ABI 1.1) */
#define A32H_CAP_DARWIN_PERSONALITY (1ULL << 12) /* Host-driven 32-bit Darwin/XNU personality (ABI 1.2) */

/*
 * Linux-compatible `_IOR('a', 0x01, struct a32h_info)` encoding:
 *   dir  = 2 (read, _IOC_READ) << 30
 *   size = 256 (sizeof(a32h_info_t)) << 16
 *   type = 'a' (0x61) << 8
 *   nr   = 0x01
 *
 * Companion `/dev/a32host` requests (ABI 1.0 / 1.1):
 *   A32H_COMPAT_IOCTL      = _IOWR('a', 0x02, a32h_compat_ioctl_t)  (24 bytes -> 0xc0186102UL)
 *   A32H_SET_ROBUST_LIST32 = _IOW('a',  0x03, a32h_robust_list32_t) (16 bytes -> 0x40106103UL)
 *   A32H_SET_PROC          = _IOW('a',  0x04, a32h_proc_t)          (64 bytes -> 0x40406104UL)
 */
#define A32H_GET_INFO          0x81006101UL
#define A32H_COMPAT_IOCTL      0xc0186102UL
#define A32H_SET_ROBUST_LIST32 0x40106103UL
#define A32H_SET_PROC          0x40406104UL

typedef struct a32h_compat_ioctl {
    int32_t  fd;        /* target guest fd */
    uint32_t cmd;       /* 32-bit guest ioctl command */
    uint64_t arg;       /* guest pointer (host VA G + wArg) or scalar */
    int64_t  result;    /* out: syscall return value or -errno */
} a32h_compat_ioctl_t;

_Static_assert(sizeof(a32h_compat_ioctl_t) == 24, "a32h_compat_ioctl_t must be 24 bytes");

typedef struct a32h_robust_list32 {
    uint64_t head_hva;  /* host VA (G + guest_head_u32) of 32-bit robust_list_head */
    uint32_t len;       /* guest len (12 for 32-bit futex_robust_list_head) */
    uint32_t _pad;      /* reserved, 0 */
} a32h_robust_list32_t;

_Static_assert(sizeof(a32h_robust_list32_t) == 16, "a32h_robust_list32_t must be 16 bytes");

typedef struct a32h_proc {
    uint64_t exe_path_ptr; /* host VA of NUL-terminated guest exe path (0 = unchanged) */
    uint64_t cmdline_ptr;  /* host VA of guest argv NUL-separated buffer (0 = unchanged) */
    uint32_t cmdline_len;  /* byte length of cmdline buffer */
    uint32_t pid;          /* optional guest pid override (0 = unchanged) */
    uint32_t tgid;         /* optional guest tgid override (0 = unchanged) */
    uint32_t ppid;         /* optional guest ppid override (0 = unchanged) */
    uint8_t  _reserved[28];/* pad total size to 64 bytes */
} a32h_proc_t;

_Static_assert(sizeof(a32h_proc_t) == 64, "a32h_proc_t must be 64 bytes");

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

/* --------------------------------------------------------------------------
 * A32H_ABI 1.2 — Narrow Cross-Repo 32-Bit Darwin/XNU Execution Contract (G02)
 *
 * Keeps Class-A translators (`a32rt`, `ppc32rt`) small by delegating Mach-O,
 * dyld, CommPage, BSD/Mach traps, stubs, frameworks, and UI to `hyper-linux`
 * (`hl`) or an in-process mock handler for standalone unit tests.
 *
 *   A32H_DARWIN_BOOT = _IOWR('a', 0x05, a32h_darwin_boot_t) (128 B -> 0xc0806105UL)
 *   A32H_DARWIN_TRAP = _IOWR('a', 0x06, a32h_darwin_trap_t) (128 B -> 0xc0806106UL)
 * -------------------------------------------------------------------------- */
#define A32H_DARWIN_BOOT 0xc0806105UL
#define A32H_DARWIN_TRAP 0xc0806106UL

#define A32H_ARCH_ARM32 1U /* CPU_TYPE_ARM (armv7 / armv7s LE) */
#define A32H_ARCH_PPC32 2U /* CPU_TYPE_POWERPC (7400 / 7450 G4 BE) */

/* Guest exit reasons reported by translator -> host */
#define A32H_DEXIT_NONE        0U
#define A32H_DEXIT_SVC_TRAP    1U /* ARM32 svc #imm / PPC32 sc */
#define A32H_DEXIT_FAULT       2U /* Page / protection / alignment fault */
#define A32H_DEXIT_BKPT        3U /* Breakpoint / Darwin __builtin_trap / PPC trap */
#define A32H_DEXIT_ILLEGAL     4U /* Undefined / illegal instruction */
#define A32H_DEXIT_THREAD_EXIT 5U /* Worker pthread exiting */

/* Fault access kind (`fault_kind`) */
#define A32H_DFAULT_READ  0U
#define A32H_DFAULT_WRITE 1U
#define A32H_DFAULT_EXEC  2U

/* Host reply action bitmask (`reply_action`) */
#define A32H_DACT_RESUME         0U
#define A32H_DACT_FLUSH_ICACHE   (1U << 0) /* Invalidate JIT/SMC in [flush_va, +flush_len) */
#define A32H_DACT_SYNC_VM_PROT   (1U << 1) /* Sync guest VMA prot in [prot_va, +prot_len) */
#define A32H_DACT_SPAWN_THREAD   (1U << 2) /* Spawn worker pthread at spawn_pc/sp/r0/tls */
#define A32H_DACT_EXIT_PROCESS   (1U << 3) /* Terminate guest with exit_status */
#define A32H_DACT_DELIVER_SIGNAL (1U << 4) /* Signal frame installed; reload FP/vec if dirty */
#define A32H_DACT_EXIT_THREAD    (1U << 5) /* Terminate this worker; process lives on */

/* `a32h_darwin_cpu_state_t.state_flags` */
#define A32H_DSTATE_FP_VALID  (1U << 0) /* Translator populated fpr[32] */
#define A32H_DSTATE_VEC_VALID (1U << 1) /* Translator populated vr[32] (PPC32 AltiVec) */
#define A32H_DSTATE_FP_DIRTY  (1U << 2) /* Host modified fpr[32] / fpscr */
#define A32H_DSTATE_VEC_DIRTY (1U << 3) /* Host modified vr[32] / vscr / vrsave */
#define A32H_DSTATE_NEED_FULL (1U << 4) /* Host needs full FP/vec snapshot, re-trap once */

/* Initial VMA record populated by `A32H_DARWIN_BOOT` (prot uses POSIX 1/2/4 R/W/X) */
typedef struct a32h_darwin_vmap {
    uint32_t va;
    uint32_t len;
    uint32_t prot;
    uint32_t flags;
} a32h_darwin_vmap_t;

_Static_assert(sizeof(a32h_darwin_vmap_t) == 16, "a32h_darwin_vmap_t must be 16 bytes");

typedef struct a32h_darwin_boot {
    uint32_t arch;                 /* in: A32H_ARCH_ARM32 or A32H_ARCH_PPC32 */
    uint32_t abi_minor;            /* in: A32H_ABI_MINOR_DARWIN (2) */
    uint64_t window_base;          /* in: translator guest window base G */
    uint64_t vmap_ptr;             /* in: host VA of a32h_darwin_vmap_t[vmap_cap] */
    uint32_t vmap_cap;             /* in: capacity of vmap_ptr array */
    uint32_t vmap_count;           /* out: number of initial VMAs written (or required) */
    uint32_t entry_pc;             /* out: initial 32-bit guest PC */
    uint32_t entry_sp;             /* out: initial 32-bit guest SP */
    uint32_t entry_r0;             /* out: initial r0 / arg0 (or main mach_header VA) */
    uint32_t entry_cpsr_or_msr;    /* out: initial CPSR (Thumb bit) or PPC MSR/CR */
    uint32_t commpage_va;          /* out: 0xFFFF4000 (ARM32) or 0xFFFF8000 (PPC32) */
    uint32_t commpage_size;        /* out: mapped CommPage byte length */
    uint64_t aot_personality_hash; /* out: mixed into AOT cache key for isolation */
    uint32_t initial_tid;          /* out: initial Darwin thread ID */
    uint32_t _pad0;                /* reserved, 0 */
    uint8_t  _reserved[56];        /* pad total size to 128 bytes */
} a32h_darwin_boot_t;

_Static_assert(sizeof(a32h_darwin_boot_t) == 128, "a32h_darwin_boot_t must be 128 bytes");

typedef struct __attribute__((aligned(16))) a32h_darwin_cpu_state {
    uint32_t gpr[32];        /* 0x000: r0..r15 (ARM32) or r0..r31 (PPC32) */
    uint32_t pc;             /* 0x080: guest PC at trap/fault */
    uint32_t next_pc;        /* 0x084: next sequential PC (or Thumb flag) */
    uint32_t lr;             /* 0x088: PPC32 LR (mirrored in gpr[14] on ARM32) */
    uint32_t ctr;            /* 0x08c: PPC32 CTR */
    uint32_t cpsr_or_cr;     /* 0x090: ARM32 CPSR (incl. C/T) or PPC32 CR */
    uint32_t xer;            /* 0x094: PPC32 XER (SO/OV/CA) */
    uint32_t fpscr;          /* 0x098: guest FPSCR */
    uint32_t vrsave;         /* 0x09c: PPC32 SPR 256 (VRSAVE) */
    uint32_t vscr;           /* 0x0a0: PPC32 AltiVec VSCR */
    uint32_t tls_tp;         /* 0x0a4: ARM32 TPIDRURO or PPC32 thread-ID word */
    uint32_t state_flags;    /* 0x0a8: A32H_DSTATE_* bitmask */
    uint32_t _pad0;          /* 0x0ac: reserved, 0 */
    uint64_t fpr[32];        /* 0x0b0: ARM32 d0..d31 (q0..q15) or PPC32 f0..f31 */
    uint8_t  vr[32][16];     /* 0x1b0: PPC32 AltiVec v0..v31 (128-bit BE lanes) */
    uint8_t  _reserved[80];  /* 0x3b0..0x3ff: pad total size to 1024 bytes */
} a32h_darwin_cpu_state_t;

_Static_assert(sizeof(a32h_darwin_cpu_state_t) == 1024,
               "a32h_darwin_cpu_state_t must be 1024 bytes");

typedef struct a32h_darwin_trap {
    uint32_t arch;            /* in: A32H_ARCH_ARM32 or A32H_ARCH_PPC32 */
    uint32_t tid;             /* in: Darwin thread ID */
    uint32_t exit_reason;     /* in: A32H_DEXIT_* */
    uint32_t trap_imm;        /* in: immediate (e.g. 0x80/0x81 on ARM32, 0 on PPC32) */
    uint32_t fault_va;        /* in: 32-bit guest fault VA */
    uint32_t fault_kind;      /* in: A32H_DFAULT_READ/WRITE/EXEC */
    uint32_t fault_is_prot;   /* in: 1 = protection fault (SIGBUS), 0 = unmapped (SIGSEGV) */
    uint32_t fault_syndrome;  /* in: arch syndrome (PPC DSISR / ARM FSR) */
    uint64_t cpu_state_ptr;   /* in: translator VA of a32h_darwin_cpu_state_t */
    uint32_t reply_action;    /* out: A32H_DACT_* bitmask */
    int32_t  exit_status;     /* out: process exit code when A32H_DACT_EXIT_PROCESS */
    uint32_t flush_va;        /* out: guest VA start for A32H_DACT_FLUSH_ICACHE */
    uint32_t flush_len;       /* out: byte length for A32H_DACT_FLUSH_ICACHE */
    uint32_t prot_va;         /* out: guest VA start for A32H_DACT_SYNC_VM_PROT */
    uint32_t prot_len;        /* out: byte length for A32H_DACT_SYNC_VM_PROT */
    uint32_t prot_flags;      /* out: POSIX PROT_* mask for A32H_DACT_SYNC_VM_PROT */
    uint32_t spawn_tid;       /* out: new Darwin tid for A32H_DACT_SPAWN_THREAD */
    uint32_t spawn_pc;        /* out: new thread start PC */
    uint32_t spawn_sp;        /* out: new thread SP */
    uint32_t spawn_r0;        /* out: new thread arg0 */
    uint32_t spawn_tls;       /* out: new thread TLS / TSD base */
    uint8_t  _reserved[40];   /* pad total size to 128 bytes */
} a32h_darwin_trap_t;

_Static_assert(sizeof(a32h_darwin_trap_t) == 128, "a32h_darwin_trap_t must be 128 bytes");

/* Optional in-process handler hook for standalone host unit-testing of G02
 * without requiring `/dev/a32host` or Hypervisor.framework. */
typedef int (*a32h_darwin_handler_fn)(void *opaque, unsigned long req, void *arg);

#endif /* A32HOST_H */
