/*
 * src/ppc32rt.h — Core context, constants, and module interfaces for ppc32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 freeze (SPEC 2.1): the layout of the first 0x238 bytes of
 * ppc32_ctx_t is ABI-locked for the future DBT trampoline and the a64
 * emitter. Fields after the IBTC array are C-only and may be extended at
 * the tail between phases; never inside the locked prefix.
 */

#ifndef PPC32RT_H
#define PPC32RT_H

#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "a32host.h" /* vendored, byte-identical to a32rt/i686rt (D14) */

/* PowerPC GPR indices in architectural numbering (r0..r31). */
#define PPC32_REG_R0  0U
#define PPC32_REG_SP  1U  /* r1 = stack pointer */
#define PPC32_REG_TP  2U  /* r2 = TLS thread pointer (E06; PPC64 r13 does not apply) */
#define PPC32_REG_R13 13U /* r13 = small-data area (classic ABI) */

/* SPR numbers used by mfspr/mtspr (Book I) and mftb (Book II). */
#define PPC32_SPR_XER 1U
#define PPC32_SPR_LR  8U
#define PPC32_SPR_CTR 9U
#define PPC32_SPR_SPEFSCR 512U
/* e500v2 SPEFSCR (P32-R7-13; EREF/SPEPEM Table 2-35, PSIM
 * e500_registers.h): sticky status, current-op status, enables, and the
 * 2-bit FRMC rounding field (00 nearest, 01 zero, 10 +inf, 11 -inf).
 * MODE and the three reserved bits are not writable. */
#define SPE_SOVH  0x80000000u
#define SPE_OVH   0x40000000u
#define SPE_FGH   0x20000000u
#define SPE_FXH   0x10000000u
#define SPE_FINVH 0x08000000u
#define SPE_FDBZH 0x04000000u
#define SPE_FUNFH 0x02000000u
#define SPE_FOVFH 0x01000000u
#define SPE_FINXS 0x00200000u
#define SPE_FINVS 0x00100000u
#define SPE_FDBZS 0x00080000u
#define SPE_FUNFS 0x00040000u
#define SPE_FOVFS 0x00020000u
#define SPE_MODE  0x00010000u
#define SPE_SOV   0x00008000u
#define SPE_OV    0x00004000u
#define SPE_FG    0x00002000u
#define SPE_FX    0x00001000u
#define SPE_FINV  0x00000800u
#define SPE_FDBZ  0x00000400u
#define SPE_FUNF  0x00000200u
#define SPE_FOVF  0x00000100u
#define SPE_FINXE 0x00000040u
#define SPE_FINVE 0x00000020u
#define SPE_FDBZE 0x00000010u
#define SPE_FUNFE 0x00000008u
#define SPE_FOVFE 0x00000004u
#define SPE_FRMC  0x00000003u
#define SPE_WRITABLE (0xffffffffu & ~(0x00800000u | 0x00400000u | \
    0x00010000u | 0x00000080u))
#define PPC32_SPR_PVR 287U
/* PVR values reported per profile (match the qemu-ppc oracle CPUs). */
#define PPC32_PVR_750    0x00080301U /* 750_v3.1 */
#define PPC32_PVR_E500V2 0x80210022U /* e500v2_v22 */
#define PPC32_SPR_TB  268U
#define PPC32_SPR_TBU 269U

/* CR0.SO bit (word bit 3, mask 0x10000000): set on syscall error (E01). */
#define PPC32_CR0_SO (1U << 28)

/* `sc` instruction word: primary opcode 17, LEV 0, suffix 0b10 (E01). */
#define PPC32_INSN_SC 0x44000002U

/* Block exit reasons (engines return to the dispatcher via ctx->exit_reason). */
#define PPC32_EXIT_NONE    0U
#define PPC32_EXIT_BRANCH  1U /* b/bl/bc/bclr/bctr taken to ctx->exit_dest */
#define PPC32_EXIT_SYSCALL 2U /* sc: nr in r0, args in r3..r8 */
#define PPC32_EXIT_UNDEF   3U /* undecodable insn: interpreter single-step */
#define PPC32_EXIT_FAULT   4U /* guest memory fault; ctx->fault_addr set */
#define PPC32_EXIT_TRAP    5U /* tw/td trap instruction */

/* Architectural limits, cache capacities, page/window constants. */
#define PPC32_MAX_REGIONS    512U
#define PPC32_RAS_SIZE       64U
#define PPC32_IBTC_SIZE      4096U /* SPEC §3: 4096-entry per-thread IBTC */
#define PPC32_PAGE_SIZE      4096U
#define PPC32_TASK_SIZE_TOP  0xC0000000U /* ppc32 TASK_SIZE (SPEC 1.1) */
#define PPC32_STACK_TOP      0xBFFF0000U /* initial stack top (SPEC 1.1) */
#define PPC32_SIGTRAMP_BASE  0xBFFFE000U /* vDSO/sigtramp (Phase 2/4) */
#define PPC32_LOW_GUARD_SIZE 0x00010000U

/* FPU/SPE profile selection (--profile, PPC32RT_PROFILE). */
enum {
    PPC32_PROFILE_CLASSIC = 0, /* PowerPC 750 / RAD750 (64-bit FPU) */
    PPC32_PROFILE_SPE     = 1  /* NXP e500v2 (SPE APU, major opcode 4) */
};

/* Engine selection (PPC32RT_ENGINE, --interp / --dbt). */
enum {
    PPC32_ENGINE_INTERP = 0, /* portable C interpreter: correctness oracle */
    PPC32_ENGINE_DBT    = 1  /* PPC->A64 dynamic binary translator */
};

typedef struct ppc32_region {
    uint32_t start;
    uint32_t end;
    uint32_t prot;
    uint32_t flags;
    int      fd;
    uint64_t offset;
    char     name[64];
} ppc32_region_t;

typedef struct ppc32_ibtc_entry {
    uint32_t    key;       /* guest NIP (identity key; no T bit) */
    uint32_t    epoch;
    const void *host_code;
    void       *entry;
    uint64_t    pad;
} ppc32_ibtc_entry_t;

_Static_assert(sizeof(ppc32_ibtc_entry_t) == 32, "ppc32_ibtc_entry_t must be 32 bytes");

/*
 * Unified guest + runtime state for a 32-bit PowerPC thread.
 *
 * ABI-locked prefix (offsets 0x000..0x237) shared with the future DBT
 * trampoline and a64 emitter (SPEC 2.1):
 *   0x000 gpr[32]        low 32 bits of r0..r31 (r1 = sp, r2 = tp)
 *   0x080 gpr_hi[32]     upper 32 bits (e500v2 SPE 64-bit ev* / efd* ops;
 *                        untouched by classic 32-bit instructions)
 *   0x100 nip, lr, ctr, cr, xer, fpscr, spefscr
 *   0x120 acc (u64 SPE accumulator), fpr[32] (classic f0..f31)
 *   0x228 guest_base (u64 G of the [G, G+4GiB) window, held in x20/xG)
 *   0x230 res_addr, res_val (lwarx/stwcx. reservation), res_valid, is_spe
 */
typedef struct ppc32_ctx {
    uint32_t gpr[32];                 /* 0x000 */
    uint32_t gpr_hi[32];              /* 0x080 */
    uint32_t nip;                     /* 0x100 */
    uint32_t lr;                      /* 0x104 */
    uint32_t ctr;                     /* 0x108 */
    uint32_t cr;                      /* 0x10c (8 x 4-bit fields [LT,GT,EQ,SO]) */
    uint32_t xer;                     /* 0x110 */
    uint32_t fpscr;                   /* 0x114 */
    uint32_t spefscr;                 /* 0x118 */
    uint64_t acc;                     /* 0x120 */
    uint64_t fpr[32];                 /* 0x128 */
    uint64_t guest_base;              /* 0x228 */
    uint32_t res_addr;                /* 0x230 */
    uint32_t res_val;                 /* 0x234 */
    uint8_t  res_valid;               /* 0x238 */
    uint8_t  is_spe;                  /* 0x239 */

    /* ---- C-only tail (no asm offset dependencies; extend at end only) ---- */

    /* Fast-dispatch scalars and arrays. The carried a64 emitter exit
     * sequences address these with single LDR/STR unsigned immediates
     * (12-bit scaled), so every scalar here must sit below byte offset
     * 16380 and the ras/ibtc array bases below 32760 — all computed with
     * offsetof(), never hardcoded. The signal check loads pending_signals
     * plus the flag word right after it (trace/sync bytes, zero at rest);
     * pending_signals must stay 8-byte aligned and immediately followed by
     * that flag word. blocks_executed starts the NEXT 8-byte word after
     * the pair, so counting blocks never trips the check. */
    uint8_t           pad_tail[6];          /* 0x23a: align sig_mask */
    uint64_t          sig_mask;             /* 0x240: pending-signal mask */
    volatile uint64_t pending_signals;      /* 0x248 */
    bool              trace_enabled;        /* 0x250: signal-check word +0 */
    bool              gdb_enabled;          /* 0x251 */
    bool              single_step;          /* 0x252 */
    volatile bool     sync_sig_delivered;   /* 0x253 */
    uint32_t          pad_lock1;            /* 0x254 */
    uint64_t          blocks_executed;      /* 0x258 */
    uint64_t          chain_hits;           /* 0x260 */
    void             *last_exec_entry;      /* 0x268 */
    uint64_t          ibtc_hits;            /* 0x270 */
    uint64_t          ras_hits;             /* 0x278 */
    uint32_t          ras_top;              /* 0x280 */
    uint32_t          pad_lock2;            /* 0x284 */
    uint32_t          exit_reason;          /* 0x288 */
    uint32_t          exit_arg;             /* 0x28c */
    uint32_t          fault_addr;           /* 0x290: guest fault VA */
    uint32_t          exit_dest;            /* 0x294 */
    ppc32_ibtc_entry_t ras[PPC32_RAS_SIZE];   /* 0x298 */
    ppc32_ibtc_entry_t ibtc[PPC32_IBTC_SIZE]; /* 0xA98 */

    /* Guest memory layout & allocator inside [G, G + 4GiB) */
    uint32_t brk_base;
    uint32_t brk_curr;
    uint32_t mmap_cursor;       /* bottom-up cursor for guest mmap (§1.2) */
    uint32_t interp_base;
    uint32_t elf_base;
    uint32_t elf_entry;
    uint32_t stack_top;
    uint32_t stack_base;
    uint32_t vdso_base;         /* synthetic ppc32 vDSO (Phase 2) */

    /* Host handshake (/dev/a32host, A32H_ABI 1.0/1.1) */
    a32h_info_t host_info;
    bool        has_host_info;

    /* Tracked guest regions (sorted by start) for /proc/self/maps + gaps */
    ppc32_region_t regions[PPC32_MAX_REGIONS];
    size_t         region_count;

    /* Thread, futex, and signal state (Phase 4 owns the logic) */
    uint32_t clear_child_tid;
    uint32_t robust_list_head;
    uint32_t robust_list_len;
    uint32_t altstack_sp;
    uint32_t altstack_size;
    uint32_t altstack_flags;
    int      host_tid;
    bool     is_thread_clone;
    uint32_t guest_pid;
    uint32_t guest_tid;

    /* Signal-frame anchor, per thread (mirrors i686 RC7b lesson: never a
     * file-static shared across host threads). */
    uint32_t sig_last_frame_va; /* 0 = none pending */
    uint32_t sig_last_frame_rt;

    /* Guest startup metadata for /proc/self/{cmdline,auxv,exe} */
    int      guest_argc;
    char   **guest_argv;
    char   **host_envp;
    uint32_t auxv_data[64];
    size_t   auxv_bytes;

    /* Configuration & engine selection */
    const char *sysroot;
    const char *exec_path;
    const char *cache_dir;
    int         engine;         /* PPC32_ENGINE_* */
    int         profile;        /* PPC32_PROFILE_* */
    bool        difftest;
    bool        trace_syscalls;
    bool        stats_enabled;
    int         gdb_port;

    /* Reservation epoch for lwarx/stwcx. (E06): bumped by helpers,
     * syscalls, signals, and thread switches. */
    uint64_t reservation_epoch;

    /* Instrumentation counters */
    uint64_t blocks_compiled;
    uint64_t syscalls_executed;
    uint64_t icache_flushes;
    uint64_t wx_transitions;

    /*
     * VM readiness (RC1): guest_base == 0 is a VALID window base (G=0
     * identity mapping, tried first by ppc32_vm_init), so "not yet
     * initialized" needs its own flag. Set by ppc32_vm_init on success,
     * cleared by ppc32_vm_reset_for_exec (window torn down).
     */
    bool vm_ready;

    /* Guest signal number for the last FAULT exit: PPC32_SIGSEGV (software
     * faults, host SIGSEGV) or PPC32_SIGBUS (host SIGBUS, e.g. truncated
     * file page). Set by interp fault() and the host-fault guard; read by
     * deliver_sync. Zero (no fault recorded) delivers as SIGSEGV. */
    uint32_t fault_signo;

    /* Per-thread LL/SC epoch snapshots (P32-10: no shared-slot race). */
    uint64_t res_snap;
    uint64_t res_gensnap;

    /* P32-R6-1: last cache generation this ctx synced (set by
     * ppc32_cache_sync_ctx at DBT dispatcher entry; 0 = never). The
     * reclaimer frees a retired block only once every registered ctx
     * has synced past it, so threads inside chained code stay safe. */
    uint32_t ibtc_synced_epoch;

} ppc32_ctx_t;

/* ABI-locked offsets (future trampoline, Phase 3+, must agree). */
#define PPC32_CTX_GPR_OFFSET    0x000U
#define PPC32_CTX_GPR_HI_OFFSET 0x080U
#define PPC32_CTX_NIP_OFFSET    0x100U
#define PPC32_CTX_ACC_OFFSET    0x120U
#define PPC32_CTX_FPR_OFFSET    0x128U
#define PPC32_CTX_GUEST_BASE_OFFSET 0x228U

_Static_assert(offsetof(ppc32_ctx_t, gpr) == 0x000, "gpr must be at offset 0x000");
_Static_assert(offsetof(ppc32_ctx_t, gpr_hi) == 0x080, "gpr_hi must be at offset 0x080");
_Static_assert(offsetof(ppc32_ctx_t, nip) == 0x100, "nip must be at offset 0x100");
_Static_assert(offsetof(ppc32_ctx_t, lr) == 0x104, "lr must be at offset 0x104");
_Static_assert(offsetof(ppc32_ctx_t, ctr) == 0x108, "ctr must be at offset 0x108");
_Static_assert(offsetof(ppc32_ctx_t, cr) == 0x10c, "cr must be at offset 0x10c");
_Static_assert(offsetof(ppc32_ctx_t, xer) == 0x110, "xer must be at offset 0x110");
_Static_assert(offsetof(ppc32_ctx_t, fpscr) == 0x114, "fpscr must be at offset 0x114");
_Static_assert(offsetof(ppc32_ctx_t, spefscr) == 0x118, "spefscr must be at offset 0x118");
_Static_assert(offsetof(ppc32_ctx_t, acc) == 0x120, "acc must be at offset 0x120");
_Static_assert(offsetof(ppc32_ctx_t, fpr) == 0x128, "fpr must be at offset 0x128");
_Static_assert(offsetof(ppc32_ctx_t, guest_base) == 0x228, "guest_base must be at offset 0x228");
_Static_assert(offsetof(ppc32_ctx_t, res_addr) == 0x230, "res_addr must be at offset 0x230");
_Static_assert(offsetof(ppc32_ctx_t, res_val) == 0x234, "res_val must be at offset 0x234");
_Static_assert(offsetof(ppc32_ctx_t, res_valid) == 0x238, "res_valid must be at offset 0x238");
_Static_assert(offsetof(ppc32_ctx_t, is_spe) == 0x239, "is_spe must be at offset 0x239");
_Static_assert(sizeof(ppc32_ibtc_entry_t) * PPC32_IBTC_SIZE == 131072,
               "IBTC array must span 131072 bytes");

static inline void ppc32_spin_lock(_Atomic uint32_t *lock)
{
    while (atomic_exchange_explicit(lock, 1U, memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static inline void ppc32_spin_unlock(_Atomic uint32_t *lock)
{
    atomic_store_explicit(lock, 0U, memory_order_release);
}

/* Guest VA -> host pointer. va is u32: never sign-extend or truncate. */
static inline void *ppc32_guest_ptr(const ppc32_ctx_t *ctx, uint32_t guest_va)
{
    return (void *)(uintptr_t)(ctx->guest_base + (uint64_t)guest_va);
}

static inline uint32_t ppc32_page_down(uint32_t x)
{
    return x & ~(PPC32_PAGE_SIZE - 1U);
}

static inline uint32_t ppc32_page_up(uint32_t x)
{
    return (x + (PPC32_PAGE_SIZE - 1U)) & ~(PPC32_PAGE_SIZE - 1U);
}

/* Cache keys hash on guest NIP only — identity key, no T bit. */
static inline uint32_t ppc32_make_key(uint32_t nip)
{
    return nip;
}

static inline uint32_t ppc32_ibtc_hash(uint32_t nip)
{
    return (nip >> 2U) & (PPC32_IBTC_SIZE - 1U);
}

/*
 * Guest prot -> host prot for window mappings. Guest PROT_EXEC is never
 * host-exec (window holds data; translated code lives outside the window),
 * which also dissolves any W^X conflict; SMC write-protection is layered
 * on top by the JIT, never here.
 */
static inline int ppc32_host_prot(const ppc32_ctx_t *ctx, uint32_t guest_prot)
{
    (void)ctx;
    uint32_t p = guest_prot & 0x7U;
    if ((p & 0x4U) != 0U) {
        p |= 0x1U; /* PROT_EXEC implies PROT_READ on host */
        p &= ~0x4U;
    }
    return (int)p;
}

/* Big-endian guest memory access (ELFDATA2MSB): every 16/32/64-bit guest
 * load/store byte-swaps (REV16/REV/REV64 under the DBT). */
static inline uint16_t ppc32_be16(uint16_t v)
{
    return (uint16_t)(((v & 0x00FFU) << 8) | ((v & 0xFF00U) >> 8));
}

static inline uint32_t ppc32_be32(uint32_t v)
{
    return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
           ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
}

static inline uint64_t ppc32_be64(uint64_t v)
{
    return ((v & 0x00000000000000FFULL) << 56) |
           ((v & 0x000000000000FF00ULL) << 40) |
           ((v & 0x0000000000FF0000ULL) << 24) |
           ((v & 0x00000000FF000000ULL) << 8) |
           ((v & 0x000000FF00000000ULL) >> 8) |
           ((v & 0x0000FF0000000000ULL) >> 24) |
           ((v & 0x00FF000000000000ULL) >> 40) |
           ((v & 0xFF00000000000000ULL) >> 56);
}

#endif /* PPC32RT_H */
