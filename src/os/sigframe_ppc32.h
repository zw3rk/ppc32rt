/*
 * src/os/sigframe_ppc32.h — frozen PPC32 signal-frame ABI (SPEC §2.3, E04)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Kernel-exact guest layouts (Linux arch/powerpc UAPI, 32-bit):
 * struct mcontext / struct ucontext (asm/ucontext.h), elf regsets
 * (asm/elf.h: ELF_NGREG 48, ELF_NFPREG 33, ELF_NVRREG 33,
 * ELF_NEVRREG 34), mc_gregs index map (asm/ptrace.h PT_*), struct stat /
 * struct stat64 (asm/stat.h), and struct rt_sigframe
 * (arch/powerpc/kernel/signal_32.c: siginfo + ucontext + abigap[56]).
 * Lanes must not edit this file — escalate instead.
 */

#ifndef PPC32RT_OS_SIGFRAME_PPC32_H
#define PPC32RT_OS_SIGFRAME_PPC32_H

#include <stdint.h>

/* P32-R13-8: canonical guest stat layouts live in os/convert.h; this
 * header re-exports them so signal-frame consumers keep working. */
#include "os/convert.h"

/* ---- mc_gregs word indices (asm/ptrace.h PT_R0..PT_DSCR) ---- */
enum {
    PPC32_MC_R0 = 0,
    PPC32_MC_R31 = 31,
    PPC32_MC_NIP = 32,
    PPC32_MC_MSR = 33,
    PPC32_MC_ORIG_R3 = 34,
    PPC32_MC_CTR = 35,
    PPC32_MC_LINK = 36,
    PPC32_MC_XER = 37,
    PPC32_MC_CCR = 38,
    PPC32_MC_MQ = 39,
    PPC32_MC_TRAP = 40,
    PPC32_MC_DAR = 41,
    PPC32_MC_DSISR = 42,
    PPC32_MC_RESULT = 43,
    PPC32_MC_DSCR = 44
};

/* ---- struct mcontext (992 B, 16-byte aligned tail) ---- */
typedef struct {
    uint32_t mc_gregs[48]; /* 0x000: r0..r31, nip, msr, orig_r3, ctr, ... */
    double mc_fregs[33];   /* 0x0c0: f0..f31 + fpscr (kernel: double[33]) */
    uint32_t mc_pad[2];    /* 0x1c8: pads mc_vregs up to 16-byte alignment */
    _Alignas(16) uint8_t mc_vregs[528]; /* 0x1d0: elf_vrregset_t (33x16 B) */
} ppc32_mcontext_t;

/* ---- SPE overlay at the start of mc_vregs (e500v2, CONFIG_SPE) ----
 * evr[32] carries gpr_hi[0..31], then 64-bit acc, then spefscr.
 * 128 + 8 + 4 = 140 payload, 144 with the acc-imposed 8-alignment
 * tail pad; 32 + 2 = 34 = ELF_NEVRREG ("acc as 2"). Must stay <= 528. */
typedef struct {
    uint32_t evr[32];  /* +0x00: gpr_hi[0..31] */
    uint64_t acc;      /* +0x80: 64-bit SPE accumulator */
    uint32_t spefscr;  /* +0x88: SPE status/control */
} ppc32_spe_overlay_t;

/* ---- struct ucontext (1184 B: 192 B header + 992 B mcontext) ----
 * uc_link / uc_regs are 32-bit guest pointers. uc_sigmask is the
 * 64-bit kernel mask (2 words on 32-bit), not the glibc 1024-bit one. */
typedef struct {
    uint32_t uc_flags;       /* 0x00 */
    uint32_t uc_link;        /* 0x04: guest struct ucontext * */
    uint32_t uc_stack_sp;    /* 0x08: stack_t ss_sp */
    int32_t uc_stack_flags;  /* 0x0c: stack_t ss_flags */
    uint32_t uc_stack_size;  /* 0x10: stack_t ss_size */
    int32_t uc_pad[7];       /* 0x14 */
    uint32_t uc_regs;        /* 0x30: guest ptr -> uc_mcontext.mc_gregs */
    uint32_t uc_sigmask[2];  /* 0x34: 64-bit kernel signal mask */
    int32_t uc_maskext[30];  /* 0x3c */
    int32_t uc_pad2[3];      /* 0xb4 */
    ppc32_mcontext_t uc_mcontext; /* 0xc0 */
} ppc32_ucontext_t;

/* ---- struct rt_sigframe (1536 B: siginfo + ucontext + ABI gap) ----
 * signal_32.c (non-PPC64, non-TM): info, uc, abigap[56]. The 128-byte
 * siginfo payload is carried opaquely; Phase 4 (L4a) owns field decode. */
typedef struct {
    uint8_t si_info[128];  /* 0x000: struct siginfo (SI_MAX_SIZE 128) */
    ppc32_ucontext_t uc;   /* 0x080 */
    int32_t abigap[56];    /* 0x520: rs6000/xcoff register-save gap */
} ppc32_rt_sigframe_t;

/* ---- frozen ABI assertions (stat layouts canonical in convert.h) ---- */
_Static_assert(sizeof(ppc32_mcontext_t) == 992, "mcontext must be 992 B");
_Static_assert(sizeof(ppc32_ucontext_t) == 1184, "ucontext must be 1184 B");
_Static_assert(sizeof(ppc32_rt_sigframe_t) == 1536, "rt_sigframe 1536 B");
_Static_assert(sizeof(ppc32_stat_t) == 72, "ppc32 stat must be 72 B");
_Static_assert(sizeof(ppc32_stat64_t) == 104, "ppc32 stat64 must be 104 B");
_Static_assert(sizeof(ppc32_spe_overlay_t) == 144, "SPE overlay 144 B");

#endif /* PPC32RT_OS_SIGFRAME_PPC32_H */
