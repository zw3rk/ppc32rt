/*
 * tests/check_abi_invariants.c — ABI offset/size verification (Phase 0 L0b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Compile-time (_Static_assert) + runtime (offsetof/sizeof) checks for
 * every field offset and struct size in src/os/sigframe_ppc32.h
 * (SPEC §2.3, E04) and the SPEC §2.1 ppc32_ctx_t locked prefix in
 * src/ppc32rt.h (RC0 coordinator rewire; no local replica).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "os/sigframe_ppc32.h"
#include "ppc32rt.h"

/* ---- compile-time pins: sigframe/stat structs ---- */
_Static_assert(offsetof(ppc32_mcontext_t, mc_gregs) == 0x0, "mc_gregs@0x0");
_Static_assert(offsetof(ppc32_mcontext_t, mc_fregs) == 0xc0, "mc_fregs@0xc0");
_Static_assert(offsetof(ppc32_mcontext_t, mc_pad) == 0x1c8, "mc_pad@0x1c8");
_Static_assert(offsetof(ppc32_mcontext_t, mc_vregs) == 0x1d0, "mc_vregs@0x1d0");
_Static_assert(sizeof(((ppc32_mcontext_t *)0)->mc_gregs) == 192, "gregs 192 B");
_Static_assert(sizeof(((ppc32_mcontext_t *)0)->mc_fregs) == 264, "fregs 264 B");
_Static_assert(sizeof(((ppc32_mcontext_t *)0)->mc_vregs) == 528, "vregs 528 B");
_Static_assert(sizeof(ppc32_mcontext_t) == 992, "mcontext 992 B");

_Static_assert(offsetof(ppc32_spe_overlay_t, evr) == 0x0, "evr@+0");
_Static_assert(offsetof(ppc32_spe_overlay_t, acc) == 128, "acc@+128");
_Static_assert(offsetof(ppc32_spe_overlay_t, spefscr) == 136, "spefscr@+136");
_Static_assert(sizeof(ppc32_spe_overlay_t) == 144, "SPE overlay 144 B");
_Static_assert(sizeof(ppc32_spe_overlay_t) <= 528, "overlay fits mc_vregs");

_Static_assert(offsetof(ppc32_ucontext_t, uc_flags) == 0x0, "uc_flags@0x0");
_Static_assert(offsetof(ppc32_ucontext_t, uc_link) == 0x4, "uc_link@0x4");
_Static_assert(offsetof(ppc32_ucontext_t, uc_stack_sp) == 0x8, "sp@0x8");
_Static_assert(offsetof(ppc32_ucontext_t, uc_stack_flags) == 0xc, "sflags@0xc");
_Static_assert(offsetof(ppc32_ucontext_t, uc_stack_size) == 0x10, "ssize@0x10");
_Static_assert(offsetof(ppc32_ucontext_t, uc_pad) == 0x14, "uc_pad@0x14");
_Static_assert(offsetof(ppc32_ucontext_t, uc_regs) == 0x30, "uc_regs@0x30");
_Static_assert(offsetof(ppc32_ucontext_t, uc_sigmask) == 0x34, "mask@0x34");
_Static_assert(offsetof(ppc32_ucontext_t, uc_maskext) == 0x3c, "maskext@0x3c");
_Static_assert(offsetof(ppc32_ucontext_t, uc_pad2) == 0xb4, "pad2@0xb4");
_Static_assert(offsetof(ppc32_ucontext_t, uc_mcontext) == 0xc0, "uc_mc@0xc0");
_Static_assert(sizeof(ppc32_ucontext_t) == 1184, "ucontext 1184 B");

_Static_assert(offsetof(ppc32_rt_sigframe_t, si_info) == 0x0, "info@0x0");
_Static_assert(sizeof(((ppc32_rt_sigframe_t *)0)->si_info) == 128, "info 128 B");
_Static_assert(offsetof(ppc32_rt_sigframe_t, uc) == 0x80, "sigframe uc@0x80");
_Static_assert(offsetof(ppc32_rt_sigframe_t, abigap) == 0x520, "abigap@0x520");
_Static_assert(sizeof(ppc32_rt_sigframe_t) == 1536, "rt_sigframe 1536 B");

_Static_assert(offsetof(ppc32_stat_t, st_dev) == 0x0, "stat dev@0x0");
_Static_assert(offsetof(ppc32_stat_t, st_ino) == 0x4, "stat ino@0x4");
_Static_assert(offsetof(ppc32_stat_t, st_mode) == 0x8, "stat mode@0x8");
_Static_assert(offsetof(ppc32_stat_t, st_nlink) == 0xc, "stat nlink@0xc");
_Static_assert(offsetof(ppc32_stat_t, st_uid) == 0x10, "stat uid@0x10");
_Static_assert(offsetof(ppc32_stat_t, st_gid) == 0x14, "stat gid@0x14");
_Static_assert(offsetof(ppc32_stat_t, st_rdev) == 0x18, "stat rdev@0x18");
_Static_assert(offsetof(ppc32_stat_t, st_size) == 0x1c, "stat size@0x1c");
_Static_assert(offsetof(ppc32_stat_t, st_blksize) == 0x20, "stat blksz@0x20");
_Static_assert(offsetof(ppc32_stat_t, st_blocks) == 0x24, "stat blks@0x24");
_Static_assert(offsetof(ppc32_stat_t, st_atime) == 0x28, "stat atime@0x28");
_Static_assert(offsetof(ppc32_stat_t, st_mtime) == 0x30, "stat mtime@0x30");
_Static_assert(offsetof(ppc32_stat_t, st_ctime) == 0x38, "stat ctime@0x38");
_Static_assert(offsetof(ppc32_stat_t, __unused5) == 0x44, "stat un5@0x44");
_Static_assert(sizeof(ppc32_stat_t) == 72, "ppc32 stat 72 B");

_Static_assert(offsetof(ppc32_stat64_t, st_dev) == 0x0, "st64 dev@0x0");
_Static_assert(offsetof(ppc32_stat64_t, st_ino) == 0x8, "st64 ino@0x8");
_Static_assert(offsetof(ppc32_stat64_t, st_mode) == 0x10, "st64 mode@0x10");
_Static_assert(offsetof(ppc32_stat64_t, st_nlink) == 0x14, "st64 nlink@0x14");
_Static_assert(offsetof(ppc32_stat64_t, st_uid) == 0x18, "st64 uid@0x18");
_Static_assert(offsetof(ppc32_stat64_t, st_gid) == 0x1c, "st64 gid@0x1c");
_Static_assert(offsetof(ppc32_stat64_t, st_rdev) == 0x20, "st64 rdev@0x20");
_Static_assert(offsetof(ppc32_stat64_t, __pad2) == 0x28, "st64 pad2@0x28");
_Static_assert(offsetof(ppc32_stat64_t, st_size) == 0x30, "st64 size@0x30");
_Static_assert(offsetof(ppc32_stat64_t, st_blksize) == 0x38, "st64 blksz@0x38");
_Static_assert(offsetof(ppc32_stat64_t, st_blocks) == 0x40, "st64 blks@0x40");
_Static_assert(offsetof(ppc32_stat64_t, st_atime) == 0x48, "st64 at@0x48");
_Static_assert(offsetof(ppc32_stat64_t, st_mtime) == 0x50, "st64 mt@0x50");
_Static_assert(offsetof(ppc32_stat64_t, st_ctime) == 0x58, "st64 ct@0x58");
_Static_assert(offsetof(ppc32_stat64_t, __unused4) == 0x60, "st64 un4@0x60");
_Static_assert(offsetof(ppc32_stat64_t, __unused5) == 0x64, "st64 un5@0x64");
_Static_assert(sizeof(ppc32_stat64_t) == 104, "ppc32 stat64 104 B");

/* ---- compile-time pins: SPEC §2.1 ctx locked prefix (real ppc32_ctx_t) ---- */
_Static_assert(offsetof(ppc32_ctx_t, gpr) == 0x0, "ctx gpr@0x0");
_Static_assert(offsetof(ppc32_ctx_t, gpr_hi) == 0x80, "ctx gpr_hi@0x80");
_Static_assert(offsetof(ppc32_ctx_t, nip) == 0x100, "ctx nip@0x100");
_Static_assert(offsetof(ppc32_ctx_t, lr) == 0x104, "ctx lr@0x104");
_Static_assert(offsetof(ppc32_ctx_t, ctr) == 0x108, "ctx ctr@0x108");
_Static_assert(offsetof(ppc32_ctx_t, cr) == 0x10c, "ctx cr@0x10c");
_Static_assert(offsetof(ppc32_ctx_t, xer) == 0x110, "ctx xer@0x110");
_Static_assert(offsetof(ppc32_ctx_t, fpscr) == 0x114, "ctx fpscr@0x114");
_Static_assert(offsetof(ppc32_ctx_t, spefscr) == 0x118, "ctx spefscr");
_Static_assert(offsetof(ppc32_ctx_t, acc) == 0x120, "ctx acc@0x120");
_Static_assert(offsetof(ppc32_ctx_t, fpr) == 0x128, "ctx fpr@0x128");
_Static_assert(offsetof(ppc32_ctx_t, guest_base) == 0x228, "ctx G@0x228");
_Static_assert(offsetof(ppc32_ctx_t, res_addr) == 0x230, "ctx ra@0x230");
_Static_assert(offsetof(ppc32_ctx_t, res_val) == 0x234, "ctx rv@0x234");
_Static_assert(offsetof(ppc32_ctx_t, res_valid) == 0x238, "ctx rvld");
_Static_assert(offsetof(ppc32_ctx_t, is_spe) == 0x239, "ctx spe@0x239");

static int fails = 0;

static void check_size(const char *name, size_t got, size_t want)
{
    printf("%-16s sizeof = 0x%lX (%lu) want 0x%lX %s\n", name,
        (unsigned long)got, (unsigned long)got,
        (unsigned long)want, got == want ? "ok" : "MISMATCH");
    if (got != want) {
        fails++;
    }
}

static void check_off(const char *name, size_t got, size_t want)
{
    printf("%-16s offset = 0x%lX (%lu) want 0x%lX %s\n", name,
        (unsigned long)got, (unsigned long)got,
        (unsigned long)want, got == want ? "ok" : "MISMATCH");
    if (got != want) {
        fails++;
    }
}

int main(void)
{
    check_size("mcontext", sizeof(ppc32_mcontext_t), 992u);
    check_off("mc_gregs", offsetof(ppc32_mcontext_t, mc_gregs), 0x0u);
    check_off("mc_fregs", offsetof(ppc32_mcontext_t, mc_fregs), 0xc0u);
    check_off("mc_pad", offsetof(ppc32_mcontext_t, mc_pad), 0x1c8u);
    check_off("mc_vregs", offsetof(ppc32_mcontext_t, mc_vregs), 0x1d0u);

    check_size("spe_overlay", sizeof(ppc32_spe_overlay_t), 144u);
    check_off("spe.evr", offsetof(ppc32_spe_overlay_t, evr), 0x0u);
    check_off("spe.acc", offsetof(ppc32_spe_overlay_t, acc), 128u);
    check_off("spe.spefscr", offsetof(ppc32_spe_overlay_t, spefscr), 136u);

    check_size("ucontext", sizeof(ppc32_ucontext_t), 1184u);
    check_off("uc_flags", offsetof(ppc32_ucontext_t, uc_flags), 0x0u);
    check_off("uc_link", offsetof(ppc32_ucontext_t, uc_link), 0x4u);
    check_off("uc_stack_sp", offsetof(ppc32_ucontext_t, uc_stack_sp), 0x8u);
    check_off("uc_pad", offsetof(ppc32_ucontext_t, uc_pad), 0x14u);
    check_off("uc_regs", offsetof(ppc32_ucontext_t, uc_regs), 0x30u);
    check_off("uc_sigmask", offsetof(ppc32_ucontext_t, uc_sigmask), 0x34u);
    check_off("uc_maskext", offsetof(ppc32_ucontext_t, uc_maskext), 0x3cu);
    check_off("uc_pad2", offsetof(ppc32_ucontext_t, uc_pad2), 0xb4u);
    check_off("uc_mcontext", offsetof(ppc32_ucontext_t, uc_mcontext), 0xc0u);

    check_size("rt_sigframe", sizeof(ppc32_rt_sigframe_t), 1536u);
    check_off("sf.uc", offsetof(ppc32_rt_sigframe_t, uc), 0x80u);
    check_off("sf.abigap", offsetof(ppc32_rt_sigframe_t, abigap), 0x520u);

    check_size("ppc32_stat", sizeof(ppc32_stat_t), 72u);
    check_off("stat.uid", offsetof(ppc32_stat_t, st_uid), 0x10u);
    check_off("stat.rdev", offsetof(ppc32_stat_t, st_rdev), 0x18u);
    check_off("stat.size", offsetof(ppc32_stat_t, st_size), 0x1cu);
    check_off("stat.ctime", offsetof(ppc32_stat_t, st_ctime), 0x38u);

    check_size("ppc32_stat64", sizeof(ppc32_stat64_t), 104u);
    check_off("st64.dev", offsetof(ppc32_stat64_t, st_dev), 0x0u);
    check_off("st64.ino", offsetof(ppc32_stat64_t, st_ino), 0x8u);
    check_off("st64.mode", offsetof(ppc32_stat64_t, st_mode), 0x10u);
    check_off("st64.rdev", offsetof(ppc32_stat64_t, st_rdev), 0x20u);
    check_off("st64.size", offsetof(ppc32_stat64_t, st_size), 0x30u);
    check_off("st64.blksize", offsetof(ppc32_stat64_t, st_blksize), 0x38u);
    check_off("st64.blocks", offsetof(ppc32_stat64_t, st_blocks), 0x40u);
    check_off("st64.atime", offsetof(ppc32_stat64_t, st_atime), 0x48u);
    check_off("st64.mtime", offsetof(ppc32_stat64_t, st_mtime), 0x50u);
    check_off("st64.ctime", offsetof(ppc32_stat64_t, st_ctime), 0x58u);

    /* SPEC §2.1 locked prefix, checked against the real ppc32_ctx_t. */
    check_off("ctx.gpr", offsetof(ppc32_ctx_t, gpr), 0x0u);
    check_off("ctx.gpr_hi", offsetof(ppc32_ctx_t, gpr_hi), 0x80u);
    check_off("ctx.nip", offsetof(ppc32_ctx_t, nip), 0x100u);
    check_off("ctx.acc", offsetof(ppc32_ctx_t, acc), 0x120u);
    check_off("ctx.fpr", offsetof(ppc32_ctx_t, fpr), 0x128u);
    check_off("ctx.G", offsetof(ppc32_ctx_t, guest_base), 0x228u);
    check_off("ctx.res_valid", offsetof(ppc32_ctx_t, res_valid), 0x238u);
    check_off("ctx.is_spe", offsetof(ppc32_ctx_t, is_spe), 0x239u);

    if (PPC32_MC_NIP != 32 || PPC32_MC_MSR != 33 || PPC32_MC_CTR != 35 ||
        PPC32_MC_LINK != 36 || PPC32_MC_XER != 37 || PPC32_MC_CCR != 38 ||
        PPC32_MC_RESULT != 43 || PPC32_MC_DSCR != 44) {
        printf("greg index map MISMATCH\n");
        fails++;
    }

    printf(fails == 0 ? "check_abi_invariants: ALL OK\n" :
        "check_abi_invariants: %d FAILURES\n", fails);
    return fails != 0;
}
